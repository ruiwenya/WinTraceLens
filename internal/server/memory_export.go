package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Server) handleThreatMemoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pid64, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("pid")), 10, 32)
	if err != nil || pid64 == 0 {
		http.Error(w, "无效 PID", http.StatusBadRequest)
		return
	}
	baseText := strings.TrimSpace(r.URL.Query().Get("base"))
	baseText = strings.TrimPrefix(strings.TrimPrefix(baseText, "0x"), "0X")
	base, err := strconv.ParseUint(baseText, 16, 64)
	if err != nil || base == 0 {
		http.Error(w, "无效区域基址", http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("size")), 10, 64)
	if err != nil || size == 0 {
		http.Error(w, "无效区域大小", http.StatusBadRequest)
		return
	}
	exported, err := memoryscan.ExportRegion(uint32(pid64), base, size, 128*1024*1024)
	if err != nil {
		http.Error(w, "导出内存区域失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var proc process.Info
	processes, _ := s.evidenceStore.Processes(process.Options{SkipHashes: true}, false)
	for _, item := range processes {
		if item.PID == uint32(pid64) {
			proc = item
			break
		}
	}
	metadata := struct {
		memoryscan.RegionExport
		Process      string `json:"process"`
		ProcessPath  string `json:"processPath"`
		Signature    string `json:"signature"`
		SignatureMsg string `json:"signatureMsg"`
	}{RegionExport: exported, Process: proc.Name, ProcessPath: proc.Path, Signature: proc.Signature, SignatureMsg: proc.SignatureMsg}
	metadata.Data = nil
	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	processName := unsafeFilenameChars.ReplaceAllString(strings.TrimSuffix(proc.Name, ".exe"), "_")
	if processName == "" {
		processName = "process"
	}
	baseName := fmt.Sprintf("PID_%d_%s_%X", pid64, processName, base)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	binFile, _ := writer.Create(baseName + ".bin")
	_, _ = binFile.Write(exported.Data)
	jsonFile, _ := writer.Create(baseName + ".json")
	_, _ = jsonFile.Write(metadataJSON)
	if err := writer.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("memory-evidence-%d-%s.zip", pid64, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(archive.Bytes())
}
