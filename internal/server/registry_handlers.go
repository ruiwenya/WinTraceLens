package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
)

func (s *Server) handleRegistryAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.registrySnapshot(registryOptionsFromRequest(r), boolFromQuery(r, "refresh", false))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapshot.Records = filterRegistryRecords(snapshot.Records, r.URL.Query().Get("risk"), r.URL.Query().Get("q"))
	writeJSON(w, snapshot)
}

func (s *Server) handleRegistryAnomaliesCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.registrySnapshot(registryOptionsFromRequest(r), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := filterRegistryRecords(snapshot.Records, r.URL.Query().Get("risk"), r.URL.Query().Get("q"))
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, registryRecordRow(item))
	}
	writeCSV(w, "registry-anomalies", []string{"风险", "评分", "Hive", "用户SID", "键路径", "值名", "类型", "数据长度", "最后写入", "SHA256", "哈希范围", "熵", "异常原因", "关联证据", "十六进制预览", "字符串预览"}, rows)
}

func (s *Server) handleRegistryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ref, err := registryanomaly.DecodeReference(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, valueType, modified, err := registryanomaly.ReadExportValue(ref, 32*1024*1024)
	if err != nil {
		http.Error(w, "导出注册表值失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(data)
	metadata := struct {
		Hive        string `json:"hive"`
		KeyPath     string `json:"keyPath"`
		ValueName   string `json:"valueName"`
		ValueType   uint32 `json:"valueType"`
		Length      int    `json:"length"`
		SHA256      string `json:"sha256"`
		LastWrite   string `json:"lastWrite"`
		CollectedAt string `json:"collectedAt"`
	}{
		Hive: ref.Hive, KeyPath: ref.KeyPath, ValueName: ref.ValueName, ValueType: valueType,
		Length: len(data), SHA256: hex.EncodeToString(sum[:]), LastWrite: modified.Local().Format("2006-01-02 15:04:05"),
		CollectedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	binFile, _ := writer.Create("registry-value.bin")
	_, _ = binFile.Write(data)
	jsonFile, _ := writer.Create("registry-value.json")
	_, _ = jsonFile.Write(metadataJSON)
	if err := writer.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("registry-evidence-%s.zip", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(archive.Bytes())
}

func (s *Server) registrySnapshot(opts registryanomaly.Options, force bool) (registryanomaly.Snapshot, error) {
	snapshot, err := s.evidenceStore.Registry(opts, force)
	if err != nil {
		return snapshot, err
	}
	processes, processErr := s.evidenceStore.Processes(process.Options{HashLimitBytes: s.options.HashLimitBytes, SkipHashes: true}, force)
	if processErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "进程关联: "+processErr.Error())
	}
	machine, hostErr := s.evidenceStore.Host(host.Options{HashLimitBytes: s.options.HashLimitBytes}, force)
	if hostErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "主机信息关联: "+hostErr.Error())
	}
	snapshot = registryanomaly.Correlate(snapshot, processes, machine)
	s.rememberEvidence("registry-correlated", opts, snapshot)
	return snapshot, nil
}

func registryOptionsFromRequest(r *http.Request) registryanomaly.Options {
	return registryanomaly.Options{
		MaxRecords:  intFromQuery(r, "max", 500, 1, 3000),
		MaxKeys:     intFromQuery(r, "keys", 6000, 100, 30000),
		MaxValues:   intFromQuery(r, "values", 30000, 100, 150000),
		MaxDepth:    intFromQuery(r, "depth", 5, 1, 10),
		MaxDataSize: intFromQuery(r, "data_mb", 4, 1, 32) * 1024 * 1024,
		Timeout:     time.Duration(intFromQuery(r, "timeout", 10, 2, 60)) * time.Second,
	}
}

func filterRegistryRecords(items []registryanomaly.Record, risk, query string) []registryanomaly.Record {
	filtered := make([]registryanomaly.Record, 0, len(items))
	for _, item := range items {
		if risk != "" && risk != "all" && item.Level != risk {
			continue
		}
		if matchesCSVQuery(query, registryRecordRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func registryRecordRow(item registryanomaly.Record) []string {
	return []string{
		item.Level, strconv.Itoa(item.Score), item.Hive, item.SID, item.KeyPath, item.ValueName,
		item.ValueType, strconv.Itoa(item.DataLength), item.LastWrite, item.SHA256, item.HashScope,
		fmt.Sprintf("%.2f", item.Entropy), strings.Join(item.Reasons, "；"), strings.Join(item.Associations, "；"),
		item.HexPreview, item.StringsPreview,
	}
}
