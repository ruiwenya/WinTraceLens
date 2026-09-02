package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/evidencebundle"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func (s *Server) rememberEvidence(source string, opts, value any) {
	if err := s.evidenceStore.RecordResult(source, opts, value); err != nil {
		log.Printf("retain evidence %s: %v", source, err)
	}
}

func (s *Server) collectModuleEvidence(pid uint32) ([]process.ModuleInfo, error) {
	items, err := process.Modules(pid, process.Options{HashLimitBytes: s.options.HashLimitBytes})
	var warnings []string
	opts := map[string]any{"pid": pid}
	if err != nil {
		warnings = append(warnings, err.Error())
		opts["unavailable"] = true
	}
	s.rememberEvidence("process-modules", opts, map[string]any{
		"pid": pid, "items": items, "collectionErrors": warnings,
	})
	return items, err
}

func (s *Server) handleEvidenceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	datasets, err := s.evidenceStore.ExportSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	status, err := evidencebundle.Describe(datasets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.evidenceCollectMu.TryLock() {
		s.evidenceCollectMu.Unlock()
	} else {
		status.Collecting = true
	}
	writeJSON(w, status)
}

func (s *Server) handleEvidencePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Sources []string `json:"sources"`
	}
	if r.ContentLength != 0 {
		if err := readJSONBody(w, r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if _, err := evidencebundle.NormalizeSelection(req.Sources); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.evidenceExportMu.TryLock() {
		http.Error(w, "已有取证包正在生成，请稍后重试。", http.StatusConflict)
		return
	}
	defer s.evidenceExportMu.Unlock()
	datasets, err := s.evidenceStore.ExportSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	datasets, err = evidencebundle.Select(datasets, req.Sources)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(datasets) == 0 {
		http.Error(w, "勾选来源尚无已完成数据，请先一键采集或打开对应功能页。", http.StatusConflict)
		return
	}
	now := time.Now().UTC()
	hostname, _ := os.Hostname()
	data, err := evidencebundle.BuildSelected(r.Context(), datasets, s.options.Version, hostname, now, req.Sources)
	if err != nil {
		http.Error(w, "取证包生成失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="WinTraceLens-evidence-%s.zip"`, now.Format("20060102-150405")))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
