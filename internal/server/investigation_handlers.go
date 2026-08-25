package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/driveranalysis"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/investigation"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

type investigationCacheEntry struct {
	snapshot  investigation.Snapshot
	expiresAt time.Time
}

func (s *Server) handleInvestigation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.investigationSnapshot(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, snapshot)
}

func (s *Server) handleInvestigationCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.investigationSnapshot(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	rows := make([][]string, 0, len(snapshot.Timeline))
	for _, item := range snapshot.Timeline {
		row := investigation.TimelineRow(item)
		if query == "" || matchesCSVQuery(query, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "case-timeline", []string{"时间", "级别", "场景分数", "场景依据", "证据组", "来源", "分类", "动作", "实体", "PID", "用户", "远程地址/域名", "路径", "哈希", "详情"}, rows)
}

func (s *Server) investigationSnapshot(r *http.Request) (investigation.Snapshot, error) {
	startTime, endTime, err := dateRangeFromRequest(r)
	if err != nil {
		return investigation.Snapshot{}, err
	}
	if startTime.IsZero() {
		startTime = time.Now().AddDate(0, 0, -7).Truncate(24 * time.Hour)
	}
	if endTime.IsZero() {
		now := time.Now()
		endTime = time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, time.Local)
	}
	maxRecords := investigationMaxFromQuery(r)
	scenario := r.URL.Query().Get("scenario")
	hours := int(time.Since(startTime).Hours()) + 24
	if hours < 24 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	key := fmt.Sprintf("%s|%s|%d", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), maxRecords)
	force := boolFromQuery(r, "refresh", false)

	s.investigationMu.Lock()
	defer s.investigationMu.Unlock()
	if !force {
		if cached, ok := s.investigationCache[key]; ok && time.Now().Before(cached.expiresAt) {
			return investigation.ApplyScenario(cached.snapshot, scenario), nil
		}
	}

	opts := investigation.Options{
		MaxRecords:     maxRecords,
		StartTime:      startTime,
		EndTime:        endTime,
		Hours:          hours,
		HashLimitBytes: s.options.HashLimitBytes,
	}
	sourceLimit := maxRecords / 3
	if sourceLimit < 300 {
		sourceLimit = 300
	}
	if sourceLimit > 1000 {
		sourceLimit = 1000
	}
	driverLimit := sourceLimit
	if driverLimit > 300 {
		driverLimit = 300
	}
	sources := investigation.Sources{}
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	run(func() {
		sources.Processes, sources.ProcessError = s.evidenceStore.Processes(process.Options{HashLimitBytes: s.options.HashLimitBytes}, force)
	})
	run(func() {
		sources.Host, sources.HostError = s.evidenceStore.Host(host.Options{HashLimitBytes: s.options.HashLimitBytes}, force)
	})
	run(func() {
		sources.FileTrace, sources.FileTraceError = s.evidenceStore.FileTraces(filetrace.Options{MaxRecords: sourceLimit, Hours: hours, ArtifactsOnly: true}, force)
	})
	run(func() {
		sources.History, sources.HistoryError = s.evidenceStore.History(history.Options{MaxRecords: sourceLimit, StartTime: startTime, EndTime: endTime}, force)
	})
	run(func() {
		sources.Security, sources.SecurityError = s.evidenceStore.Security(securitylog.Options{MaxRecords: sourceLimit, StartTime: startTime, EndTime: endTime}, force)
	})
	run(func() {
		sources.Drivers, sources.DriverError = s.evidenceStore.Drivers(driveranalysis.Options{HashLimitBytes: s.options.HashLimitBytes, MaxRecords: driverLimit}, force)
	})
	run(func() { sources.Connections, sources.ConnectionError = s.evidenceStore.Connections(force) })
	run(func() {
		sources.Registry, sources.RegistryError = s.evidenceStore.Registry(registryanomaly.Options{
			MaxRecords: sourceLimit, MaxKeys: 6000, MaxValues: 30000, MaxDepth: 5,
			MaxDataSize: 4 * 1024 * 1024, Timeout: 10 * time.Second,
		}, force)
	})
	wg.Wait()
	snapshot := investigation.Build(opts, sources)
	s.investigationCache = map[string]investigationCacheEntry{
		key: {snapshot: snapshot, expiresAt: time.Now().Add(2 * time.Minute)},
	}
	return investigation.ApplyScenario(snapshot, scenario), nil
}

func investigationMaxFromQuery(r *http.Request) int {
	value := strings.TrimSpace(r.URL.Query().Get("max"))
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 1500
	}
	if parsed > 5000 {
		return 5000
	}
	return parsed
}
