package server

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

type processDetailResponse struct {
	Process          process.Info             `json:"process"`
	Parent           *process.Info            `json:"parent"`
	Children         []process.Info           `json:"children"`
	Services         []host.ServiceInfo       `json:"services"`
	ScheduledTasks   []host.ScheduledTaskInfo `json:"scheduledTasks"`
	StartupItems     []host.StartupItem       `json:"startupItems"`
	ImageHijacks     []host.ImageHijackInfo   `json:"imageHijacks"`
	HistoryRecords   []history.Record         `json:"historyRecords"`
	SecurityEvents   []securitylog.Event      `json:"securityEvents"`
	CollectionErrors []string                 `json:"collectionErrors"`
	GeneratedAt      string                   `json:"generatedAt"`
}

func (s *Server) handleProcessDetail(w http.ResponseWriter, r *http.Request, pid uint32) {
	processes, err := process.Collect(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	current, parent, children, found := selectProcessFamily(processes, pid)
	if !found {
		http.Error(w, "process not found", http.StatusNotFound)
		return
	}

	resp := processDetailResponse{
		Process:     current,
		Parent:      parent,
		Children:    children,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	maxRecords := maxRecordsFromRequest(r)
	if maxRecords <= 0 {
		maxRecords = 300
	}
	if maxRecords > 1000 {
		maxRecords = 1000
	}

	startTime, endTime, rangeErr := dateRangeFromRequest(r)
	if rangeErr != nil {
		resp.CollectionErrors = append(resp.CollectionErrors, rangeErr.Error())
	}

	var wg sync.WaitGroup
	var hostSnapshot host.Snapshot
	var hostErr error
	var historySnapshot history.Snapshot
	var historyErr error
	var securitySnapshot securitylog.Snapshot
	var securityErr error

	wg.Add(3)
	go func() {
		defer wg.Done()
		hostSnapshot, hostErr = host.Collect(host.Options{HashLimitBytes: s.options.HashLimitBytes})
	}()
	go func() {
		defer wg.Done()
		historySnapshot, historyErr = history.Collect(history.Options{
			MaxRecords: maxRecords,
			StartTime:  startTime,
			EndTime:    endTime,
		})
	}()
	go func() {
		defer wg.Done()
		securitySnapshot, securityErr = securitylog.Collect(securitylog.Options{
			MaxRecords: maxRecords,
			StartTime:  startTime,
			EndTime:    endTime,
		})
	}()
	wg.Wait()

	if hostErr != nil {
		resp.CollectionErrors = append(resp.CollectionErrors, "主机持久化信息采集失败: "+hostErr.Error())
	} else {
		resp.CollectionErrors = append(resp.CollectionErrors, hostSnapshot.CollectionErrors...)
		resp.Services = relatedServices(hostSnapshot.Services, current)
		resp.ScheduledTasks = relatedTasks(hostSnapshot.ScheduledTasks, current)
		resp.StartupItems = relatedStartupItems(hostSnapshot.StartupItems, current)
		resp.ImageHijacks = relatedImageHijacks(hostSnapshot.ImageHijacks, current)
	}

	if historyErr != nil {
		resp.CollectionErrors = append(resp.CollectionErrors, "历史通信记录采集失败: "+historyErr.Error())
	} else {
		resp.CollectionErrors = append(resp.CollectionErrors, historySnapshot.CollectionErrors...)
		resp.HistoryRecords = limitHistoryRecords(relatedHistoryRecords(historySnapshot.Records, current), 120)
	}

	if securityErr != nil {
		resp.CollectionErrors = append(resp.CollectionErrors, "事件日志采集失败: "+securityErr.Error())
	} else {
		resp.CollectionErrors = append(resp.CollectionErrors, securitySnapshot.CollectionErrors...)
		resp.SecurityEvents = limitSecurityEvents(relatedSecurityEvents(securitySnapshot.Events, current), 120)
	}

	writeJSON(w, resp)
}

func selectProcessFamily(items []process.Info, pid uint32) (process.Info, *process.Info, []process.Info, bool) {
	var current process.Info
	found := false
	byPID := make(map[uint32]process.Info, len(items))
	for _, item := range items {
		byPID[item.PID] = item
		if item.PID == pid {
			current = item
			found = true
		}
	}
	if !found {
		return process.Info{}, nil, nil, false
	}

	var parent *process.Info
	if item, ok := byPID[current.ParentPID]; ok {
		parent = &item
	}

	children := make([]process.Info, 0)
	for _, item := range items {
		if item.ParentPID == pid {
			children = append(children, item)
		}
	}
	return current, parent, children, true
}

func relatedServices(items []host.ServiceInfo, proc process.Info) []host.ServiceInfo {
	out := make([]host.ServiceInfo, 0)
	for _, item := range items {
		if relatedToProcess(proc, item.Path, item.Command, item.Name, item.DisplayName) {
			out = append(out, item)
		}
	}
	return out
}

func relatedTasks(items []host.ScheduledTaskInfo, proc process.Info) []host.ScheduledTaskInfo {
	out := make([]host.ScheduledTaskInfo, 0)
	for _, item := range items {
		if relatedToProcess(proc, item.Executable, item.Command, item.Arguments, item.Name, item.Path) {
			out = append(out, item)
		}
	}
	return out
}

func relatedStartupItems(items []host.StartupItem, proc process.Info) []host.StartupItem {
	out := make([]host.StartupItem, 0)
	for _, item := range items {
		if relatedToProcess(proc, item.Path, item.Command, item.Name, item.Location) {
			out = append(out, item)
		}
	}
	return out
}

func relatedImageHijacks(items []host.ImageHijackInfo, proc process.Info) []host.ImageHijackInfo {
	out := make([]host.ImageHijackInfo, 0)
	for _, item := range items {
		if relatedToProcess(proc, item.Path, item.Debugger, item.Image, item.RegistryPath) {
			out = append(out, item)
		}
	}
	return out
}

func relatedHistoryRecords(items []history.Record, proc process.Info) []history.Record {
	pid := strconv.FormatUint(uint64(proc.PID), 10)
	out := make([]history.Record, 0)
	for _, item := range items {
		if strings.TrimSpace(item.PID) == pid || relatedToProcess(proc, item.Process, item.Details, item.User, item.Query) {
			out = append(out, item)
		}
	}
	return out
}

func relatedSecurityEvents(items []securitylog.Event, proc process.Info) []securitylog.Event {
	pid := strconv.FormatUint(uint64(proc.PID), 10)
	out := make([]securitylog.Event, 0)
	for _, item := range items {
		if strings.Contains(item.Process, pid) ||
			relatedToProcess(proc, item.Process, item.Command, item.ServiceName, item.Message, item.Details) {
			out = append(out, item)
		}
	}
	return out
}

func relatedToProcess(proc process.Info, values ...string) bool {
	procPath := normalizeEvidence(proc.Path)
	procName := strings.ToLower(strings.TrimSpace(proc.Name))
	baseName := strings.ToLower(strings.TrimSpace(filepath.Base(proc.Path)))
	if baseName == "." || baseName == string(filepath.Separator) {
		baseName = ""
	}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		normalized := normalizeEvidence(value)
		if procPath != "" && (normalized == procPath || strings.Contains(normalized, procPath) || strings.Contains(value, procPath)) {
			return true
		}
		if procName != "" && strings.Contains(value, procName) {
			return true
		}
		if baseName != "" && strings.Contains(value, baseName) {
			return true
		}
	}
	return false
}

func normalizeEvidence(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(value))
}

func limitHistoryRecords(items []history.Record, max int) []history.Record {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func limitSecurityEvents(items []securitylog.Event, max int) []securitylog.Event {
	if len(items) <= max {
		return items
	}
	return items[:max]
}
