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
	force := boolFromQuery(r, "refresh", false)
	processes, err := s.evidenceStore.Processes(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, force)
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
		hostSnapshot, hostErr = s.evidenceStore.Host(host.Options{HashLimitBytes: s.options.HashLimitBytes}, force)
	}()
	go func() {
		defer wg.Done()
		historySnapshot, historyErr = s.evidenceStore.History(history.Options{
			MaxRecords: maxRecords,
			StartTime:  startTime,
			EndTime:    endTime,
		}, force)
	}()
	go func() {
		defer wg.Done()
		securitySnapshot, securityErr = s.evidenceStore.Security(securitylog.Options{
			MaxRecords: maxRecords,
			StartTime:  startTime,
			EndTime:    endTime,
		}, force)
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
	if item, ok := byPID[current.ParentPID]; ok && validParentInstance(item, current) {
		parent = &item
	}

	children := make([]process.Info, 0)
	for _, item := range items {
		if item.ParentPID == pid && validParentInstance(current, item) {
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
	out := make([]history.Record, 0)
	for _, item := range items {
		if !eventBelongsToProcessLifetime(proc, item.Time) {
			continue
		}
		if strings.TrimSpace(item.PID) != "" {
			pid, ok := parsePIDReference(item.PID)
			if ok && pid == proc.PID {
				out = append(out, item)
			}
			continue
		}
		if strictProcessReference(proc, item.Process) {
			out = append(out, item)
		}
	}
	return out
}

func relatedSecurityEvents(items []securitylog.Event, proc process.Info) []securitylog.Event {
	out := make([]securitylog.Event, 0)
	for _, item := range items {
		if securitylog.IsWinTraceLensCollectorEvent(item) || securitylog.IsLowValuePowerShellEvent(item) {
			continue
		}
		if !eventBelongsToProcessLifetime(proc, item.Time) {
			continue
		}
		if pid, ok := parsePIDReference(item.Process); ok {
			if pid == proc.PID {
				out = append(out, item)
			}
			continue
		}
		if strictProcessReference(proc, item.Process) || strictProcessReference(proc, item.Command) {
			out = append(out, item)
		}
	}
	return out
}

func relatedToProcess(proc process.Info, values ...string) bool {
	for _, value := range values {
		if strictProcessReference(proc, value) {
			return true
		}
	}
	return false
}

func strictProcessReference(proc process.Info, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	procPath := normalizeEvidence(proc.Path)
	procName := strings.ToLower(strings.TrimSpace(proc.Name))
	baseName := strings.ToLower(strings.TrimSpace(filepath.Base(proc.Path)))
	if baseName == "." || baseName == string(filepath.Separator) {
		baseName = ""
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == procName || lower == baseName {
		return procName != "" || baseName != ""
	}
	if procPath != "" {
		if normalizeEvidence(value) == procPath || containsCommandPath(lower, procPath) {
			return true
		}
	}
	candidate := commandExecutable(value)
	if candidate == "" {
		return false
	}
	if strings.ContainsAny(candidate, `\\/`) {
		return procPath != "" && normalizeEvidence(candidate) == procPath
	}
	candidate = strings.ToLower(candidate)
	return candidate == procName || candidate == baseName
}

func commandExecutable(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value[0] == '"' {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			return strings.TrimSpace(value[1 : end+1])
		}
	}
	lower := strings.ToLower(value)
	end := len(value)
	found := false
	for _, ext := range []string{".exe", ".com", ".bat", ".cmd", ".dll"} {
		if index := strings.Index(lower, ext); index >= 0 && (!found || index+len(ext) < end) {
			end = index + len(ext)
			found = true
		}
	}
	if found {
		return strings.Trim(strings.TrimSpace(value[:end]), `"`)
	}
	if fields := strings.Fields(value); len(fields) > 0 {
		return strings.Trim(fields[0], `"`)
	}
	return ""
}

func containsCommandPath(value, normalizedPath string) bool {
	value = strings.ReplaceAll(strings.ToLower(value), "/", `\`)
	normalizedPath = strings.ReplaceAll(normalizedPath, "/", `\`)
	for start := 0; ; {
		index := strings.Index(value[start:], normalizedPath)
		if index < 0 {
			return false
		}
		index += start
		beforeOK := index == 0 || isCommandBoundary(value[index-1])
		after := index + len(normalizedPath)
		afterOK := after == len(value) || isCommandBoundary(value[after])
		if beforeOK && afterOK {
			return true
		}
		start = index + 1
	}
}

func isCommandBoundary(value byte) bool {
	return value == ' ' || value == '\t' || value == '"' || value == '\'' || value == ',' || value == ';' || value == '(' || value == ')'
}

func parsePIDReference(value string) (uint32, bool) {
	value = strings.TrimSpace(value)
	if pid, ok := parsePIDToken(value); ok {
		return pid, true
	}
	lower := strings.ToLower(value)
	for _, label := range []string{"process id", "processid", "pid"} {
		index := strings.Index(lower, label)
		if index < 0 {
			continue
		}
		tail := strings.TrimLeft(lower[index+len(label):], " \t:=#")
		end := 0
		for end < len(tail) && (tail[end] >= '0' && tail[end] <= '9' || tail[end] >= 'a' && tail[end] <= 'f' || tail[end] == 'x') {
			end++
		}
		if end > 0 {
			return parsePIDToken(tail[:end])
		}
	}
	return 0, false
}

func parsePIDToken(value string) (uint32, bool) {
	value = strings.TrimSpace(value)
	base := 10
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		base = 16
		value = value[2:]
	}
	parsed, err := strconv.ParseUint(value, base, 32)
	return uint32(parsed), err == nil
}

func eventBelongsToProcessLifetime(proc process.Info, eventTime string) bool {
	created, createdOK := parseProcessTime(proc.CreatedAt)
	eventAt, eventOK := parseProcessTime(eventTime)
	return !createdOK || !eventOK || !eventAt.Before(created.Add(-2*time.Second))
}

func validParentInstance(parent, child process.Info) bool {
	parentCreated, parentOK := parseProcessTime(parent.CreatedAt)
	if expected, expectedOK := parseProcessTime(child.ParentCreatedAt); parentOK && expectedOK {
		delta := parentCreated.Sub(expected)
		return delta >= -2*time.Second && delta <= 2*time.Second
	}
	childCreated, childOK := parseProcessTime(child.CreatedAt)
	return !parentOK || !childOK || !parentCreated.After(childCreated.Add(2*time.Second))
}

func parseProcessTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, time.RFC3339Nano} {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
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
