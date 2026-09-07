package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/driveranalysis"
	"github.com/ruiwenya/WinTraceLens/internal/evidencebundle"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/investigation"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"github.com/ruiwenya/WinTraceLens/internal/threatanalysis"
)

type evidenceCollectRequest struct {
	Sources      []string `json:"sources"`
	Start        string   `json:"start"`
	End          string   `json:"end"`
	MaxRecords   int      `json:"maxRecords"`
	MaxProcesses int      `json:"maxProcesses"`
	startTime    time.Time
	endTime      time.Time
}

func (req *evidenceCollectRequest) validate(now time.Time) error {
	var err error
	req.Sources, err = evidencebundle.NormalizeSelection(req.Sources)
	if err != nil {
		return err
	}
	if req.MaxRecords == 0 {
		req.MaxRecords = 500
	}
	if req.MaxProcesses == 0 {
		req.MaxProcesses = 300
	}
	if req.MaxRecords < 1 || req.MaxRecords > 3000 || req.MaxProcesses < 1 || req.MaxProcesses > 800 {
		return errors.New("条数应为 1–3000，进程上限应为 1–800")
	}
	if req.Start == "" {
		req.Start = now.AddDate(0, 0, -6).Format("2006-01-02")
	}
	if req.End == "" {
		req.End = now.Format("2006-01-02")
	}
	req.startTime, err = time.ParseInLocation("2006-01-02", req.Start, time.Local)
	if err != nil {
		return errors.New("日志开始日期无效")
	}
	req.endTime, err = time.ParseInLocation("2006-01-02", req.End, time.Local)
	if err != nil {
		return errors.New("日志结束日期无效")
	}
	req.endTime = req.endTime.AddDate(0, 0, 1).Add(-time.Nanosecond)
	if req.startTime.After(req.endTime) {
		return errors.New("日志开始日期不能晚于结束日期")
	}
	if req.endTime.Sub(req.startTime) > 31*24*time.Hour {
		return errors.New("一键采集的日志范围最多 31 天；更长范围请在事件日志页单独采集")
	}
	return nil
}

var evidenceDependencies = map[string][]string{
	"process-modules":     {"processes"},
	"registry-correlated": {"registry", "processes", "host"},
	"findings":            {"processes", "host", "registry-correlated"},
	"memory":              {"processes"},
	"behavior":            {"processes", "host", "memory", "file-traces"},
	"investigation":       {"processes", "connections", "host", "registry-correlated", "file-traces", "network-history", "security-events", "drivers"},
}

var evidenceCollectionPriority = []string{
	"processes", "connections", "host", "registry", "registry-correlated",
	"network-history", "security-events", "file-traces", "drivers", "memory",
	"process-modules", "log-health", "findings", "behavior", "investigation",
}

func evidenceCollectionPlan(sources []string) ([]string, error) {
	selected, err := evidencebundle.NormalizeSelection(sources)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var plan []string
	var visit func(string)
	visit = func(id string) {
		if seen[id] || id == "yara" {
			return
		}
		seen[id] = true
		for _, dependency := range evidenceDependencies[id] {
			visit(dependency)
		}
		plan = append(plan, id)
	}
	selectedSet := make(map[string]bool, len(selected))
	for _, id := range selected {
		selectedSet[id] = true
	}
	for _, id := range evidenceCollectionPriority {
		if selectedSet[id] {
			visit(id)
		}
	}
	for _, id := range selected {
		visit(id)
	}
	if len(plan) == 0 {
		return nil, errors.New("YARA 需要指定规则，不能自动采集；可直接导出已有结果")
	}
	return plan, nil
}

type evidenceProgress struct {
	Type      string   `json:"type"`
	Source    string   `json:"source,omitempty"`
	Label     string   `json:"label,omitempty"`
	Completed int      `json:"completed"`
	Total     int      `json:"total"`
	Percent   int      `json:"percent"`
	Status    string   `json:"status,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

type evidenceStep struct {
	ID    string
	Label string
	Run   func(context.Context, func(int, int, string)) ([]string, error)
}

// Completion percentages count finished stages, not elapsed time or success rate.
func runEvidenceSteps(ctx context.Context, steps []evidenceStep, emit func(evidenceProgress) error) error {
	var allWarnings []string
	for i, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		event := evidenceProgress{Type: "progress", Source: step.ID, Label: step.Label, Completed: i, Total: len(steps), Percent: i * 100 / len(steps), Status: "running"}
		if err := emit(event); err != nil {
			return err
		}
		var sendErr error
		warnings, err := step.Run(ctx, func(current, total int, detail string) {
			if sendErr != nil || total <= 0 {
				return
			}
			if current < 0 {
				current = 0
			}
			if current > total {
				current = total
			}
			event.Percent = (i*100 + current*100/total) / len(steps)
			if event.Percent > 99 {
				event.Percent = 99
			}
			event.Detail = detail
			sendErr = emit(event)
		})
		if sendErr != nil {
			return sendErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		event.Type = "result"
		event.Completed = i + 1
		event.Percent = (i + 1) * 100 / len(steps)
		event.Detail = ""
		event.Status = "complete"
		if err != nil {
			warnings = append(warnings, err.Error())
			event.Status = "failed"
		} else if len(warnings) > 0 {
			event.Status = "partial"
		}
		for _, warning := range warnings {
			allWarnings = append(allWarnings, step.Label+"："+warning)
		}
		// Keep the streamed UI compact; full warnings stay in the evidence datasets.
		if len(warnings) > 20 {
			warnings = append(warnings[:20], fmt.Sprintf("另有 %d 条提示，详见取证包", len(warnings)-20))
		}
		event.Warnings = warnings
		if err := emit(event); err != nil {
			return err
		}
	}
	status := "complete"
	if len(allWarnings) > 0 {
		status = "partial"
	}
	return emit(evidenceProgress{Type: "done", Completed: len(steps), Total: len(steps), Percent: 100, Status: status, Detail: fmt.Sprintf("采集结束：%d 个阶段，%d 条提示。YARA 不自动运行。", len(steps), len(allWarnings))})
}

func (s *Server) handleEvidenceCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req evidenceCollectRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := req.validate(time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := evidenceCollectionPlan(req.Sources)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.evidenceCollectMu.TryLock() {
		http.Error(w, "已有采集任务正在执行或收尾，请稍后更新范围再试。", http.StatusConflict)
		return
	}
	defer s.evidenceCollectMu.Unlock()
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "当前连接不支持采集进度流", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	encoder := json.NewEncoder(w)
	_ = runEvidenceSteps(r.Context(), s.evidenceSteps(req, plan), func(event evidenceProgress) error {
		if err := encoder.Encode(event); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
}

func (s *Server) evidenceSteps(req evidenceCollectRequest, plan []string) []evidenceStep {
	store := s.evidenceStore
	sources := investigation.Sources{}
	var memory memoryscan.Snapshot
	var memoryErr error
	limits := map[string]any{"start": req.Start, "end": req.End, "maxRecords": req.MaxRecords, "maxProcesses": req.MaxProcesses}
	labels, _ := evidencebundle.Describe(nil)
	labelMap := make(map[string]string)
	for _, item := range labels.Sources {
		labelMap[item.ID] = item.Label
	}
	var steps []evidenceStep
	for _, sourceID := range plan {
		id := sourceID
		steps = append(steps, evidenceStep{ID: id, Label: labelMap[id], Run: func(ctx context.Context, progress func(int, int, string)) ([]string, error) {
			warnings, err := func() ([]string, error) {
				switch id {
				case "processes":
					sources.Processes, sources.ProcessError = store.Processes(process.Options{HashLimitBytes: s.options.HashLimitBytes}, true)
					return nil, sources.ProcessError
				case "connections":
					sources.Connections, sources.ConnectionError = store.Connections(true)
					return nil, sources.ConnectionError
				case "host":
					sources.Host, sources.HostError = store.Host(host.Options{HashLimitBytes: s.options.HashLimitBytes}, true)
					return sources.Host.CollectionErrors, sources.HostError
				case "registry":
					sources.Registry, sources.RegistryError = store.Registry(registryanomaly.Options{MaxRecords: req.MaxRecords, MaxKeys: 6000, MaxValues: 30000, MaxDepth: 5, MaxDataSize: 4 * 1024 * 1024, Timeout: 15 * time.Second}, true)
					return sources.Registry.CollectionErrors, sources.RegistryError
				case "registry-correlated":
					if sources.RegistryError != nil {
						return nil, fmt.Errorf("注册表基础采集失败：%w", sources.RegistryError)
					}
					sources.Registry = registryanomaly.Correlate(sources.Registry, sources.Processes, sources.Host)
					for _, e := range []error{sources.ProcessError, sources.HostError} {
						if e != nil {
							sources.Registry.CollectionErrors = append(sources.Registry.CollectionErrors, "关联来源不完整："+e.Error())
						}
					}
					s.rememberEvidence(id, limits, sources.Registry)
					return sources.Registry.CollectionErrors, nil
				case "file-traces":
					sources.FileTrace, sources.FileTraceError = store.FileTraces(filetrace.Options{Hours: 168, MaxRecords: req.MaxRecords}, true)
					return sources.FileTrace.CollectionErrors, sources.FileTraceError
				case "network-history":
					sources.History, sources.HistoryError = store.History(history.Options{StartTime: req.startTime, EndTime: req.endTime, MaxRecords: req.MaxRecords}, true)
					return sources.History.CollectionErrors, sources.HistoryError
				case "security-events":
					sources.Security, sources.SecurityError = store.Security(securitylog.Options{StartTime: req.startTime, EndTime: req.endTime, MaxRecords: req.MaxRecords}, true)
					return sources.Security.CollectionErrors, sources.SecurityError
				case "log-health":
					_, err := store.LogHealth(true)
					return nil, err
				case "drivers":
					sources.Drivers, sources.DriverError = store.Drivers(driveranalysis.Options{HashLimitBytes: s.options.HashLimitBytes, MaxRecords: req.MaxRecords}, true)
					return sources.Drivers.CollectionErrors, sources.DriverError
				case "memory":
					memory, memoryErr = store.Memory(memoryscan.Options{MaxProcesses: req.MaxProcesses, MaxRecords: req.MaxRecords, MaxRegionsPerProcess: 48, IncludeThreads: true}, true)
					return memory.CollectionErrors, memoryErr
				case "process-modules":
					if sources.ProcessError != nil {
						return nil, fmt.Errorf("进程采集失败：%w", sources.ProcessError)
					}
					items := prioritizeModuleTargets(sources.Processes)
					var warnings []string
					attempted := 0
					defer func() {
						status := "complete"
						if ctx.Err() != nil {
							status = "cancelled"
							warnings = append(warnings, "采集中断，未继续读取剩余进程模块")
						} else if len(warnings) > 0 {
							status = "partial"
						}
						s.rememberEvidence(id, map[string]any{"batchScope": limits}, map[string]any{
							"collectionStatus": status, "collectionErrors": warnings,
							"availableProcesses": len(sources.Processes), "attemptedProcesses": attempted,
						})
					}()
					if len(items) > req.MaxProcesses {
						warnings = append(warnings, fmt.Sprintf("进程模块最多采集前 %d 个进程，共 %d 个", req.MaxProcesses, len(items)))
						items = items[:req.MaxProcesses]
					}
					for i, item := range items {
						if err := ctx.Err(); err != nil {
							return warnings, err
						}
						_, err := s.collectModuleEvidence(item.PID)
						attempted++
						if err != nil {
							warnings = append(warnings, fmt.Sprintf("PID %d %s：%s", item.PID, item.Name, err))
						}
						progress(i+1, len(items), fmt.Sprintf("PID %d，%d / %d", item.PID, i+1, len(items)))
					}
					return warnings, nil
				case "findings":
					var warnings []string
					for _, e := range []error{sources.ProcessError, sources.HostError, sources.RegistryError} {
						if e != nil {
							warnings = append(warnings, e.Error())
						}
					}
					items := analysis.BuildFindings(sources.Processes, sources.Host)
					items = append(items, analysis.RegistryFindings(sources.Registry)...)
					s.rememberEvidence(id, limits, map[string]any{"items": items, "collectionErrors": warnings})
					return warnings, nil
				case "behavior":
					var warnings []string
					for _, e := range []error{sources.ProcessError, sources.HostError, sources.FileTraceError, memoryErr} {
						if e != nil {
							warnings = append(warnings, e.Error())
						}
					}
					warnings = append(warnings, sources.Host.CollectionErrors...)
					warnings = append(warnings, sources.FileTrace.CollectionErrors...)
					warnings = append(warnings, memory.CollectionErrors...)
					snapshot := threatanalysis.Build(threatanalysis.Options{HashLimitBytes: s.options.HashLimitBytes, MaxRecords: req.MaxRecords, IncludeMemory: true, IncludeFileTrace: true}, threatanalysis.Sources{Processes: sources.Processes, Host: sources.Host, Memory: memory, FileTrace: sources.FileTrace, CollectionErrors: warnings})
					s.rememberEvidence(id, limits, snapshot)
					return snapshot.CollectionErrors, nil
				case "investigation":
					snapshot := investigation.Build(investigation.Options{StartTime: req.startTime, EndTime: req.endTime, MaxRecords: req.MaxRecords, Hours: 168, HashLimitBytes: s.options.HashLimitBytes}, sources)
					s.rememberEvidence(id, limits, snapshot)
					return snapshot.CollectionErrors, nil
				}
				return nil, fmt.Errorf("不支持的采集来源：%s", id)
			}()
			if !errors.Is(err, context.Canceled) {
				store.RecordCollectionFailure(id, err)
			}
			return warnings, err
		}})
	}
	return steps
}

func prioritizeModuleTargets(items []process.Info) []process.Info {
	prioritized := append([]process.Info(nil), items...)
	sort.SliceStable(prioritized, func(i, j int) bool {
		left := moduleTargetScore(prioritized[i])
		right := moduleTargetScore(prioritized[j])
		if left != right {
			return left > right
		}
		return prioritized[i].PID < prioritized[j].PID
	})
	return prioritized
}

func moduleTargetScore(item process.Info) int {
	score := 0
	if item.PID == 4 {
		score += 100
	}
	signature := strings.ToLower(item.Signature + " " + item.SignatureMsg)
	if strings.Contains(signature, "无签名") || strings.Contains(signature, "未签名") || strings.Contains(signature, "异常") || strings.Contains(signature, "invalid") {
		score += 60
	}
	path := strings.ToLower(strings.ReplaceAll(item.Path, "/", `\`))
	for _, marker := range []string{`\temp\`, `\appdata\`, `\programdata\`, `\users\public\`} {
		if strings.Contains(path, marker) {
			score += 45
			break
		}
	}
	if item.EnumerationWarning != "" || item.PathError != "" {
		score += 30
	}
	if item.ConnectionCount > 0 {
		connectionScore := item.ConnectionCount
		if connectionScore > 20 {
			connectionScore = 20
		}
		score += 10 + connectionScore
	}
	return score
}
