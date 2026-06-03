package server

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/aianalysis"
	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/dialog"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/loghealth"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/runtimeinfo"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"github.com/ruiwenya/WinTraceLens/internal/threatanalysis"
	"github.com/ruiwenya/WinTraceLens/internal/yaraengine"
)

//go:embed ui/*
var uiFiles embed.FS

type Options struct {
	HashLimitBytes int64
	Version        string
}

type Server struct {
	options     Options
	aiSessionMu sync.Mutex
	aiSession   aianalysis.SessionState
}

func New(options Options) *Server {
	return &Server{options: options}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/processes", s.handleProcesses)
	mux.HandleFunc("/api/processes.csv", s.handleProcessesCSV)
	mux.HandleFunc("/api/process/", s.handleProcessAction)
	mux.HandleFunc("/api/host", s.handleHost)
	mux.HandleFunc("/api/host.csv", s.handleHostCSV)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/findings.csv", s.handleFindingsCSV)
	mux.HandleFunc("/api/threat/memory", s.handleThreatMemory)
	mux.HandleFunc("/api/threat/memory.csv", s.handleThreatMemoryCSV)
	mux.HandleFunc("/api/threat/behavior", s.handleThreatBehavior)
	mux.HandleFunc("/api/threat/behavior.csv", s.handleThreatBehaviorCSV)
	mux.HandleFunc("/api/files/traces", s.handleFileTraces)
	mux.HandleFunc("/api/files/traces.csv", s.handleFileTracesCSV)
	mux.HandleFunc("/api/network/history", s.handleNetworkHistory)
	mux.HandleFunc("/api/network/history.csv", s.handleNetworkHistoryCSV)
	mux.HandleFunc("/api/security/events", s.handleSecurityEvents)
	mux.HandleFunc("/api/security/events.csv", s.handleSecurityEventsCSV)
	mux.HandleFunc("/api/log/health", s.handleLogHealth)
	mux.HandleFunc("/api/yara/status", s.handleYARAStatus)
	mux.HandleFunc("/api/yara/processes", s.handleYARAProcesses)
	mux.HandleFunc("/api/yara/rules", s.handleYARARules)
	mux.HandleFunc("/api/yara/validate", s.handleYARAValidate)
	mux.HandleFunc("/api/yara/scan", s.handleYARAScan)
	mux.HandleFunc("/api/ai/analyze", s.handleAIAnalyze)
	mux.HandleFunc("/api/ai/session", s.handleAISession)
	mux.HandleFunc("/api/dialog/folder", s.handleDialogFolder)
	mux.HandleFunc("/api/about", s.handleAbout)
	uiRoot, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(uiRoot)))
	return mux
}

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, runtimeinfo.Collect(s.options.Version))
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := host.Collect(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, snapshot)
}

func (s *Server) handleHostCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := host.Collect(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	q := r.URL.Query().Get("q")
	switch tab {
	case "", "services":
		rows := make([][]string, 0, len(snapshot.Services))
		for _, item := range snapshot.Services {
			row := []string{
				item.Name, item.DisplayName, item.State, item.StartMode, item.Account,
				item.MD5, item.Signature, item.SignatureMsg, item.Path, item.Command, item.HashError,
			}
			if matchesCSVQuery(q, row) {
				rows = append(rows, row)
			}
		}
		writeCSV(w, "host-services", []string{"服务名", "显示名", "状态", "启动", "账户", "MD5", "签名", "签名说明", "路径", "命令", "错误"}, rows)
	case "tasks":
		rows := make([][]string, 0, len(snapshot.ScheduledTasks))
		for _, item := range snapshot.ScheduledTasks {
			row := []string{
				item.Name, item.Path, item.State, item.Status, item.Author,
				item.MD5, item.Signature, item.SignatureMsg, item.Executable, item.Command, item.Arguments, item.HashError,
			}
			if matchesCSVQuery(q, row) {
				rows = append(rows, row)
			}
		}
		writeCSV(w, "host-tasks", []string{"任务名", "任务路径", "状态", "运行状态", "作者", "MD5", "签名", "签名说明", "可执行路径", "命令", "参数", "错误"}, rows)
	case "startup":
		rows := make([][]string, 0, len(snapshot.StartupItems))
		for _, item := range snapshot.StartupItems {
			row := []string{item.Source, item.Name, item.MD5, item.Signature, item.SignatureMsg, item.Path, item.Command, item.Location, item.HashError}
			if matchesCSVQuery(q, row) {
				rows = append(rows, row)
			}
		}
		writeCSV(w, "host-startup", []string{"来源", "名称", "MD5", "签名", "签名说明", "路径", "命令", "位置", "错误"}, rows)
	case "users":
		rows := make([][]string, 0, len(snapshot.Users))
		for _, item := range snapshot.Users {
			row := []string{
				item.Name, item.SID, strconv.FormatBool(item.Disabled), strconv.FormatBool(item.Lockout),
				strconv.FormatBool(item.PasswordRequired), strconv.FormatBool(item.LocalAccount),
			}
			if matchesCSVQuery(q, row) {
				rows = append(rows, row)
			}
		}
		writeCSV(w, "host-users", []string{"用户名", "SID", "禁用", "锁定", "需要密码", "本地账户"}, rows)
	case "ifeo":
		rows := make([][]string, 0, len(snapshot.ImageHijacks))
		for _, item := range snapshot.ImageHijacks {
			row := []string{item.Image, item.MD5, item.Signature, item.SignatureMsg, item.Path, item.Debugger, item.RegistryPath, item.HashError}
			if matchesCSVQuery(q, row) {
				rows = append(rows, row)
			}
		}
		writeCSV(w, "host-ifeo", []string{"目标镜像", "Debugger MD5", "签名", "签名说明", "Debugger 路径", "Debugger", "注册表路径", "错误"}, rows)
	default:
		http.Error(w, "unknown host csv tab", http.StatusBadRequest)
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, hostSummary, err := s.collectFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	if q != "" {
		items = filterFindings(items, q)
	}

	writeJSON(w, struct {
		Items       []analysis.Finding `json:"items"`
		Count       int                `json:"count"`
		GeneratedAt string             `json:"generatedAt"`
		HostSummary string             `json:"hostSummary"`
	}{
		Items:       items,
		Count:       len(items),
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		HostSummary: hostSummary,
	})
}

func (s *Server) handleFindingsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, _, err := s.collectFindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		row := []string{
			item.Level, item.Source, item.Name, item.Reason, item.MD5,
			item.Signature, item.SignatureMsg, item.Path, item.Command, item.Extra,
		}
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "ir-findings", []string{"级别", "来源", "名称", "原因", "MD5", "签名", "签名说明", "路径", "命令", "补充信息"}, rows)
}

func (s *Server) handleThreatMemory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := memoryscan.Collect(memoryScanOptionsFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapshot.Records = filterMemoryRecords(snapshot.Records, r.URL.Query().Get("q"))
	writeJSON(w, snapshot)
}

func (s *Server) handleThreatMemoryCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := memoryscan.Collect(memoryScanOptionsFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(snapshot.Records))
	for _, item := range snapshot.Records {
		row := memoryRecordRow(item)
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "threat-memory", []string{"级别", "分类", "PID", "进程", "路径", "原因", "基址/入口", "大小", "保护属性", "内存类型", "线程ID", "上下文", "详情"}, rows)
}

func (s *Server) handleThreatBehavior(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := threatanalysis.Collect(threatAnalysisOptionsFromRequest(r, s.options.HashLimitBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapshot.Items = filterThreatItems(snapshot.Items, r.URL.Query().Get("q"))
	writeJSON(w, snapshot)
}

func (s *Server) handleThreatBehaviorCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := threatanalysis.Collect(threatAnalysisOptionsFromRequest(r, s.options.HashLimitBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(snapshot.Items))
	for _, item := range snapshot.Items {
		row := threatanalysis.Row(item)
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "threat-behavior", []string{"级别", "场景", "评分", "PID", "进程/来源", "MD5", "签名", "连接数", "摘要", "路径", "证据", "关联信号"}, rows)
}

func (s *Server) handleFileTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := filetrace.Collect(fileTraceOptionsFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	snapshot.Records = filterFileTraceRecords(snapshot.Records, r.URL.Query().Get("category"), r.URL.Query().Get("q"))
	writeJSON(w, snapshot)
}

func (s *Server) handleFileTracesCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := filetrace.Collect(fileTraceOptionsFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	category := r.URL.Query().Get("category")
	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(snapshot.Records))
	for _, item := range snapshot.Records {
		row := fileTraceRecordRow(item)
		if fileTraceCategoryMatches(item, category) && matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "file-traces", []string{"分类", "来源", "名称", "路径", "目录", "扩展名", "大小", "创建时间", "修改时间", "访问时间", "最近运行", "运行次数", "可疑等级", "原因", "详情"}, rows)
}

func (s *Server) handleNetworkHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts, err := historyOptionsFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snapshot, err := history.Collect(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	snapshot.Records = filterHistoryRecords(snapshot.Records, r.URL.Query().Get("category"), q)
	writeJSON(w, snapshot)
}

func (s *Server) handleNetworkHistoryCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts, err := historyOptionsFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snapshot, err := history.Collect(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")
	rows := make([][]string, 0, len(snapshot.Records))
	for _, item := range snapshot.Records {
		row := historyRecordRow(item)
		if historyCategoryMatches(item, category) && matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "network-history", []string{"时间", "来源", "事件ID", "进程", "PID", "协议", "本地地址", "远程地址", "DNS 查询", "动作", "用户", "详情"}, rows)
}

func (s *Server) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts, err := securityLogOptionsFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snapshot, err := securitylog.Collect(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	snapshot.Events = filterSecurityEvents(snapshot.Events, r.URL.Query().Get("category"), q)
	writeJSON(w, snapshot)
}

func (s *Server) handleSecurityEventsCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	opts, err := securityLogOptionsFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snapshot, err := securitylog.Collect(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")
	rows := make([][]string, 0, len(snapshot.Events))
	for _, item := range snapshot.Events {
		row := securityEventRow(item)
		if securityCategoryMatches(item, category) && matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "security-events", []string{"时间", "分类", "来源", "事件ID", "动作", "账户", "域", "操作者", "登录类型", "登录类型说明", "来源IP", "来源端口", "工作站", "进程", "服务名", "命令/路径", "认证包", "状态", "失败原因", "目标SID", "Provider", "级别", "消息", "详情"}, rows)
}

func (s *Server) handleLogHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := loghealth.Collect()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, snapshot)
}

func (s *Server) handleYARAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, yaraengine.ResolveEngine(r.URL.Query().Get("enginePath")))
}

func (s *Server) handleYARAProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := process.Collect(process.Options{
		SkipHashes:     true,
		SkipSignatures: true,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		Items []process.Info `json:"items"`
		Count int            `json:"count"`
	}{
		Items: items,
		Count: len(items),
	})
}

func (s *Server) handleYARARules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req yaraengine.RulesRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, yaraengine.ValidateRules(r.Context(), req))
}

func (s *Server) handleYARAValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req yaraengine.ValidateRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, yaraengine.Validate(r.Context(), req))
}

func (s *Server) handleYARAScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req yaraengine.ScanRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	engine := yaraengine.ResolveEngine(req.EnginePath)
	var processes []process.Info
	var err error
	if engine.Found {
		processes, err = process.Collect(process.Options{
			SkipHashes:     true,
			SkipSignatures: true,
		})
	}
	resp := yaraengine.Scan(r.Context(), req, processes)
	if err != nil {
		resp.Errors = append(resp.Errors, "进程列表采集失败，文件命中将无法关联进程: "+err.Error())
	}
	writeJSON(w, resp)
}

func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req aianalysis.AnalyzeRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := aianalysis.Analyze(r.Context(), req, aianalysis.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		var validation aianalysis.ValidationError
		if errors.As(err, &validation) {
			http.Error(w, validation.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleAISession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.aiSessionMu.Lock()
		state := s.aiSession
		s.aiSessionMu.Unlock()
		writeJSON(w, state)
	case http.MethodPut:
		var state aianalysis.SessionState
		if err := readJSONBody(w, r, &state); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state = aianalysis.NormalizeSessionState(state)
		s.aiSessionMu.Lock()
		s.aiSession = state
		s.aiSessionMu.Unlock()
		writeJSON(w, state)
	case http.MethodDelete:
		s.aiSessionMu.Lock()
		s.aiSession = aianalysis.SessionState{}
		s.aiSessionMu.Unlock()
		writeJSON(w, struct {
			OK bool `json:"ok"`
		}{OK: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDialogFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, dialog.SelectFolder(r.URL.Query().Get("title")))
}

func (s *Server) collectFindings() ([]analysis.Finding, string, error) {
	processes, err := process.Collect(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		return nil, "", fmt.Errorf("process collection: %w", err)
	}

	hostSnapshot, err := host.Collect(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		return nil, "", fmt.Errorf("host collection: %w", err)
	}

	return analysis.BuildFindings(processes, hostSnapshot), hostSnapshot.Summary(), nil
}

func (s *Server) handleProcessAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/process/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	pid64, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}
	pid := uint32(pid64)

	switch parts[1] {
	case "detail":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleProcessDetail(w, r, pid)
	case "modules":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleModules(w, pid)
	case "connections":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleConnections(w, pid)
	case "open-path":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOpenPath(w, pid)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := process.Collect(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Items []process.Info `json:"items"`
		Count int            `json:"count"`
	}{
		Items: items,
		Count: len(items),
	})
}

func (s *Server) handleProcessesCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := process.Collect(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		row := []string{
			strconv.FormatUint(uint64(item.PID), 10),
			item.Name,
			item.MD5,
			item.Signature,
			item.SignatureMsg,
			strconv.Itoa(item.ConnectionCount),
			strconv.FormatUint(uint64(item.ParentPID), 10),
			item.ParentName,
			item.CreatedAt,
			item.Path,
			item.FileCreated,
			item.FileModified,
			strings.TrimSpace(item.HashError + " " + item.PathError),
		}
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "process-md5", []string{"PID", "进程名称", "MD5", "签名信息", "签名说明", "连接数", "父PID", "父进程", "进程创建时间", "可执行文件路径", "文件创建时间", "文件修改时间", "错误"}, rows)
}

func (s *Server) handleModules(w http.ResponseWriter, pid uint32) {
	items, err := process.Modules(pid, process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, struct {
		Items []process.ModuleInfo `json:"items"`
		Count int                  `json:"count"`
	}{
		Items: items,
		Count: len(items),
	})
}

func (s *Server) handleConnections(w http.ResponseWriter, pid uint32) {
	items, err := process.Connections(pid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, struct {
		Items []process.ConnectionInfo `json:"items"`
		Count int                      `json:"count"`
	}{
		Items: items,
		Count: len(items),
	})
}

func (s *Server) handleOpenPath(w http.ResponseWriter, pid uint32) {
	if err := process.OpenFileLocation(pid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func readJSONBody(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024*1024)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("请求 JSON 格式错误: %w", err)
	}
	return nil
}

func writeCSV(w http.ResponseWriter, name string, header []string, rows [][]string) {
	filename := fmt.Sprintf("%s-%s.csv", name, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	_ = writer.Write(sanitizeCSVRow(header))
	for _, row := range rows {
		_ = writer.Write(sanitizeCSVRow(row))
	}
	writer.Flush()
}

func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, value := range row {
		out[i] = strings.Join(strings.Fields(strings.ReplaceAll(value, "\x00", "")), " ")
	}
	return out
}

func filterFindings(items []analysis.Finding, q string) []analysis.Finding {
	filtered := make([]analysis.Finding, 0, len(items))
	for _, item := range items {
		row := []string{
			item.Level, item.Source, item.Name, item.Reason, item.MD5,
			item.Signature, item.SignatureMsg, item.Path, item.Command, item.Extra,
		}
		if matchesCSVQuery(q, row) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func matchesCSVQuery(q string, values []string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(fmt.Sprint(value)), q) {
			return true
		}
	}
	return false
}

func memoryScanOptionsFromRequest(r *http.Request) memoryscan.Options {
	return memoryscan.Options{
		MaxProcesses:         intFromQuery(r, "processes", 300, 1, 800),
		MaxRecords:           maxRecordsFromRequest(r),
		MaxRegionsPerProcess: intFromQuery(r, "regions", 64, 1, 512),
		IncludeThreads:       boolFromQuery(r, "threads", true),
	}
}

func threatAnalysisOptionsFromRequest(r *http.Request, hashLimitBytes int64) threatanalysis.Options {
	return threatanalysis.Options{
		HashLimitBytes:   hashLimitBytes,
		MaxRecords:       maxRecordsFromRequest(r),
		IncludeMemory:    boolFromQuery(r, "memory", true),
		IncludeFileTrace: boolFromQuery(r, "filetrace", false),
	}
}

func filterMemoryRecords(items []memoryscan.Record, q string) []memoryscan.Record {
	filtered := make([]memoryscan.Record, 0, len(items))
	for _, item := range items {
		if matchesCSVQuery(q, memoryRecordRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func memoryRecordRow(item memoryscan.Record) []string {
	return []string{
		item.Level,
		item.Category,
		strconv.FormatUint(uint64(item.PID), 10),
		item.Process,
		item.Path,
		item.Reason,
		item.Base,
		strconv.FormatUint(item.Size, 10),
		item.Protect,
		item.MemoryType,
		strconv.FormatUint(uint64(item.ThreadID), 10),
		item.Context,
		item.Details,
	}
}

func filterThreatItems(items []threatanalysis.Item, q string) []threatanalysis.Item {
	filtered := make([]threatanalysis.Item, 0, len(items))
	for _, item := range items {
		if matchesCSVQuery(q, threatanalysis.Row(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func fileTraceOptionsFromRequest(r *http.Request) filetrace.Options {
	return filetrace.Options{
		MaxRecords:    maxRecordsFromRequest(r),
		Hours:         hoursFromRequest(r),
		ModifiedRoots: fileTraceRootsFromRequest(r),
	}
}

func fileTraceRootsFromRequest(r *http.Request) []string {
	rawValues := make([]string, 0)
	rawValues = append(rawValues, r.URL.Query()["root"]...)
	if roots := strings.TrimSpace(r.URL.Query().Get("roots")); roots != "" {
		rawValues = append(rawValues, strings.FieldsFunc(roots, func(ch rune) bool {
			return ch == '\r' || ch == '\n' || ch == ';'
		})...)
	}

	seen := make(map[string]struct{})
	roots := make([]string, 0, len(rawValues))
	for _, value := range rawValues {
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, value)
		if len(roots) >= 8 {
			break
		}
	}
	return roots
}

func hoursFromRequest(r *http.Request) int {
	value := strings.TrimSpace(r.URL.Query().Get("hours"))
	if value == "" {
		return 72
	}
	hours, err := strconv.Atoi(value)
	if err != nil || hours <= 0 {
		return 72
	}
	if hours > 24*30 {
		return 24 * 30
	}
	return hours
}

func filterFileTraceRecords(items []filetrace.Record, category, q string) []filetrace.Record {
	filtered := make([]filetrace.Record, 0, len(items))
	for _, item := range items {
		if fileTraceCategoryMatches(item, category) && matchesCSVQuery(q, fileTraceRecordRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func fileTraceCategoryMatches(item filetrace.Record, category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "", "all":
		return true
	case "modified":
		return item.Category == "最近修改文件"
	case "run":
		return item.Category == "最近运行文件"
	case "temp":
		return item.Category == "Temp 临时文件"
	case "suspicious":
		return strings.TrimSpace(item.Suspicion) != ""
	default:
		return true
	}
}

func fileTraceRecordRow(item filetrace.Record) []string {
	return []string{
		item.Category,
		item.Source,
		item.Name,
		item.Path,
		item.Directory,
		item.Extension,
		strconv.FormatInt(item.Size, 10),
		item.Created,
		item.Modified,
		item.Accessed,
		item.LastRun,
		item.RunCount,
		item.Suspicion,
		item.Reason,
		item.Details,
	}
}

func filterHistoryRecords(items []history.Record, category, q string) []history.Record {
	filtered := make([]history.Record, 0, len(items))
	for _, item := range items {
		if historyCategoryMatches(item, category) && matchesCSVQuery(q, historyRecordRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func historyCategoryMatches(item history.Record, category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "", "all":
		return true
	case "connections":
		switch item.Source {
		case "Sysmon", "安全日志 WFP", "防火墙日志":
			return true
		default:
			return false
		}
	case "dns":
		switch item.Source {
		case "DNS 缓存", "Sysmon DNS", "DNS Client 日志":
			return true
		default:
			return false
		}
	default:
		return true
	}
}

func historyRecordRow(item history.Record) []string {
	return []string{
		item.Time,
		item.Source,
		item.EventID,
		item.Process,
		item.PID,
		item.Proto,
		item.Local,
		item.Remote,
		item.Query,
		item.Action,
		item.User,
		item.Details,
	}
}

func maxRecordsFromRequest(r *http.Request) int {
	value := strings.TrimSpace(r.URL.Query().Get("max"))
	if value == "" {
		return 500
	}
	maxRecords, err := strconv.Atoi(value)
	if err != nil || maxRecords <= 0 {
		return 500
	}
	if maxRecords > 5000 {
		return 5000
	}
	return maxRecords
}

func intFromQuery(r *http.Request, name string, defaultValue, minValue, maxValue int) int {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	if parsed < minValue {
		return minValue
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

func boolFromQuery(r *http.Request, name string, defaultValue bool) bool {
	value := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name)))
	if value == "" {
		return defaultValue
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func historyOptionsFromRequest(r *http.Request) (history.Options, error) {
	startTime, endTime, err := dateRangeFromRequest(r)
	if err != nil {
		return history.Options{}, err
	}
	return history.Options{
		MaxRecords: maxRecordsFromRequest(r),
		StartTime:  startTime,
		EndTime:    endTime,
	}, nil
}

func securityLogOptionsFromRequest(r *http.Request) (securitylog.Options, error) {
	startTime, endTime, err := dateRangeFromRequest(r)
	if err != nil {
		return securitylog.Options{}, err
	}
	return securitylog.Options{
		MaxRecords: maxRecordsFromRequest(r),
		StartTime:  startTime,
		EndTime:    endTime,
	}, nil
}

func dateRangeFromRequest(r *http.Request) (time.Time, time.Time, error) {
	startTime, err := parseDateQuery(r, "start", false)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	endTime, err := parseDateQuery(r, "end", true)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !startTime.IsZero() && !endTime.IsZero() && endTime.Before(startTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("结束日期不能早于开始日期")
	}
	return startTime, endTime, nil
}

func parseDateQuery(r *http.Request, key string, endOfDay bool) (time.Time, error) {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s 参数格式错误，应为 YYYY-MM-DD", key)
	}
	if endOfDay {
		return parsed.Add(24*time.Hour - time.Second), nil
	}
	return parsed, nil
}

func filterSecurityEvents(items []securitylog.Event, category, q string) []securitylog.Event {
	filtered := make([]securitylog.Event, 0, len(items))
	for _, item := range items {
		if securityCategoryMatches(item, category) && matchesCSVQuery(q, securityEventRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func securityCategoryMatches(item securitylog.Event, category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "", "all":
		return true
	case "logon":
		switch item.Category {
		case "登录", "登录失败", "注销", "特权登录", "工作站锁定", "工作站解锁":
			return true
		default:
			return false
		}
	case "rdp":
		return strings.Contains(item.Category, "RDP") || strings.Contains(item.Action, "RDP")
	case "service":
		return item.Category == "服务创建"
	case "user":
		return item.Category == "用户账户"
	case "powershell":
		return item.Category == "PowerShell日志"
	case "sql":
		return item.Category == "SQL Server日志"
	default:
		return true
	}
}

func securityEventRow(item securitylog.Event) []string {
	return []string{
		item.Time,
		item.Category,
		item.Source,
		item.EventID,
		item.Action,
		item.Account,
		item.Domain,
		item.Subject,
		item.LogonType,
		item.LogonTypeName,
		item.SourceIP,
		item.SourcePort,
		item.Workstation,
		item.Process,
		item.ServiceName,
		item.Command,
		item.AuthPackage,
		item.Status,
		item.FailureReason,
		item.TargetSID,
		item.Provider,
		item.Level,
		item.Message,
		item.Details,
	}
}
