package server

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/aianalysis"
	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/dialog"
	"github.com/ruiwenya/WinTraceLens/internal/driveranalysis"
	"github.com/ruiwenya/WinTraceLens/internal/evidence"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/runtimeinfo"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"github.com/ruiwenya/WinTraceLens/internal/systemtools"
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
	options            Options
	accessToken        string
	aiSessionMu        sync.Mutex
	aiSession          aianalysis.SessionState
	aiPreviews         map[string]aiPreviewEntry
	investigationMu    sync.Mutex
	investigationCache map[string]investigationCacheEntry
	evidenceStore      *evidence.Store
}

type aiPreviewEntry struct {
	prepared  aianalysis.PreparedAnalysis
	expiresAt time.Time
}

func New(options Options) *Server {
	return &Server{
		options:            options,
		accessToken:        newAccessToken(),
		aiPreviews:         make(map[string]aiPreviewEntry),
		investigationCache: make(map[string]investigationCacheEntry),
		evidenceStore:      evidence.NewStore(),
	}
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
	mux.HandleFunc("/api/threat/drivers", s.handleThreatDrivers)
	mux.HandleFunc("/api/threat/drivers.csv", s.handleThreatDriversCSV)
	mux.HandleFunc("/api/threat/driver-checks.csv", s.handleThreatDriverChecksCSV)
	mux.HandleFunc("/api/files/traces", s.handleFileTraces)
	mux.HandleFunc("/api/files/traces.csv", s.handleFileTracesCSV)
	mux.HandleFunc("/api/network/history", s.handleNetworkHistory)
	mux.HandleFunc("/api/network/history.csv", s.handleNetworkHistoryCSV)
	mux.HandleFunc("/api/network/live", s.handleNetworkLive)
	mux.HandleFunc("/api/network/live.csv", s.handleNetworkLiveCSV)
	mux.HandleFunc("/api/security/events", s.handleSecurityEvents)
	mux.HandleFunc("/api/security/events.csv", s.handleSecurityEventsCSV)
	mux.HandleFunc("/api/log/health", s.handleLogHealth)
	mux.HandleFunc("/api/log/health.csv", s.handleLogHealthCSV)
	mux.HandleFunc("/api/investigation", s.handleInvestigation)
	mux.HandleFunc("/api/investigation.csv", s.handleInvestigationCSV)
	mux.HandleFunc("/api/yara/status", s.handleYARAStatus)
	mux.HandleFunc("/api/yara/processes", s.handleYARAProcesses)
	mux.HandleFunc("/api/yara/rules", s.handleYARARules)
	mux.HandleFunc("/api/yara/validate", s.handleYARAValidate)
	mux.HandleFunc("/api/yara/scan", s.handleYARAScan)
	mux.HandleFunc("/api/ai/analyze", s.handleAIAnalyze)
	mux.HandleFunc("/api/ai/preview", s.handleAIPreview)
	mux.HandleFunc("/api/ai/session", s.handleAISession)
	mux.HandleFunc("/api/dialog/folder", s.handleDialogFolder)
	mux.HandleFunc("/api/dialog/file", s.handleDialogFile)
	mux.HandleFunc("/api/system/open", s.handleSystemOpen)
	mux.HandleFunc("/api/about", s.handleAbout)
	mux.HandleFunc("/app.js", s.handleAppJS)
	mux.HandleFunc("/health.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/security.html?tab=health", http.StatusTemporaryRedirect)
	})
	uiRoot, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(uiRoot)))
	return s.requireLocalSession(mux)
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

	snapshot, err := s.evidenceStore.Host(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, boolFromQuery(r, "refresh", false))
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

	snapshot, err := s.evidenceStore.Host(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, false)
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

	items, hostSummary, err := s.collectFindings(boolFromQuery(r, "refresh", false))
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

	items, _, err := s.collectFindings(false)
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

	snapshot, err := s.evidenceStore.Memory(memoryScanOptionsFromRequest(r), boolFromQuery(r, "refresh", false))
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

	snapshot, err := s.evidenceStore.Memory(memoryScanOptionsFromRequest(r), false)
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

	snapshot, err := s.threatBehaviorSnapshot(threatAnalysisOptionsFromRequest(r, s.options.HashLimitBytes), boolFromQuery(r, "refresh", false))
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

	snapshot, err := s.threatBehaviorSnapshot(threatAnalysisOptionsFromRequest(r, s.options.HashLimitBytes), false)
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

func (s *Server) handleThreatDrivers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := s.evidenceStore.Drivers(driverAnalysisOptionsFromRequest(r, s.options.HashLimitBytes), boolFromQuery(r, "refresh", false))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snapshot.Items = filterDriverItems(snapshot.Items, r.URL.Query().Get("q"))
	writeJSON(w, snapshot)
}

func (s *Server) handleThreatDriversCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := s.evidenceStore.Drivers(driverAnalysisOptionsFromRequest(r, s.options.HashLimitBytes), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(snapshot.Items))
	for _, item := range snapshot.Items {
		row := driveranalysis.Row(item)
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "threat-drivers", []string{"级别", "评分", "驱动名", "类型", "签名", "签名说明", "MD5", "MD5/文件错误", "基址", "大小KB", "路径", "服务项", "启动类型", "服务类型", "服务ImagePath", "注册表路径", "事件关联", "磁盘路径", "Amcache路径", "Amcache SHA1", "Amcache信息", "Amcache记录时间", "多源差异", "原因", "证据"}, rows)
}

func (s *Server) handleThreatDriverChecksCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := s.evidenceStore.Drivers(driverAnalysisOptionsFromRequest(r, s.options.HashLimitBytes), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([][]string, 0, len(snapshot.Checks))
	for _, check := range snapshot.Checks {
		rows = append(rows, driveranalysis.CheckRow(check))
	}
	writeCSV(w, "threat-driver-checks", []string{"级别", "状态", "核查项", "数量", "说明", "样例", "建议"}, rows)
}

func (s *Server) handleFileTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshot, err := s.fileTraceSnapshot(fileTraceOptionsFromRequest(r), boolFromQuery(r, "refresh", false))
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

	snapshot, err := s.fileTraceSnapshot(fileTraceOptionsFromRequest(r), false)
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
	writeCSV(w, "file-traces", []string{"分类", "来源", "名称", "路径", "目录", "扩展名", "大小", "创建时间", "修改时间", "访问时间", "最近运行", "运行次数", "可疑等级", "原因", "详情", "Schema", "SHA1", "Publisher", "产品", "产品版本", "BinaryType", "ProgramId", "应用关联", "Amcache记录时间", "时间语义", "PE链接时间", "当前签名", "签名说明"}, rows)
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
	snapshot, err := s.evidenceStore.History(opts, boolFromQuery(r, "refresh", false))
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
	snapshot, err := s.evidenceStore.History(opts, false)
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

type liveConnectionItem struct {
	PID        uint32 `json:"pid"`
	Process    string `json:"process"`
	Path       string `json:"path"`
	ParentPID  uint32 `json:"parentPid"`
	ParentName string `json:"parentName"`
	Protocol   string `json:"protocol"`
	Local      string `json:"local"`
	LocalIP    string `json:"localIp"`
	LocalPort  uint16 `json:"localPort"`
	Remote     string `json:"remote"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort uint16 `json:"remotePort"`
	RemoteKind string `json:"remoteKind"`
	State      string `json:"state"`
}

func (s *Server) handleNetworkLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := s.collectLiveConnections(boolFromQuery(r, "refresh", false))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items = filterLiveConnections(items, r.URL.Query().Get("q"))
	writeJSON(w, struct {
		Items       []liveConnectionItem `json:"items"`
		Count       int                  `json:"count"`
		GeneratedAt string               `json:"generatedAt"`
	}{
		Items:       items,
		Count:       len(items),
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	})
}

func (s *Server) handleNetworkLiveCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	items, err := s.collectLiveConnections(false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items = filterLiveConnections(items, r.URL.Query().Get("q"))
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, liveConnectionRow(item))
	}
	writeCSV(w, "network-live", []string{"PID", "进程", "父PID", "父进程", "协议", "本地地址", "本地IP", "本地端口", "远程地址", "远程IP", "远程端口", "远程类型", "状态", "路径"}, rows)
}

func (s *Server) collectLiveConnections(force bool) ([]liveConnectionItem, error) {
	processes, err := s.evidenceStore.Processes(process.Options{
		SkipHashes:     true,
		SkipSignatures: true,
	}, force)
	if err != nil {
		return nil, err
	}
	connections, err := s.evidenceStore.Connections(force)
	if err != nil {
		return nil, err
	}
	byPID := make(map[uint32]process.Info, len(processes))
	for _, item := range processes {
		byPID[item.PID] = item
	}
	items := make([]liveConnectionItem, 0, len(connections))
	for _, conn := range connections {
		proc := byPID[conn.PID]
		items = append(items, liveConnectionItem{
			PID:        conn.PID,
			Process:    proc.Name,
			Path:       proc.Path,
			ParentPID:  proc.ParentPID,
			ParentName: proc.ParentName,
			Protocol:   conn.Protocol,
			Local:      conn.Local,
			LocalIP:    conn.LocalIP,
			LocalPort:  conn.LocalPort,
			Remote:     conn.Remote,
			RemoteIP:   conn.RemoteIP,
			RemotePort: conn.RemotePort,
			RemoteKind: conn.RemoteKind,
			State:      conn.State,
		})
	}
	return items, nil
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
	snapshot, err := s.evidenceStore.Security(opts, boolFromQuery(r, "refresh", false))
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
	snapshot, err := s.evidenceStore.Security(opts, false)
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
	snapshot, err := s.evidenceStore.LogHealth(boolFromQuery(r, "refresh", false))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, snapshot)
}

func (s *Server) handleLogHealthCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.evidenceStore.LogHealth(false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := r.URL.Query().Get("q")
	rows := make([][]string, 0, len(snapshot.Sources))
	for _, item := range snapshot.Sources {
		row := []string{
			item.Category, item.Name, item.Status, item.LogName, item.EventIDs,
			item.LastEventTime, strconv.FormatInt(item.RecordCount, 10), item.Details, item.Recommendation,
		}
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "log-health", []string{"类别", "日志源", "状态", "日志名/来源", "事件ID", "最后事件", "记录数", "详情", "建议"}, rows)
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

	items, err := s.evidenceStore.Processes(process.Options{
		SkipHashes:     true,
		SkipSignatures: true,
	}, boolFromQuery(r, "refresh", false))
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
		processes, err = s.evidenceStore.Processes(process.Options{
			SkipHashes:     true,
			SkipSignatures: true,
		}, false)
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
	if strings.TrimSpace(req.APIKey) == "" {
		s.aiSessionMu.Lock()
		req.APIKey = s.aiSession.APIKeys[aiProviderKey(req.Provider)]
		s.aiSessionMu.Unlock()
	} else {
		s.aiSessionMu.Lock()
		if s.aiSession.APIKeys == nil {
			s.aiSession.APIKeys = make(map[string]string)
		}
		s.aiSession.APIKeys[aiProviderKey(req.Provider)] = strings.TrimSpace(req.APIKey)
		s.aiSessionMu.Unlock()
	}

	var resp aianalysis.AnalyzeResponse
	var err error
	if len(req.Messages) == 0 {
		prepared, ok := s.consumeAIPreview(req.PreviewID)
		if !ok {
			http.Error(w, "请先预览并确认将发送给 AI 的内容", http.StatusBadRequest)
			return
		}
		resp, err = aianalysis.AnalyzePrepared(r.Context(), req, prepared)
	} else {
		resp, err = aianalysis.Analyze(r.Context(), req, aianalysis.Options{
			HashLimitBytes: s.options.HashLimitBytes,
			Evidence:       s.evidenceStore,
		})
	}
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

func (s *Server) handleAIPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req aianalysis.AnalyzeRequest
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prepared, preview, err := aianalysis.Prepare(req, aianalysis.Options{
		HashLimitBytes: s.options.HashLimitBytes,
		Evidence:       s.evidenceStore,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	preview.PreviewID = newAccessToken()
	s.aiSessionMu.Lock()
	now := time.Now()
	for id, entry := range s.aiPreviews {
		if now.After(entry.expiresAt) {
			delete(s.aiPreviews, id)
		}
	}
	s.aiPreviews[preview.PreviewID] = aiPreviewEntry{
		prepared:  prepared,
		expiresAt: now.Add(10 * time.Minute),
	}
	s.aiSessionMu.Unlock()
	writeJSON(w, preview)
}

func (s *Server) consumeAIPreview(id string) (aianalysis.PreparedAnalysis, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return aianalysis.PreparedAnalysis{}, false
	}
	s.aiSessionMu.Lock()
	defer s.aiSessionMu.Unlock()
	entry, ok := s.aiPreviews[id]
	delete(s.aiPreviews, id)
	if !ok || time.Now().After(entry.expiresAt) {
		return aianalysis.PreparedAnalysis{}, false
	}
	return entry.prepared, true
}

func (s *Server) handleAISession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.aiSessionMu.Lock()
		state := publicAISessionState(s.aiSession)
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
		storedKeys := s.aiSession.APIKeys
		if storedKeys == nil {
			storedKeys = make(map[string]string)
		}
		for provider, key := range state.APIKeys {
			storedKeys[aiProviderKey(provider)] = key
		}
		state.APIKeys = storedKeys
		s.aiSession = state
		publicState := publicAISessionState(state)
		s.aiSessionMu.Unlock()
		writeJSON(w, publicState)
	case http.MethodDelete:
		s.aiSessionMu.Lock()
		s.aiSession = aianalysis.SessionState{}
		s.aiPreviews = make(map[string]aiPreviewEntry)
		s.aiSessionMu.Unlock()
		writeJSON(w, struct {
			OK bool `json:"ok"`
		}{OK: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func publicAISessionState(state aianalysis.SessionState) aianalysis.SessionState {
	state.SavedAPIKeys = make(map[string]bool)
	for provider, key := range state.APIKeys {
		if strings.TrimSpace(key) != "" {
			state.SavedAPIKeys[provider] = true
		}
	}
	if len(state.SavedAPIKeys) == 0 {
		state.SavedAPIKeys = nil
	}
	state.APIKeys = nil
	return state
}

func aiProviderKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "moonshot":
		return "kimi"
	case "dashscope":
		return "qwen"
	case "":
		return "openai"
	default:
		return value
	}
}

func (s *Server) handleDialogFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, dialog.SelectFolder(r.URL.Query().Get("title")))
}

func (s *Server) handleDialogFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, dialog.SelectFile(r.URL.Query().Get("title")))
}

func (s *Server) handleSystemOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Tool string `json:"tool"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tool, err := systemtools.Open(req.Tool)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, struct {
		OK      bool             `json:"ok"`
		Tool    systemtools.Tool `json:"tool"`
		Message string           `json:"message"`
	}{OK: true, Tool: tool, Message: "已请求打开系统界面：" + tool.Label})
}

func (s *Server) collectFindings(force bool) ([]analysis.Finding, string, error) {
	processes, err := s.evidenceStore.Processes(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, force)
	if err != nil {
		return nil, "", fmt.Errorf("process collection: %w", err)
	}

	hostSnapshot, err := s.evidenceStore.Host(host.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, force)
	if err != nil {
		return nil, "", fmt.Errorf("host collection: %w", err)
	}

	return analysis.BuildFindings(processes, hostSnapshot), hostSnapshot.Summary(), nil
}

func (s *Server) threatBehaviorSnapshot(opts threatanalysis.Options, force bool) (threatanalysis.Snapshot, error) {
	processes, err := s.evidenceStore.Processes(process.Options{HashLimitBytes: opts.HashLimitBytes}, force)
	if err != nil {
		return threatanalysis.Snapshot{}, fmt.Errorf("process collection: %w", err)
	}
	sources := threatanalysis.Sources{Processes: processes}
	sources.Host, err = s.evidenceStore.Host(host.Options{HashLimitBytes: opts.HashLimitBytes}, force)
	if err != nil {
		sources.CollectionErrors = append(sources.CollectionErrors, "主机持久化采集失败: "+err.Error())
	}
	if opts.IncludeMemory {
		sources.Memory, err = s.evidenceStore.Memory(memoryscan.Options{
			MaxProcesses:         len(processes),
			MaxRecords:           1000,
			MaxRegionsPerProcess: 48,
			IncludeThreads:       true,
		}, force)
		if err != nil {
			sources.CollectionErrors = append(sources.CollectionErrors, "内存异常采集失败: "+err.Error())
		} else {
			sources.CollectionErrors = append(sources.CollectionErrors, sources.Memory.CollectionErrors...)
		}
	}
	if opts.IncludeFileTrace {
		sources.FileTrace, err = s.evidenceStore.FileTraces(filetrace.Options{MaxRecords: 300, Hours: 24 * 7}, force)
		if err != nil {
			sources.CollectionErrors = append(sources.CollectionErrors, "文件痕迹采集失败: "+err.Error())
		} else {
			sources.CollectionErrors = append(sources.CollectionErrors, sources.FileTrace.CollectionErrors...)
		}
	}
	return threatanalysis.Build(opts, sources), nil
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
	case "modules.csv":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleModulesCSV(w, pid)
	case "connections":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleConnections(w, r, pid)
	case "connections.csv":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleConnectionsCSV(w, pid)
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

	items, err := s.evidenceStore.Processes(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, boolFromQuery(r, "refresh", false))
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

	items, err := s.evidenceStore.Processes(process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	}, false)
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
			item.EnumerationSources,
			item.EnumerationWarning,
		}
		if matchesCSVQuery(q, row) {
			rows = append(rows, row)
		}
	}
	writeCSV(w, "process-md5", []string{"PID", "进程名称", "MD5", "签名信息", "签名说明", "连接数", "父PID", "父进程", "进程创建时间", "可执行文件路径", "文件创建时间", "文件修改时间", "错误", "枚举视图", "枚举差异"}, rows)
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

func (s *Server) handleModulesCSV(w http.ResponseWriter, pid uint32) {
	items, err := process.Modules(pid, process.Options{
		HashLimitBytes: s.options.HashLimitBytes,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name,
			item.Kind,
			item.MD5,
			item.Signature,
			item.SignatureMsg,
			item.BaseAddress,
			strconv.FormatUint(uint64(item.SizeKB), 10),
			item.Path,
			item.HashError,
		})
	}
	writeCSV(w, fmt.Sprintf("process-%d-modules", pid), []string{"模块名", "类型", "MD5", "签名信息", "签名说明", "基址", "大小KB", "路径", "错误"}, rows)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request, pid uint32) {
	items, err := s.processConnections(pid, boolFromQuery(r, "refresh", false))
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

func (s *Server) handleConnectionsCSV(w http.ResponseWriter, pid uint32) {
	items, err := s.processConnections(pid, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, processConnectionRow(item))
	}
	writeCSV(w, fmt.Sprintf("process-%d-connections", pid), []string{"PID", "协议", "本地地址", "本地IP", "本地端口", "远程地址", "远程IP", "远程端口", "远程类型", "状态"}, rows)
}

func (s *Server) processConnections(pid uint32, force bool) ([]process.ConnectionInfo, error) {
	connections, err := s.evidenceStore.Connections(force)
	if err != nil {
		return nil, err
	}
	items := make([]process.ConnectionInfo, 0)
	for _, item := range connections {
		if item.PID == pid {
			items = append(items, item)
		}
	}
	return items, nil
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
		value = strings.Join(strings.Fields(strings.ReplaceAll(value, "\x00", "")), " ")
		if value != "" && strings.ContainsRune("=+-@", rune(value[0])) {
			value = "'" + value
		}
		out[i] = value
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
	q = strings.TrimSpace(q)
	if q == "" {
		return true
	}
	if expression, isRegex, valid := csvQueryRegexp(q); isRegex {
		return valid && expression.MatchString(strings.Join(values, " "))
	}
	q = strings.ToLower(q)
	haystack := strings.ToLower(strings.Join(values, " "))
	parts := strings.Fields(q)
	if len(parts) > 1 {
		for _, part := range parts {
			if !strings.Contains(haystack, part) {
				return false
			}
		}
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(fmt.Sprint(value)), q) {
			return true
		}
	}
	return false
}

func csvQueryRegexp(query string) (*regexp.Regexp, bool, bool) {
	pattern := ""
	flags := ""
	if strings.HasPrefix(query, "re:") {
		pattern = strings.TrimSpace(strings.TrimPrefix(query, "re:"))
		flags = "i"
	} else if strings.HasPrefix(query, "/") {
		end := strings.LastIndex(query, "/")
		if end <= 0 {
			return nil, false, true
		}
		pattern = query[1:end]
		flags = query[end+1:]
		if strings.ContainsAny(flags, "^$()[]{}|\\") {
			return nil, true, false
		}
	} else if looksLikeBareRegexQuery(query) {
		pattern = query
		flags = "i"
	} else {
		return nil, false, true
	}
	for _, flag := range flags {
		if !strings.ContainsRune("ims", flag) {
			return nil, true, false
		}
	}
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	expression, err := regexp.Compile(pattern)
	return expression, true, err == nil
}

func looksLikeBareRegexQuery(query string) bool {
	if strings.Contains(query, ".*") || strings.Contains(query, ".+") || strings.Contains(query, ".?") {
		return true
	}
	for _, marker := range []string{`\d`, `\D`, `\s`, `\S`, `\w`, `\W`, `\b`, `\B`} {
		if strings.Contains(query, marker) {
			return true
		}
	}
	if strings.HasPrefix(query, "^") || strings.HasSuffix(query, "$") {
		return true
	}
	left := strings.Index(query, "[")
	right := strings.LastIndex(query, "]")
	return left >= 0 && right > left
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

func driverAnalysisOptionsFromRequest(r *http.Request, hashLimitBytes int64) driveranalysis.Options {
	return driveranalysis.Options{
		HashLimitBytes: hashLimitBytes,
		MaxRecords:     maxRecordsFromRequest(r),
		AmcachePath:    strings.Trim(strings.TrimSpace(r.URL.Query().Get("amcache_path")), `"`),
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

func filterDriverItems(items []driveranalysis.Item, q string) []driveranalysis.Item {
	filtered := make([]driveranalysis.Item, 0, len(items))
	for _, item := range items {
		if matchesCSVQuery(q, driveranalysis.Row(item)) {
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
		AmcachePath:   strings.Trim(strings.TrimSpace(r.URL.Query().Get("amcache_path")), `"`),
	}
}

func (s *Server) fileTraceSnapshot(opts filetrace.Options, force bool) (filetrace.Snapshot, error) {
	return s.evidenceStore.FileTraces(opts, force)
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
	case "artifacts":
		if item.Source == "Prefetch" || item.Source == "Recent 快捷方式" {
			return true
		}
		switch item.Category {
		case "执行痕迹", "命令历史", "NTFS 元数据", "NTFS 变更痕迹", "网络与应用痕迹", "取证源状态":
			return true
		default:
			return false
		}
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
		item.Schema,
		item.SHA1,
		item.Publisher,
		item.ProductName,
		item.ProductVersion,
		item.BinaryType,
		item.ProgramID,
		item.Association,
		item.EvidenceTime,
		item.TimeMeaning,
		item.LinkDate,
		item.Signature,
		item.SignatureMsg,
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

func processConnectionRow(item process.ConnectionInfo) []string {
	return []string{
		strconv.FormatUint(uint64(item.PID), 10),
		item.Protocol,
		item.Local,
		item.LocalIP,
		strconv.FormatUint(uint64(item.LocalPort), 10),
		item.Remote,
		item.RemoteIP,
		strconv.FormatUint(uint64(item.RemotePort), 10),
		item.RemoteKind,
		item.State,
	}
}

func liveConnectionRow(item liveConnectionItem) []string {
	return []string{
		strconv.FormatUint(uint64(item.PID), 10),
		item.Process,
		strconv.FormatUint(uint64(item.ParentPID), 10),
		item.ParentName,
		item.Protocol,
		item.Local,
		item.LocalIP,
		strconv.FormatUint(uint64(item.LocalPort), 10),
		item.Remote,
		item.RemoteIP,
		strconv.FormatUint(uint64(item.RemotePort), 10),
		item.RemoteKind,
		item.State,
		item.Path,
	}
}

func filterLiveConnections(items []liveConnectionItem, q string) []liveConnectionItem {
	filtered := make([]liveConnectionItem, 0, len(items))
	for _, item := range items {
		if matchesCSVQuery(q, liveConnectionRow(item)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
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
		return !securitylog.IsLowValuePowerShellEvent(item)
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
