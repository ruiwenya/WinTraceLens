package aianalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/loghealth"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"github.com/ruiwenya/WinTraceLens/internal/threatanalysis"
)

const (
	sectionProcesses = "processes"
	sectionFindings  = "findings"
	sectionBehavior  = "behavior"
	sectionMemory    = "memory"
	sectionHost      = "host"
	sectionFileTrace = "filetrace"
	sectionHistory   = "history"
	sectionSecurity  = "security"
	sectionLogHealth = "loghealth"

	defaultMaxItems       = 80
	maxItemsUpperBound    = 300
	defaultTimeoutSeconds = 90
	maxTimeoutSeconds     = 240
)

type Options struct {
	HashLimitBytes int64
}

type AnalyzeRequest struct {
	Provider        string    `json:"provider"`
	Model           string    `json:"model"`
	APIKey          string    `json:"apiKey"`
	BaseURL         string    `json:"baseUrl"`
	Sections        []string  `json:"sections"`
	Question        string    `json:"question"`
	Messages        []Message `json:"messages"`
	IncludeEvidence bool      `json:"includeEvidence"`
	MaxItems        int       `json:"maxItems"`
	TimeoutSeconds  int       `json:"timeoutSeconds"`
}

type AnalyzeResponse struct {
	Provider         string           `json:"provider"`
	Model            string           `json:"model"`
	Endpoint         string           `json:"endpoint"`
	Answer           string           `json:"answer"`
	Sections         []SectionSummary `json:"sections"`
	CollectionErrors []string         `json:"collectionErrors"`
	Usage            Usage            `json:"usage"`
	PromptBytes      int              `json:"promptBytes"`
	GeneratedAt      string           `json:"generatedAt"`
}

type SessionState struct {
	Messages  []Message         `json:"messages"`
	Summary   AnalyzeResponse   `json:"summary"`
	Settings  SessionSettings   `json:"settings"`
	APIKeys   map[string]string `json:"apiKeys,omitempty"`
	Status    string            `json:"status"`
	UpdatedAt string            `json:"updatedAt"`
}

type SessionSettings struct {
	Provider    string   `json:"provider"`
	Model       string   `json:"model"`
	CustomModel string   `json:"customModel"`
	BaseURL     string   `json:"baseUrl"`
	Sections    []string `json:"sections"`
	Question    string   `json:"question"`
	MaxItems    int      `json:"maxItems"`
	Timeout     int      `json:"timeout"`
}

type SectionSummary struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`
	TotalTokens      int `json:"totalTokens"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

type providerConfig struct {
	key          string
	displayName  string
	baseURL      string
	defaultModel string
}

type evidenceBundle struct {
	GeneratedAt string            `json:"generatedAt"`
	Sections    []evidenceSection `json:"sections"`
}

type evidenceSection struct {
	Key              string   `json:"key"`
	Label            string   `json:"label"`
	Count            int      `json:"count"`
	Note             string   `json:"note,omitempty"`
	CollectionErrors []string `json:"collectionErrors,omitempty"`
	Items            any      `json:"items"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage chatUsage `json:"usage"`
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}

type chatUsage struct {
	PromptTokens          int `json:"prompt_tokens"`
	CompletionTokens      int `json:"completion_tokens"`
	TotalTokens           int `json:"total_tokens"`
	PromptTokensCamel     int `json:"promptTokens"`
	CompletionTokensCamel int `json:"completionTokens"`
	TotalTokensCamel      int `json:"totalTokens"`
}

func (u chatUsage) usage() Usage {
	usage := Usage{
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
	}
	if usage.PromptTokens == 0 {
		usage.PromptTokens = u.PromptTokensCamel
	}
	if usage.CompletionTokens == 0 {
		usage.CompletionTokens = u.CompletionTokensCamel
	}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = u.TotalTokensCamel
	}
	return usage
}

func Analyze(ctx context.Context, req AnalyzeRequest, opts Options) (AnalyzeResponse, error) {
	cfg, err := resolveProvider(req.Provider)
	if err != nil {
		return AnalyzeResponse{}, err
	}
	req.APIKey = strings.TrimSpace(req.APIKey)
	if req.APIKey == "" {
		return AnalyzeResponse{}, ValidationError{Message: "API Key 不能为空"}
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = cfg.defaultModel
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = cfg.baseURL
	}
	endpoint, err := chatEndpoint(baseURL)
	if err != nil {
		return AnalyzeResponse{}, err
	}
	req.MaxItems = normalizeMaxItems(req.MaxItems)
	req.TimeoutSeconds = normalizeTimeout(req.TimeoutSeconds)

	var evidence evidenceBundle
	var sections []evidenceSection
	var messages []chatMessage
	var promptBytes int
	if len(req.Messages) > 0 {
		messages, err = normalizeMessages(req.Messages)
		if err != nil {
			return AnalyzeResponse{}, err
		}
		if req.IncludeEvidence {
			req.Sections = normalizeSections(req.Sections)
			evidence = collectEvidence(req.Sections, req.MaxItems, opts)
			sections = evidence.Sections
			prompt, err := evidencePrompt(evidence)
			if err != nil {
				return AnalyzeResponse{}, fmt.Errorf("构建 AI 分析数据失败: %w", err)
			}
			messages = append([]chatMessage{{Role: "user", Content: prompt}}, messages...)
		}
		promptBytes = messagesBytes(messages)
	} else {
		req.Sections = normalizeSections(req.Sections)
		evidence = collectEvidence(req.Sections, req.MaxItems, opts)
		sections = evidence.Sections
		userPrompt, err := userPrompt(req.Question, evidence)
		if err != nil {
			return AnalyzeResponse{}, fmt.Errorf("构建 AI 分析数据失败: %w", err)
		}
		messages = []chatMessage{{Role: "user", Content: userPrompt}}
		promptBytes = len([]byte(userPrompt))
	}
	systemPrompt := systemPrompt()
	apiMessages := append([]chatMessage{{Role: "system", Content: systemPrompt}}, messages...)

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	answer, usage, err := callChatCompletion(callCtx, endpoint, req.APIKey, model, apiMessages)
	if err != nil {
		return AnalyzeResponse{}, err
	}

	return AnalyzeResponse{
		Provider:         cfg.displayName,
		Model:            model,
		Endpoint:         endpoint,
		Answer:           answer,
		Sections:         sectionSummaries(sections),
		CollectionErrors: collectionErrors(sections),
		Usage:            usage,
		PromptBytes:      promptBytes,
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}, nil
}

func resolveProvider(provider string) (providerConfig, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "openai":
		return providerConfig{
			key:          "openai",
			displayName:  "OpenAI",
			baseURL:      "https://api.openai.com/v1",
			defaultModel: "gpt-5.5",
		}, nil
	case "deepseek":
		return providerConfig{
			key:          "deepseek",
			displayName:  "DeepSeek",
			baseURL:      "https://api.deepseek.com",
			defaultModel: "deepseek-v4-flash",
		}, nil
	case "kimi", "moonshot":
		return providerConfig{
			key:          "kimi",
			displayName:  "Kimi",
			baseURL:      "https://api.moonshot.ai/v1",
			defaultModel: "kimi-k2.6",
		}, nil
	case "qwen", "dashscope":
		return providerConfig{
			key:          "qwen",
			displayName:  "Qwen",
			baseURL:      "https://dashscope.aliyuncs.com/compatible-mode/v1",
			defaultModel: "qwen3.7-plus",
		}, nil
	case "custom":
		return providerConfig{
			key:          "custom",
			displayName:  "自定义",
			defaultModel: "model-name",
		}, nil
	default:
		return providerConfig{}, ValidationError{Message: "不支持的 AI 厂商: " + provider}
	}
}

func chatEndpoint(baseURL string) (string, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return "", ValidationError{Message: "接口地址不能为空"}
	}
	if strings.HasSuffix(strings.ToLower(baseURL), "/chat/completions") {
		return baseURL, nil
	}
	return baseURL + "/chat/completions", nil
}

func normalizeSections(values []string) []string {
	if len(values) == 0 {
		values = []string{sectionProcesses, sectionFindings, sectionBehavior, sectionLogHealth}
	}
	allowed := map[string]struct{}{
		sectionProcesses: {},
		sectionFindings:  {},
		sectionBehavior:  {},
		sectionMemory:    {},
		sectionHost:      {},
		sectionFileTrace: {},
		sectionHistory:   {},
		sectionSecurity:  {},
		sectionLogHealth: {},
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if _, ok := allowed[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	if len(out) == 0 {
		return []string{sectionProcesses, sectionFindings, sectionBehavior, sectionLogHealth}
	}
	return out
}

func normalizeMaxItems(value int) int {
	if value <= 0 {
		return defaultMaxItems
	}
	if value > maxItemsUpperBound {
		return maxItemsUpperBound
	}
	return value
}

func normalizeTimeout(value int) int {
	if value <= 0 {
		return defaultTimeoutSeconds
	}
	if value > maxTimeoutSeconds {
		return maxTimeoutSeconds
	}
	return value
}

func NormalizeSessionState(state SessionState) SessionState {
	state.Messages = normalizeSessionMessages(state.Messages)
	state.Summary.Answer = ""
	state.Summary.Endpoint = trimText(state.Summary.Endpoint, 500)
	state.APIKeys = normalizeAPIKeys(state.APIKeys)
	state.Status = trimText(state.Status, 80)
	state.Settings.Provider = trimText(state.Settings.Provider, 40)
	state.Settings.Model = trimText(state.Settings.Model, 120)
	state.Settings.CustomModel = trimText(state.Settings.CustomModel, 120)
	state.Settings.BaseURL = trimText(state.Settings.BaseURL, 500)
	state.Settings.Sections = normalizeSections(state.Settings.Sections)
	state.Settings.Question = trimText(state.Settings.Question, 4000)
	state.Settings.MaxItems = normalizeMaxItems(state.Settings.MaxItems)
	state.Settings.Timeout = normalizeTimeout(state.Settings.Timeout)
	state.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	return state
}

func normalizeAPIKeys(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string)
	for provider, key := range values {
		provider = strings.ToLower(strings.TrimSpace(provider))
		key = trimText(key, 500)
		if provider == "" || key == "" {
			continue
		}
		out[provider] = key
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSessionMessages(values []Message) []Message {
	out := make([]Message, 0, len(values))
	for _, value := range values {
		role := strings.ToLower(strings.TrimSpace(value.Role))
		if role != "user" && role != "assistant" {
			continue
		}
		content := trimText(value.Content, 20000)
		if content == "" {
			continue
		}
		out = append(out, Message{Role: role, Content: content})
	}
	if len(out) > 40 {
		out = out[len(out)-40:]
	}
	return out
}

func normalizeMessages(values []Message) ([]chatMessage, error) {
	out := make([]chatMessage, 0, len(values))
	for _, value := range values {
		role := strings.ToLower(strings.TrimSpace(value.Role))
		switch role {
		case "user", "assistant":
		default:
			continue
		}
		content := trimText(value.Content, 12000)
		if content == "" {
			continue
		}
		out = append(out, chatMessage{Role: role, Content: content})
	}
	if len(out) == 0 {
		return nil, ValidationError{Message: "连续对话内容不能为空"}
	}
	if len(out) > 20 {
		out = out[len(out)-20:]
	}
	if out[len(out)-1].Role != "user" {
		return nil, ValidationError{Message: "连续对话最后一条必须是用户问题"}
	}
	return out, nil
}

func messagesBytes(messages []chatMessage) int {
	total := 0
	for _, item := range messages {
		total += len([]byte(item.Role)) + len([]byte(item.Content))
	}
	return total
}

func collectEvidence(sections []string, maxItems int, opts Options) evidenceBundle {
	bundle := evidenceBundle{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Sections:    make([]evidenceSection, 0, len(sections)),
	}
	for _, section := range sections {
		bundle.Sections = append(bundle.Sections, collectSection(section, maxItems, opts))
	}
	return bundle
}

func collectSection(section string, maxItems int, opts Options) evidenceSection {
	switch section {
	case sectionProcesses:
		return collectProcesses(maxItems, opts)
	case sectionFindings:
		return collectFindings(maxItems, opts)
	case sectionBehavior:
		return collectBehavior(maxItems, opts)
	case sectionMemory:
		return collectMemory(maxItems)
	case sectionHost:
		return collectHost(maxItems, opts)
	case sectionFileTrace:
		return collectFileTrace(maxItems)
	case sectionHistory:
		return collectHistory(maxItems)
	case sectionSecurity:
		return collectSecurity(maxItems)
	case sectionLogHealth:
		return collectLogHealth(maxItems)
	default:
		return evidenceSection{Key: section, Label: section, CollectionErrors: []string{"未知模块"}, Items: []any{}}
	}
}

func collectProcesses(maxItems int, opts Options) evidenceSection {
	items, err := process.Collect(process.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return sectionError(sectionProcesses, "进程信息", err)
	}
	connections, connErr := process.CollectConnections()
	connectionsByPID := buildConnectionsByPID(connections)
	sort.SliceStable(items, func(i, j int) bool {
		if processScore(items[i]) != processScore(items[j]) {
			return processScore(items[i]) > processScore(items[j])
		}
		return items[i].PID < items[j].PID
	})
	collectionErrors := []string(nil)
	if connErr != nil {
		collectionErrors = append(collectionErrors, "实时连接采集失败: "+connErr.Error())
	}
	limitedProcesses := limitProcesses(items, connectionsByPID, maxItems)
	return evidenceSection{
		Key:              sectionProcesses,
		Label:            "进程信息",
		Count:            len(items),
		Note:             fmt.Sprintf("按连接数、签名、路径和错误信息排序后截取；实时连接 %d 条，连接明细为当前快照，不代表历史通信", len(connections)),
		CollectionErrors: collectionErrors,
		Items: map[string]any{
			"processes":       limitedProcesses,
			"topConnections":  topConnections(limitedProcesses, maxItems),
			"connectionTotal": len(connections),
		},
	}
}

func collectFindings(maxItems int, opts Options) evidenceSection {
	processes, err := process.Collect(process.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return sectionError(sectionFindings, "关注项", err)
	}
	hostSnapshot, err := host.Collect(host.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return sectionError(sectionFindings, "关注项", err)
	}
	items := analysis.BuildFindings(processes, hostSnapshot)
	return evidenceSection{
		Key:   sectionFindings,
		Label: "关注项",
		Count: len(items),
		Items: limitSlice(items, maxItems),
	}
}

func collectBehavior(maxItems int, opts Options) evidenceSection {
	snapshot, err := threatanalysis.Collect(threatanalysis.Options{
		HashLimitBytes:   opts.HashLimitBytes,
		MaxRecords:       maxItems,
		IncludeMemory:    false,
		IncludeFileTrace: false,
	})
	if err != nil {
		return sectionError(sectionBehavior, "行为关联", err)
	}
	return evidenceSection{
		Key:              sectionBehavior,
		Label:            "行为关联",
		Count:            len(snapshot.Items),
		Note:             snapshot.SourceSummary,
		CollectionErrors: snapshot.CollectionErrors,
		Items:            snapshot.Items,
	}
}

func collectMemory(maxItems int) evidenceSection {
	snapshot, err := memoryscan.Collect(memoryscan.Options{
		MaxProcesses:         160,
		MaxRecords:           maxItems,
		MaxRegionsPerProcess: 32,
		IncludeThreads:       true,
	})
	if err != nil {
		return sectionError(sectionMemory, "内存异常", err)
	}
	return evidenceSection{
		Key:              sectionMemory,
		Label:            "内存异常",
		Count:            len(snapshot.Records),
		Note:             fmt.Sprintf("扫描进程 %d，跳过 %d", snapshot.ScannedProcesses, snapshot.SkippedProcesses),
		CollectionErrors: snapshot.CollectionErrors,
		Items:            snapshot.Records,
	}
}

func collectHost(maxItems int, opts Options) evidenceSection {
	snapshot, err := host.Collect(host.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return sectionError(sectionHost, "主机信息", err)
	}
	body := map[string]any{
		"counts": map[string]int{
			"services":       len(snapshot.Services),
			"scheduledTasks": len(snapshot.ScheduledTasks),
			"startupItems":   len(snapshot.StartupItems),
			"users":          len(snapshot.Users),
			"imageHijacks":   len(snapshot.ImageHijacks),
		},
		"suspiciousServices":       suspiciousServices(snapshot.Services, maxItems),
		"suspiciousScheduledTasks": suspiciousTasks(snapshot.ScheduledTasks, maxItems),
		"startupItems":             limitSlice(snapshot.StartupItems, maxItems),
		"notableUsers":             notableUsers(snapshot.Users),
		"imageHijacks":             limitSlice(snapshot.ImageHijacks, maxItems),
	}
	return evidenceSection{
		Key:              sectionHost,
		Label:            "主机信息",
		Count:            len(snapshot.Services) + len(snapshot.ScheduledTasks) + len(snapshot.StartupItems) + len(snapshot.Users) + len(snapshot.ImageHijacks),
		CollectionErrors: snapshot.CollectionErrors,
		Items:            body,
	}
}

func collectFileTrace(maxItems int) evidenceSection {
	snapshot, err := filetrace.Collect(filetrace.Options{
		MaxRecords: maxItems,
		Hours:      24 * 7,
	})
	if err != nil {
		return sectionError(sectionFileTrace, "文件痕迹", err)
	}
	sort.SliceStable(snapshot.Records, func(i, j int) bool {
		return suspicionRank(snapshot.Records[i].Suspicion) > suspicionRank(snapshot.Records[j].Suspicion)
	})
	return evidenceSection{
		Key:              sectionFileTrace,
		Label:            "文件痕迹",
		Count:            len(snapshot.Records),
		Note:             "最近 7 天，优先保留可疑文件",
		CollectionErrors: snapshot.CollectionErrors,
		Items:            limitSlice(snapshot.Records, maxItems),
	}
}

func collectHistory(maxItems int) evidenceSection {
	now := time.Now()
	snapshot, err := history.Collect(history.Options{
		MaxRecords: maxItems,
		StartTime:  now.Add(-7 * 24 * time.Hour),
		EndTime:    now,
	})
	if err != nil {
		return sectionError(sectionHistory, "历史通信", err)
	}
	return evidenceSection{
		Key:              sectionHistory,
		Label:            "历史通信",
		Count:            len(snapshot.Records),
		Note:             "最近 7 天；日志源未启用时可能只有 DNS 缓存或错误提示",
		CollectionErrors: snapshot.CollectionErrors,
		Items:            limitSlice(snapshot.Records, maxItems),
	}
}

func collectSecurity(maxItems int) evidenceSection {
	now := time.Now()
	snapshot, err := securitylog.Collect(securitylog.Options{
		MaxRecords: maxItems,
		StartTime:  now.Add(-7 * 24 * time.Hour),
		EndTime:    now,
	})
	if err != nil {
		return sectionError(sectionSecurity, "事件日志", err)
	}
	return evidenceSection{
		Key:              sectionSecurity,
		Label:            "事件日志",
		Count:            len(snapshot.Events),
		Note:             "最近 7 天",
		CollectionErrors: snapshot.CollectionErrors,
		Items:            limitSlice(snapshot.Events, maxItems),
	}
}

func collectLogHealth(maxItems int) evidenceSection {
	snapshot, err := loghealth.Collect()
	if err != nil {
		return sectionError(sectionLogHealth, "日志健康", err)
	}
	sources := snapshot.Sources
	if len(sources) > maxItems {
		sources = sources[:maxItems]
	}
	return evidenceSection{
		Key:   sectionLogHealth,
		Label: "日志健康",
		Count: len(snapshot.Sources),
		Note:  fmt.Sprintf("可用 %d，不可用 %d，权限问题 %d", snapshot.Summary.Available, snapshot.Summary.Unavailable, snapshot.Summary.PermissionIssue),
		Items: map[string]any{
			"summary": snapshot.Summary,
			"sources": sources,
		},
	}
}

func sectionError(key, label string, err error) evidenceSection {
	return evidenceSection{
		Key:              key,
		Label:            label,
		CollectionErrors: []string{err.Error()},
		Items:            []any{},
	}
}

func processScore(item process.Info) int {
	score := item.ConnectionCount
	switch item.Signature {
	case "签名异常":
		score += 160
	case "无签名请注意!!!":
		score += 120
	case "系统文件":
		score -= 20
	}
	if isWritablePath(item.Path) {
		score += 35
	}
	if item.HashError != "" || item.PathError != "" {
		score += 20
	}
	return score
}

func buildConnectionsByPID(items []process.ConnectionInfo) map[uint32][]process.ConnectionInfo {
	out := make(map[uint32][]process.ConnectionInfo)
	for _, item := range items {
		out[item.PID] = append(out[item.PID], item)
	}
	return out
}

func limitProcesses(items []process.Info, connectionsByPID map[uint32][]process.ConnectionInfo, maxItems int) []map[string]any {
	limit := maxItems
	if len(items) < limit {
		limit = len(items)
	}
	out := make([]map[string]any, 0, limit)
	for _, item := range items[:limit] {
		connections := connectionsByPID[item.PID]
		out = append(out, map[string]any{
			"pid":             item.PID,
			"name":            item.Name,
			"parentPid":       item.ParentPID,
			"parentName":      item.ParentName,
			"createdAt":       item.CreatedAt,
			"path":            item.Path,
			"md5":             item.MD5,
			"signature":       item.Signature,
			"signatureMsg":    trimText(item.SignatureMsg, 260),
			"connectionCount": item.ConnectionCount,
			"connections":     limitConnections(connections, 12),
			"hashError":       trimText(item.HashError, 260),
			"pathError":       trimText(item.PathError, 260),
		})
	}
	return out
}

func limitConnections(items []process.ConnectionInfo, maxItems int) []process.ConnectionInfo {
	if len(items) <= maxItems {
		return items
	}
	return items[:maxItems]
}

func topConnections(processes []map[string]any, maxItems int) []map[string]any {
	out := make([]map[string]any, 0)
	limit := maxItems
	if limit > 80 {
		limit = 80
	}
	for _, item := range processes {
		raw, ok := item["connections"].([]process.ConnectionInfo)
		if !ok || len(raw) == 0 {
			continue
		}
		for _, conn := range raw {
			out = append(out, map[string]any{
				"pid":      conn.PID,
				"process":  item["name"],
				"path":     item["path"],
				"protocol": conn.Protocol,
				"local":    conn.Local,
				"remote":   conn.Remote,
				"state":    conn.State,
			})
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func suspiciousServices(items []host.ServiceInfo, maxItems int) []host.ServiceInfo {
	out := make([]host.ServiceInfo, 0)
	for _, item := range items {
		if executableLooksSuspicious(item.Path, item.Signature, item.HashError) {
			out = append(out, item)
		}
	}
	return limitSlice(out, maxItems)
}

func suspiciousTasks(items []host.ScheduledTaskInfo, maxItems int) []host.ScheduledTaskInfo {
	out := make([]host.ScheduledTaskInfo, 0)
	for _, item := range items {
		if executableLooksSuspicious(item.Executable, item.Signature, item.HashError) || hasScriptOrLOLBIN(item.Command+" "+item.Arguments) {
			out = append(out, item)
		}
	}
	return limitSlice(out, maxItems)
}

func notableUsers(items []host.UserInfo) []host.UserInfo {
	out := make([]host.UserInfo, 0)
	for _, item := range items {
		if item.LocalAccount && (!item.Disabled || !item.PasswordRequired || item.Lockout) {
			out = append(out, item)
		}
	}
	return out
}

func executableLooksSuspicious(path, signature, hashError string) bool {
	return signature == "签名异常" || signature == "无签名请注意!!!" || hashError != "" || isWritablePath(path)
}

func isWritablePath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{`\users\`, `\appdata\`, `\temp\`, `\tmp\`, `\downloads\`, `\desktop\`, `\public\`, `\programdata\`, `\$recycle.bin\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hasScriptOrLOLBIN(command string) bool {
	lower := strings.ToLower(command)
	for _, marker := range []string{"powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", ".ps1", ".vbs", ".js", ".bat", ".cmd"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func suspicionRank(value string) int {
	switch value {
	case "高":
		return 3
	case "中":
		return 2
	case "低":
		return 1
	default:
		return 0
	}
}

func limitSlice[T any](items []T, maxItems int) []T {
	if len(items) <= maxItems {
		return items
	}
	return items[:maxItems]
}

func systemPrompt() string {
	return strings.Join([]string{
		"你是 Windows 应急响应分析助手，正在协助分析 WinTraceLens 采集到的主机数据。",
		"只能基于输入证据判断，不要编造不存在的进程、日志或网络连接。",
		"用中文输出，优先给出可执行的排查顺序，标明证据来源和不确定性。",
		"不要建议直接删除文件或杀进程；涉及处置时先建议备份、导出证据、确认业务影响。",
	}, "\n")
}

func userPrompt(question string, evidence evidenceBundle) (string, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		question = "请分析当前主机是否存在挖矿木马、蠕虫、远控木马、异常登录或持久化风险，并给出下一步排查建议。"
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		"分析目标：",
		question,
		"",
		"输出格式要求：",
		"1. 总体判断：高/中/低风险，并用一句话说明原因。",
		"2. 优先排查对象：列出 PID/进程/路径/MD5/账号/IP/事件ID 等关键线索。",
		"3. 证据关联：说明哪些模块互相印证，哪些只是单点弱信号。",
		"4. 下一步排查：给出按顺序执行的操作建议。",
		"5. 误报与缺口：说明可能误报来源，以及需要补充采集的日志或样本。",
		"",
		"WinTraceLens 采集数据 JSON：",
		string(data),
	}, "\n"), nil
}

func evidencePrompt(evidence evidenceBundle) (string, error) {
	data, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	return "以下是本轮补充的 WinTraceLens 采集数据 JSON，请在后续对话中结合这些证据分析，不要编造不存在的线索：\n" + string(data), nil
}

func callChatCompletion(ctx context.Context, endpoint, apiKey, model string, messages []chatMessage) (string, Usage, error) {
	body, err := json.Marshal(chatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	})
	if err != nil {
		return "", Usage{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", Usage{}, fmt.Errorf("AI 接口请求失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", Usage{}, fmt.Errorf("读取 AI 响应失败: %w", err)
	}

	var decoded chatResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", Usage{}, fmt.Errorf("AI 响应不是有效 JSON: %s", trimText(string(raw), 1200))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := decoded.Error.Message
		if msg == "" {
			msg = trimText(string(raw), 1200)
		}
		return "", Usage{}, fmt.Errorf("AI 接口返回 %d: %s", resp.StatusCode, msg)
	}
	if len(decoded.Choices) == 0 || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" {
		return "", Usage{}, fmt.Errorf("AI 接口未返回分析内容")
	}
	return decoded.Choices[0].Message.Content, decoded.Usage.usage(), nil
}

func sectionSummaries(sections []evidenceSection) []SectionSummary {
	out := make([]SectionSummary, 0, len(sections))
	for _, item := range sections {
		summary := SectionSummary{
			Key:   item.Key,
			Label: item.Label,
			Count: item.Count,
		}
		if len(item.CollectionErrors) > 0 {
			summary.Error = strings.Join(item.CollectionErrors, "；")
		}
		out = append(out, summary)
	}
	return out
}

func collectionErrors(sections []evidenceSection) []string {
	out := make([]string, 0)
	for _, section := range sections {
		for _, err := range section.CollectionErrors {
			err = strings.TrimSpace(err)
			if err != "" {
				out = append(out, section.Label+": "+err)
			}
		}
	}
	return out
}

func trimText(value string, max int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}
