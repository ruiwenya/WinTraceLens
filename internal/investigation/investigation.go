package investigation

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/driveranalysis"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

type Options struct {
	MaxRecords     int
	StartTime      time.Time
	EndTime        time.Time
	Hours          int
	HashLimitBytes int64
}

type Snapshot struct {
	GeneratedAt      string          `json:"generatedAt"`
	Scenario         string          `json:"scenario"`
	FocusCount       int             `json:"focusCount"`
	Timeline         []TimelineEvent `json:"timeline"`
	Entities         []Entity        `json:"entities"`
	Coverage         []Coverage      `json:"coverage"`
	CollectionErrors []string        `json:"collectionErrors"`
}

type Sources struct {
	Processes       []process.Info
	ProcessError    error
	Host            host.Snapshot
	HostError       error
	FileTrace       filetrace.Snapshot
	FileTraceError  error
	History         history.Snapshot
	HistoryError    error
	Security        securitylog.Snapshot
	SecurityError   error
	Drivers         driveranalysis.Snapshot
	DriverError     error
	Connections     []process.ConnectionInfo
	ConnectionError error
}

type Coverage struct {
	Source  string `json:"source"`
	Status  string `json:"status"`
	Count   int    `json:"count"`
	Message string `json:"message"`
}

type TimelineEvent struct {
	ID             string `json:"id"`
	Time           string `json:"time"`
	Source         string `json:"source"`
	Category       string `json:"category"`
	Level          string `json:"level"`
	Action         string `json:"action"`
	Entity         string `json:"entity"`
	PID            string `json:"pid"`
	User           string `json:"user"`
	Remote         string `json:"remote"`
	Path           string `json:"path"`
	Hash           string `json:"hash"`
	Details        string `json:"details"`
	Group          string `json:"group"`
	ScenarioScore  int    `json:"scenarioScore"`
	ScenarioReason string `json:"scenarioReason"`
	Focus          bool   `json:"focus"`
	Current        bool   `json:"current"`
	sortTime       time.Time
}

type Entity struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Source         string `json:"source"`
	Level          string `json:"level"`
	Name           string `json:"name"`
	Value          string `json:"value"`
	PID            string `json:"pid"`
	User           string `json:"user"`
	Hash           string `json:"hash"`
	Path           string `json:"path"`
	Remote         string `json:"remote"`
	Details        string `json:"details"`
	Group          string `json:"group"`
	ScenarioScore  int    `json:"scenarioScore"`
	ScenarioReason string `json:"scenarioReason"`
	Focus          bool   `json:"focus"`
}

func Collect(opts Options) Snapshot {
	opts = normalizeOptions(opts)
	sourceLimit := sourceLimitFor(opts.MaxRecords)
	sources := Sources{}
	sources.Processes, sources.ProcessError = process.Collect(process.Options{HashLimitBytes: opts.HashLimitBytes})
	sources.Host, sources.HostError = host.Collect(host.Options{HashLimitBytes: opts.HashLimitBytes})
	sources.FileTrace, sources.FileTraceError = filetrace.Collect(filetrace.Options{MaxRecords: sourceLimit, Hours: opts.Hours, ArtifactsOnly: true})
	sources.History, sources.HistoryError = history.Collect(history.Options{MaxRecords: sourceLimit, StartTime: opts.StartTime, EndTime: opts.EndTime})
	sources.Security, sources.SecurityError = securitylog.Collect(securitylog.Options{MaxRecords: sourceLimit, StartTime: opts.StartTime, EndTime: opts.EndTime})
	sources.Security.Events = securitylog.FilterPowerShellNoise(sources.Security.Events)
	sources.Drivers, sources.DriverError = driveranalysis.Collect(driveranalysis.Options{HashLimitBytes: opts.HashLimitBytes, MaxRecords: min(sourceLimit, 300)})
	sources.Connections, sources.ConnectionError = process.CollectConnections()
	return Build(opts, sources)
}

func Build(opts Options, sources Sources) Snapshot {
	opts = normalizeOptions(opts)
	snapshot := Snapshot{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}
	processes := sources.Processes
	processErr := sources.ProcessError
	hostSnapshot := sources.Host
	hostErr := sources.HostError
	fileSnapshot := sources.FileTrace
	fileErr := sources.FileTraceError
	historySnapshot := sources.History
	historyErr := sources.HistoryError
	securitySnapshot := sources.Security
	securityErr := sources.SecurityError
	driverSnapshot := sources.Drivers
	driverErr := sources.DriverError
	connections := sources.Connections
	connectionErr := sources.ConnectionError

	if processErr != nil {
		snapshot.addFailure("进程信息", processErr)
	} else {
		snapshot.Coverage = append(snapshot.Coverage, Coverage{Source: "进程信息", Status: "完成", Count: len(processes)})
	}
	snapshot.addCoverage("主机信息", hostErr, hostItemCount(hostSnapshot), hostSnapshot.CollectionErrors)
	snapshot.addCoverage("文件与执行痕迹", fileErr, len(fileSnapshot.Records), fileSnapshot.CollectionErrors)
	snapshot.addCoverage("历史通信", historyErr, len(historySnapshot.Records), historySnapshot.CollectionErrors)
	snapshot.addCoverage("事件日志", securityErr, len(securitySnapshot.Events), securitySnapshot.CollectionErrors)
	snapshot.addCoverage("内核驱动风险", driverErr, len(driverSnapshot.Items), driverSnapshot.CollectionErrors)
	snapshot.addCoverage("实时网络连接", connectionErr, len(connections), nil)

	for _, item := range processes {
		pid := strconv.FormatUint(uint64(item.PID), 10)
		snapshot.addEntity(Entity{
			Kind: "进程", Source: "进程信息", Group: "进程信息", Name: item.Name, Value: item.Name, PID: pid,
			Hash: item.MD5, Path: item.Path, Details: join("父进程="+item.ParentName+" ("+strconv.FormatUint(uint64(item.ParentPID), 10)+")", item.Signature, item.EnumerationWarning),
		})
		snapshot.addTimeline(opts, TimelineEvent{
			Time: item.CreatedAt, Source: "进程信息", Group: "进程信息", Category: "进程启动", Action: "当前仍在运行",
			Entity: item.Name, PID: pid, Path: item.Path, Hash: item.MD5,
			Details: join("父进程="+item.ParentName, item.Signature, "连接数="+strconv.Itoa(item.ConnectionCount)),
		})
	}

	for _, item := range connections {
		pid := strconv.FormatUint(uint64(item.PID), 10)
		name := processName(processes, item.PID)
		snapshot.addEntity(Entity{
			Kind: "网络连接", Source: "实时网络连接", Group: "实时网络连接", Name: name, Value: item.Remote, PID: pid, Remote: item.Remote,
			Details: join(item.Protocol, item.Local+" -> "+item.Remote, item.State),
		})
		snapshot.addTimeline(opts, TimelineEvent{
			Time: snapshot.GeneratedAt, Source: "实时网络连接", Group: "实时网络连接", Category: "当前快照", Action: item.State,
			Entity: name, PID: pid, Remote: item.Remote, Details: item.Protocol + " " + item.Local + " -> " + item.Remote, Current: true,
		})
	}

	appendHostEntities(&snapshot, hostSnapshot)
	if processErr == nil && hostErr == nil {
		findings := analysis.BuildFindings(processes, hostSnapshot)
		snapshot.Coverage = append(snapshot.Coverage, Coverage{Source: "关注项", Status: "完成", Count: len(findings)})
		for _, item := range findings {
			snapshot.addEntity(Entity{
				Kind: "关注项", Source: item.Source, Group: "关注项", Level: item.Level, Name: item.Name, Value: item.Reason,
				Hash: item.MD5, Path: item.Path, Details: join(item.Reason, item.Command, item.Extra),
			})
		}
	}

	for _, item := range fileSnapshot.Records {
		eventTime := first(item.LastRun, item.Modified, item.Created, item.Accessed)
		snapshot.addEntity(Entity{
			Kind: item.Category, Source: item.Source, Group: "文件与执行痕迹", Level: item.Suspicion, Name: item.Name, Value: item.Name,
			Path: item.Path, Details: join(item.Reason, item.Details, "运行次数="+item.RunCount),
		})
		snapshot.addTimeline(opts, TimelineEvent{
			Time: eventTime, Source: item.Source, Group: "文件与执行痕迹", Category: item.Category, Level: item.Suspicion,
			Action: fileAction(item), Entity: item.Name, Path: item.Path, Details: join(item.Reason, item.Details, "运行次数="+item.RunCount),
		})
	}

	for _, item := range historySnapshot.Records {
		remote := first(item.Remote, item.Query)
		snapshot.addEntity(Entity{
			Kind: "通信记录", Source: item.Source, Group: "历史通信", Name: first(item.Process, remote), Value: remote,
			PID: item.PID, User: item.User, Remote: remote, Details: join(item.Proto, item.Local, item.Action, item.Details),
		})
		snapshot.addTimeline(opts, TimelineEvent{
			Time: item.Time, Source: item.Source, Group: "历史通信", Category: "历史通信", Action: item.Action,
			Entity: item.Process, PID: item.PID, User: item.User, Remote: remote, Details: join(item.Proto, item.Local, item.EventID, item.Details),
		})
	}

	for _, item := range securitylog.FilterPowerShellNoise(securitySnapshot.Events) {
		entity := first(item.Process, item.ServiceName, item.Account, item.Subject)
		remote := first(item.SourceIP, item.Workstation)
		details := join(item.EventID, item.Command, item.Message, item.Details, item.FailureReason, item.Status)
		snapshot.addEntity(Entity{
			Kind: "事件日志", Source: item.Source, Group: "事件日志", Level: item.Level, Name: entity, Value: item.Action,
			User: first(item.Account, item.Subject), Remote: remote, Path: item.Process, Details: details,
		})
		snapshot.addTimeline(opts, TimelineEvent{
			Time: item.Time, Source: item.Source, Group: "事件日志", Category: item.Category, Level: item.Level, Action: item.Action,
			Entity: entity, User: first(item.Account, item.Subject), Remote: remote, Path: item.Process, Details: details,
		})
	}

	for _, item := range driverSnapshot.Items {
		snapshot.addEntity(Entity{
			Kind: "内核驱动", Source: "驱动多源核查", Group: "内核驱动风险", Level: item.Level, Name: item.Name, Value: item.Reason,
			Hash: item.MD5, Path: first(item.Path, item.DiskPath, item.ServiceImage), Details: join(item.SourceDiff, item.ServiceName, item.EventMatches, item.Evidence),
		})
	}

	sort.SliceStable(snapshot.Timeline, func(i, j int) bool {
		return snapshot.Timeline[i].sortTime.After(snapshot.Timeline[j].sortTime)
	})
	if len(snapshot.Timeline) > opts.MaxRecords {
		snapshot.Timeline = snapshot.Timeline[:opts.MaxRecords]
	}
	entityLimit := opts.MaxRecords * 4
	if entityLimit < 2000 {
		entityLimit = 2000
	}
	if entityLimit > 12000 {
		entityLimit = 12000
	}
	if len(snapshot.Entities) > entityLimit {
		snapshot.Entities = snapshot.Entities[:entityLimit]
	}
	for i := range snapshot.Timeline {
		snapshot.Timeline[i].ID = fmt.Sprintf("timeline-%d", i+1)
	}
	for i := range snapshot.Entities {
		snapshot.Entities[i].ID = fmt.Sprintf("entity-%d", i+1)
	}
	return snapshot
}

func normalizeOptions(opts Options) Options {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 1500
	}
	if opts.MaxRecords > 5000 {
		opts.MaxRecords = 5000
	}
	if opts.Hours <= 0 {
		opts.Hours = 24 * 7
	}
	if opts.Hours > 24*30 {
		opts.Hours = 24 * 30
	}
	return opts
}

func sourceLimitFor(maxRecords int) int {
	limit := maxRecords / 3
	if limit < 300 {
		limit = 300
	}
	if limit > 1000 {
		limit = 1000
	}
	return limit
}

func TimelineRow(item TimelineEvent) []string {
	return []string{item.Time, item.Level, strconv.Itoa(item.ScenarioScore), item.ScenarioReason, item.Group, item.Source, item.Category, item.Action, item.Entity, item.PID, item.User, item.Remote, item.Path, item.Hash, item.Details}
}

func (s *Snapshot) addTimeline(opts Options, item TimelineEvent) {
	parsed := parseTime(item.Time)
	if parsed.IsZero() {
		return
	}
	if !opts.StartTime.IsZero() && parsed.Before(opts.StartTime) {
		return
	}
	if !opts.EndTime.IsZero() && parsed.After(opts.EndTime) && !item.Current {
		return
	}
	item.Time = parsed.Format("2006-01-02 15:04:05")
	item.sortTime = parsed
	s.Timeline = append(s.Timeline, item)
}

func (s *Snapshot) addEntity(item Entity) {
	s.Entities = append(s.Entities, item)
}

func (s *Snapshot) addFailure(source string, err error) {
	message := source + ": " + err.Error()
	s.CollectionErrors = append(s.CollectionErrors, message)
	s.Coverage = append(s.Coverage, Coverage{Source: source, Status: "失败", Message: err.Error()})
}

func (s *Snapshot) addCoverage(source string, err error, count int, warnings []string) {
	if err != nil {
		s.addFailure(source, err)
		return
	}
	coverage := Coverage{Source: source, Status: "完成", Count: count}
	if len(warnings) > 0 {
		coverage.Status = "部分"
		coverage.Message = strings.Join(limitStrings(warnings, 3), "；")
		for _, warning := range warnings {
			s.CollectionErrors = append(s.CollectionErrors, source+": "+warning)
		}
	}
	s.Coverage = append(s.Coverage, coverage)
}

func appendHostEntities(snapshot *Snapshot, data host.Snapshot) {
	for _, item := range data.Services {
		snapshot.addEntity(Entity{Kind: "服务", Source: "主机信息", Group: "主机信息", Name: first(item.DisplayName, item.Name), Value: item.Name, User: item.Account, Hash: item.MD5, Path: item.Path, Details: join(item.State, item.StartMode, item.Signature, item.Command)})
	}
	for _, item := range data.ScheduledTasks {
		snapshot.addEntity(Entity{Kind: "计划任务", Source: "主机信息", Group: "主机信息", Name: item.Name, Value: item.Path, User: item.Author, Hash: item.MD5, Path: item.Executable, Details: join(item.State, item.Status, item.Signature, item.Command, item.Arguments)})
	}
	for _, item := range data.StartupItems {
		snapshot.addEntity(Entity{Kind: "启动项", Source: item.Source, Group: "主机信息", Name: item.Name, Value: item.Location, Hash: item.MD5, Path: item.Path, Details: join(item.Signature, item.Command)})
	}
	for _, item := range data.Users {
		snapshot.addEntity(Entity{Kind: "本地用户", Source: "主机信息", Group: "主机信息", Name: item.Name, Value: item.SID, User: item.Name, Details: fmt.Sprintf("禁用=%t；锁定=%t；本地账户=%t", item.Disabled, item.Lockout, item.LocalAccount)})
	}
	for _, item := range data.ImageHijacks {
		snapshot.addEntity(Entity{Kind: "IFEO 劫持", Source: "主机信息", Group: "主机信息", Level: "高", Name: item.Image, Value: item.Debugger, Hash: item.MD5, Path: item.Path, Details: join(item.RegistryPath, item.Signature)})
	}
}

var connectionCountPattern = regexp.MustCompile(`连接数=(\d+)`)

func ApplyScenario(input Snapshot, scenario string) Snapshot {
	scenario = normalizeScenario(scenario)
	result := input
	result.Scenario = scenario
	result.Timeline = append([]TimelineEvent(nil), input.Timeline...)
	result.Entities = append([]Entity(nil), input.Entities...)
	result.FocusCount = 0
	for i := range result.Timeline {
		text := timelineScenarioText(result.Timeline[i])
		score, reason := scenarioScore(scenario, result.Timeline[i].Level, text)
		result.Timeline[i].ScenarioScore = score
		result.Timeline[i].ScenarioReason = reason
		result.Timeline[i].Focus = score >= focusThreshold(scenario)
	}
	for i := range result.Entities {
		text := entityScenarioText(result.Entities[i])
		score, reason := scenarioScore(scenario, result.Entities[i].Level, text)
		result.Entities[i].ScenarioScore = score
		result.Entities[i].ScenarioReason = reason
		result.Entities[i].Focus = score >= focusThreshold(scenario)
		if result.Entities[i].Focus {
			result.FocusCount++
		}
	}
	return result
}

func normalizeScenario(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "smb", "mining", "rat", "worm", "account", "powershell", "rootkit":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "general"
	}
}

func focusThreshold(scenario string) int {
	if scenario == "general" {
		return 4
	}
	return 5
}

func scenarioScore(scenario, level, content string) (int, string) {
	lower := strings.ToLower(content)
	score := 0
	reasons := make([]string, 0, 6)
	add := func(points int, reason string, markers ...string) {
		for _, marker := range markers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				score += points
				reasons = append(reasons, reason)
				return
			}
		}
	}
	if scenario == "general" {
		if level == "高" {
			score += 6
			reasons = append(reasons, "原模块高风险")
		} else if level == "中" {
			score += 3
			reasons = append(reasons, "原模块需核查")
		}
		add(3, "持久化或高价值异常", "关注项", "ifeo", "文件缺失", "签名异常", "无签名")
	} else {
		if level == "高" {
			score += 2
			reasons = append(reasons, "原模块高风险（辅助分）")
		} else if level == "中" {
			score++
			reasons = append(reasons, "原模块需核查（辅助分）")
		}
		add(1, "持久化或文件异常（辅助分）", "关注项", "ifeo", "文件缺失", "签名异常", "无签名")
	}

	switch scenario {
	case "smb":
		add(8, "命中 SMB/445 线索", ":445", " 445 ", "smb", "cifs", "lanman", "admin$", "ipc$")
		add(5, "横向执行工具或远程服务", "psexec", "wmiexec", "smbexec", "服务创建", "7045", "4697")
		add(3, "网络登录或 WFP 通信", "logontype 3", "网络登录", "5156", "5157", "wfp")
	case "mining":
		add(10, "命中矿池或矿工特征", "xmrig", "stratum", "mining", "miner", "coinhive", "cryptonight")
		add(6, "命中常见矿池端口", ":3333", ":4444", ":5555", ":7777", ":14444")
		add(3, "可写目录或脚本执行", `\temp\`, `\appdata\`, `\programdata\`, "powershell", "计划任务", "启动项")
		if match := connectionCountPattern.FindStringSubmatch(lower); len(match) == 2 {
			if count, _ := strconv.Atoi(match[1]); count >= 10 {
				score += 4
				reasons = append(reasons, "连接数偏高")
			}
		}
	case "rat":
		add(8, "远控或下载执行特征", "c2", "reverse shell", "远控", "downloadstring", "invoke-webrequest", "encodedcommand")
		add(5, "脚本解释器或代理执行", "powershell", "mshta", "rundll32", "regsvr32", "wscript", "cscript")
		add(4, "用户可写目录外联或持久化", `\temp\`, `\appdata\`, `\programdata\`, "计划任务", "启动项", "服务")
	case "worm":
		add(8, "命中横向传播端口", ":445", ":135", ":139", ":3389", "smb", "rpc")
		add(5, "远程服务或批量传播线索", "psexec", "服务创建", "7045", "计划任务", "admin$", "ipc$")
		add(4, "随机文件或临时目录", "随机", `\temp\`, "recycler", "$recycle.bin")
	case "account":
		add(8, "登录失败或账户创建", "4625", "登录失败", "4720", "用户创建")
		add(6, "RDP 或远程交互登录", "rdp", "logontype 10", "远程交互", "1149")
		add(4, "特权或组成员变更", "4672", "4728", "4732", "4756", "特权登录")
	case "powershell":
		add(10, "高风险 PowerShell 行为", "encodedcommand", "frombase64string", "invoke-expression", "downloadstring", "reflection.assembly")
		add(4, "PowerShell 脚本块包含需核查内容", "4104", "4103")
		add(2, "脚本或命令历史", ".ps1", "psreadline", "命令历史")
		add(5, "常见下载或绕过参数", "invoke-webrequest", "start-bitstransfer", "-windowstyle hidden", "executionpolicy bypass", "-nop")
	case "rootkit":
		add(10, "驱动视图差异或文件缺失", "三源", "枚举差异", "文件缺失", "内核未发现", "磁盘未发现")
		add(7, "驱动加载或服务安装", ".sys", "驱动", "7045", "4697", "sysmon 6", "driverload")
		add(5, "System/PID 4 内核线索", "pid 4", "system/pid 4", "内核模块")
	default:
		add(4, "通用高价值证据", "关注项", "内核驱动", "服务创建", "用户创建", "登录失败", "文件缺失")
	}
	return score, strings.Join(uniqueStrings(reasons), "；")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func timelineScenarioText(item TimelineEvent) string {
	return join(item.Group, item.Source, item.Category, item.Action, item.Entity, item.PID, item.User, item.Remote, item.Path, item.Hash, item.Details)
}

func entityScenarioText(item Entity) string {
	return join(item.Group, item.Kind, item.Source, item.Name, item.Value, item.PID, item.User, item.Hash, item.Path, item.Remote, item.Details)
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
		time.RFC3339Nano,
		"2006-01-02T15:04:05.9999999-07:00",
		"2006/01/02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func fileAction(item filetrace.Record) string {
	if item.LastRun != "" {
		return "运行痕迹"
	}
	if item.Modified != "" {
		return "文件修改/记录更新"
	}
	return "取证痕迹"
}

func hostItemCount(data host.Snapshot) int {
	return len(data.Services) + len(data.ScheduledTasks) + len(data.StartupItems) + len(data.Users) + len(data.ImageHijacks)
}

func processName(items []process.Info, pid uint32) string {
	for _, item := range items {
		if item.PID == pid {
			return item.Name
		}
	}
	if pid == 0 {
		return ""
	}
	return "PID " + strconv.FormatUint(uint64(pid), 10)
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func join(values ...string) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasSuffix(value, "=0") || strings.HasSuffix(value, "=()") {
			continue
		}
		out = append(out, value)
	}
	return strings.Join(out, "；")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
