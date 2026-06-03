package threatanalysis

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/selfidentity"
)

type Options struct {
	HashLimitBytes   int64
	MaxRecords       int
	IncludeMemory    bool
	IncludeFileTrace bool
}

type Snapshot struct {
	Items            []Item   `json:"items"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
	SourceSummary    string   `json:"sourceSummary"`
}

type Item struct {
	Level       string `json:"level"`
	Scenario    string `json:"scenario"`
	Score       int    `json:"score"`
	PID         uint32 `json:"pid"`
	Process     string `json:"process"`
	Path        string `json:"path"`
	MD5         string `json:"md5"`
	Signature   string `json:"signature"`
	Connections int    `json:"connections"`
	Summary     string `json:"summary"`
	Evidence    string `json:"evidence"`
	Related     string `json:"related"`
}

type evidenceBuilder struct {
	score        int
	signals      []string
	evidence     []string
	hasMemory    bool
	hasStrongMem bool
	hasNetwork   bool
	hasPersist   bool
	hasLOLBIN    bool
	hasFileTrace bool
	hasExpected  bool
	hasBadPath   bool
}

const (
	signatureUnsigned = "无签名请注意!!!"
	signatureBad      = "签名异常"
	signatureSystem   = "系统文件"
)

func Collect(opts Options) (Snapshot, error) {
	opts = normalizeOptions(opts)
	snapshot := Snapshot{
		Items:            make([]Item, 0),
		CollectionErrors: make([]string, 0),
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}

	processes, err := process.Collect(process.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return Snapshot{}, fmt.Errorf("process collection: %w", err)
	}

	hostSnapshot, err := host.Collect(host.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "主机持久化采集失败: "+err.Error())
	}

	var memorySnapshot memoryscan.Snapshot
	if opts.IncludeMemory {
		memorySnapshot = memoryscan.CollectForProcesses(processes, memoryscan.Options{
			MaxProcesses:         len(processes),
			MaxRecords:           1000,
			MaxRegionsPerProcess: 48,
			IncludeThreads:       true,
		})
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, memorySnapshot.CollectionErrors...)
	}

	var traceSnapshot filetrace.Snapshot
	if opts.IncludeFileTrace {
		traceSnapshot, err = filetrace.Collect(filetrace.Options{
			MaxRecords: 300,
			Hours:      24 * 7,
		})
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "文件痕迹采集失败: "+err.Error())
		} else {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, traceSnapshot.CollectionErrors...)
		}
	}

	persistence := buildPersistenceIndex(hostSnapshot)
	traces := buildTraceIndex(traceSnapshot)
	memoryByPID := buildMemoryIndex(memorySnapshot)
	runningPaths := make(map[string]struct{})

	for _, item := range processes {
		if item.Path != "" {
			runningPaths[normalizePath(item.Path)] = struct{}{}
		}
		if result, ok := analyzeProcess(item, persistence, traces, memoryByPID); ok {
			snapshot.Items = append(snapshot.Items, result)
		}
	}

	snapshot.Items = append(snapshot.Items, standalonePersistence(hostSnapshot, runningPaths)...)
	if opts.IncludeFileTrace {
		snapshot.Items = append(snapshot.Items, standaloneTraces(traceSnapshot, runningPaths)...)
	}

	sort.SliceStable(snapshot.Items, func(i, j int) bool {
		if rank(snapshot.Items[i].Level) != rank(snapshot.Items[j].Level) {
			return rank(snapshot.Items[i].Level) > rank(snapshot.Items[j].Level)
		}
		if snapshot.Items[i].Score != snapshot.Items[j].Score {
			return snapshot.Items[i].Score > snapshot.Items[j].Score
		}
		return snapshot.Items[i].Summary < snapshot.Items[j].Summary
	})
	if len(snapshot.Items) > opts.MaxRecords {
		snapshot.Items = snapshot.Items[:opts.MaxRecords]
	}

	snapshot.CollectionErrors = uniqueStrings(snapshot.CollectionErrors)
	snapshot.SourceSummary = fmt.Sprintf(
		"进程 %d，持久化 服务%d/任务%d/启动项%d/镜像劫持%d，内存异常 %d，文件痕迹 %d",
		len(processes),
		len(hostSnapshot.Services),
		len(hostSnapshot.ScheduledTasks),
		len(hostSnapshot.StartupItems),
		len(hostSnapshot.ImageHijacks),
		len(memorySnapshot.Records),
		len(traceSnapshot.Records),
	)
	return snapshot, nil
}

func normalizeOptions(opts Options) Options {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 500
	}
	if opts.MaxRecords > 2000 {
		opts.MaxRecords = 2000
	}
	return opts
}

func analyzeProcess(item process.Info, persistence map[string][]string, traces traceIndex, memoryByPID map[uint32][]memoryscan.Record) (Item, bool) {
	if selfidentity.IsSelfProcess(item.PID, item.Path) {
		return Item{}, false
	}

	builder := evidenceBuilder{}
	name := strings.ToLower(item.Name)
	pathKey := normalizePath(item.Path)
	profile := expectedProcessProfile(item)
	trusted := isTrustedSignature(item.Signature)
	scannerPowerShell := isScannerPowerShell(item)
	expectedMemory := profile != ""
	expectedNetwork := isExpectedNetworkClient(item.Name, item.Path)

	if records := memoryByPID[item.PID]; len(records) > 0 {
		high := 0
		thread := 0
		samples := make([]string, 0)
		for _, record := range records {
			if record.Level == "高" {
				high++
			}
			if record.Category == "线程入口" {
				thread++
			}
			if len(samples) < 3 {
				samples = append(samples, fmt.Sprintf("%s/%s/%s %s", record.Level, record.Category, record.Reason, record.Base))
			}
		}
		points := 4
		signal := "内存异常"
		if high > 0 || thread > 0 {
			points = 6
			builder.hasStrongMem = true
		}
		evidencePrefix := ""
		if expectedMemory {
			signal = "常见软件内存线索"
			evidencePrefix = profile + "，已降噪；"
			points = 1
			if thread > 0 {
				points = 2
			}
			builder.hasStrongMem = false
			builder.hasExpected = true
		}
		builder.add(points, signal, fmt.Sprintf("%s内存异常 %d 条，高危 %d 条，线程入口 %d 条，样例: %s", evidencePrefix, len(records), high, thread, strings.Join(samples, " | ")))
		builder.hasMemory = true
	}

	if item.ConnectionCount >= 30 {
		points := 5
		signal := "连接数异常"
		evidence := fmt.Sprintf("当前实时连接数 %d", item.ConnectionCount)
		if expectedNetwork && trusted {
			points = 1
			signal = "常见网络客户端连接数"
			evidence += "，浏览器/聊天/开发工具已降噪"
			builder.hasExpected = true
		}
		builder.add(points, signal, evidence)
		builder.hasNetwork = true
	} else if item.ConnectionCount >= 10 {
		points := 3
		signal := "连接数偏高"
		evidence := fmt.Sprintf("当前实时连接数 %d", item.ConnectionCount)
		if expectedNetwork && trusted {
			points = 1
			signal = "常见网络客户端连接数"
			evidence += "，已降噪"
			builder.hasExpected = true
		}
		builder.add(points, signal, evidence)
		builder.hasNetwork = true
	} else if item.ConnectionCount > 0 {
		builder.hasNetwork = true
	}

	switch item.Signature {
	case signatureBad:
		builder.add(5, "签名异常", item.SignatureMsg)
	case signatureUnsigned:
		if item.ConnectionCount > 0 || isWritablePath(item.Path) {
			points := 4
			if profile != "" {
				points = 2
				builder.hasExpected = true
			}
			builder.add(points, "无签名可执行文件", item.SignatureMsg)
		} else {
			builder.add(2, "无签名可执行文件", item.SignatureMsg)
		}
	}

	if item.Path == "" {
		builder.add(2, "进程路径不可读", item.PathError)
	} else if isWritablePath(item.Path) && item.Signature != signatureSystem {
		points := 3
		evidence := item.Path
		if profile != "" && (trusted || isExpectedUserWritableApp(item.Name, item.Path)) {
			points = 1
			evidence += "，常见用户态安装/开发工具路径已降噪"
			builder.hasExpected = true
		} else {
			builder.hasBadPath = true
		}
		builder.add(points, "用户可写路径运行", evidence)
	}

	if isLOLBIN(name) && !scannerPowerShell && (item.ConnectionCount > 0 || suspiciousParent(item.ParentName) || isWritablePath(item.Path)) {
		builder.add(3, "系统工具/脚本解释器可疑", fmt.Sprintf("父进程 %s(%d)，连接数 %d", item.ParentName, item.ParentPID, item.ConnectionCount))
		builder.hasLOLBIN = true
	}

	if suspiciousParentChild(item.ParentName, item.Name) && !scannerPowerShell {
		builder.add(3, "可疑父子进程关系", fmt.Sprintf("%s(%d) -> %s(%d)", item.ParentName, item.ParentPID, item.Name, item.PID))
	}

	if pathKey != "" {
		if related := persistence[pathKey]; len(related) > 0 {
			builder.add(3, "命中持久化项", strings.Join(related, "；"))
			builder.hasPersist = true
		}
		if related := traces.byPath[pathKey]; len(related) > 0 {
			for _, trace := range related {
				points := 1
				if trace.Suspicion != "" {
					points = 3
					builder.hasFileTrace = true
				}
				builder.add(points, "命中近期文件痕迹", fmt.Sprintf("%s/%s/%s", trace.Category, trace.Suspicion, trace.Reason))
			}
		}
	}

	if builder.score < 3 {
		return Item{}, false
	}

	return Item{
		Level:       levelForScore(builder),
		Scenario:    scenarioFor(builder),
		Score:       builder.score,
		PID:         item.PID,
		Process:     item.Name,
		Path:        item.Path,
		MD5:         item.MD5,
		Signature:   item.Signature,
		Connections: item.ConnectionCount,
		Summary:     fmt.Sprintf("%s (PID %d)", item.Name, item.PID),
		Evidence:    strings.Join(builder.evidence, "；"),
		Related:     strings.Join(builder.signals, " / "),
	}, true
}

func (b *evidenceBuilder) add(score int, signal, evidence string) {
	b.score += score
	if signal != "" && !containsString(b.signals, signal) {
		b.signals = append(b.signals, signal)
	}
	evidence = strings.TrimSpace(evidence)
	if evidence != "" && !containsString(b.evidence, evidence) {
		b.evidence = append(b.evidence, evidence)
	}
}

type traceIndex struct {
	byPath map[string][]filetrace.Record
}

func buildTraceIndex(snapshot filetrace.Snapshot) traceIndex {
	index := traceIndex{byPath: make(map[string][]filetrace.Record)}
	for _, item := range snapshot.Records {
		key := normalizePath(item.Path)
		if key == "" {
			continue
		}
		index.byPath[key] = append(index.byPath[key], item)
	}
	return index
}

func buildMemoryIndex(snapshot memoryscan.Snapshot) map[uint32][]memoryscan.Record {
	index := make(map[uint32][]memoryscan.Record)
	for _, item := range snapshot.Records {
		index[item.PID] = append(index[item.PID], item)
	}
	return index
}

func buildPersistenceIndex(snapshot host.Snapshot) map[string][]string {
	index := make(map[string][]string)
	add := func(path, label string) {
		key := normalizePath(path)
		if key == "" {
			return
		}
		index[key] = append(index[key], label)
	}
	for _, item := range snapshot.Services {
		add(item.Path, "服务:"+displayName(item.Name, item.DisplayName))
	}
	for _, item := range snapshot.ScheduledTasks {
		add(item.Executable, "计划任务:"+item.Name)
	}
	for _, item := range snapshot.StartupItems {
		add(item.Path, "启动项:"+item.Name)
	}
	for _, item := range snapshot.ImageHijacks {
		add(item.Path, "镜像劫持:"+item.Image)
	}
	return index
}

func standalonePersistence(snapshot host.Snapshot, runningPaths map[string]struct{}) []Item {
	items := make([]Item, 0)
	add := func(source, name, path, md5, signature, sigMsg, command, extra string) {
		key := normalizePath(path)
		if key == "" {
			return
		}
		if selfidentity.IsSelfExecutablePath(path) {
			return
		}
		if _, ok := runningPaths[key]; ok {
			return
		}
		score := 0
		reasons := make([]string, 0)
		if signature == signatureBad {
			score += 5
			reasons = append(reasons, "签名异常")
		}
		if signature == signatureUnsigned {
			score += 3
			reasons = append(reasons, "无签名")
		}
		if isWritablePath(path) {
			score += 3
			reasons = append(reasons, "用户可写路径")
		}
		if hasScriptOrLOLBIN(command) {
			score += 2
			reasons = append(reasons, "脚本或系统工具启动")
		}
		if score < 4 {
			return
		}
		items = append(items, Item{
			Level:     simpleLevelForScore(score),
			Scenario:  "可疑持久化项",
			Score:     score,
			Process:   source,
			Path:      path,
			MD5:       md5,
			Signature: signature,
			Summary:   source + ":" + name,
			Evidence:  strings.Join(reasons, "；") + "；" + strings.TrimSpace(sigMsg+" "+extra),
			Related:   "持久化未见当前运行",
		})
	}

	for _, item := range snapshot.Services {
		add("服务", displayName(item.Name, item.DisplayName), item.Path, item.MD5, item.Signature, item.SignatureMsg, item.Command, item.StartMode+"/"+item.Account)
	}
	for _, item := range snapshot.ScheduledTasks {
		add("计划任务", item.Name, item.Executable, item.MD5, item.Signature, item.SignatureMsg, item.Command+" "+item.Arguments, item.Path)
	}
	for _, item := range snapshot.StartupItems {
		add("启动项", item.Name, item.Path, item.MD5, item.Signature, item.SignatureMsg, item.Command, item.Location)
	}
	for _, item := range snapshot.ImageHijacks {
		add("镜像劫持", item.Image, item.Path, item.MD5, item.Signature, item.SignatureMsg, item.Debugger, item.RegistryPath)
	}
	return items
}

func standaloneTraces(snapshot filetrace.Snapshot, runningPaths map[string]struct{}) []Item {
	items := make([]Item, 0)
	for _, item := range snapshot.Records {
		if item.Suspicion == "" {
			continue
		}
		key := normalizePath(item.Path)
		if key != "" {
			if _, ok := runningPaths[key]; ok {
				continue
			}
		}
		score := 3
		if item.Suspicion == "高" {
			score = 5
		}
		items = append(items, Item{
			Level:    simpleLevelForScore(score),
			Scenario: "近期可疑文件",
			Score:    score,
			Process:  item.Category,
			Path:     item.Path,
			Summary:  item.Name,
			Evidence: strings.Trim(strings.Join([]string{item.Source, item.Suspicion, item.Reason, item.Modified}, "；"), "；"),
			Related:  "文件痕迹",
		})
		if len(items) >= 80 {
			break
		}
	}
	return items
}

func levelForScore(builder evidenceBuilder) string {
	if builder.hasExpected && builder.score < 5 {
		return "低"
	}
	if builder.hasStrongMem && builder.score >= 6 && !onlyExpectedSignals(builder) {
		return "高"
	}
	if builder.score >= 7 && !onlyExpectedSignals(builder) {
		return "高"
	}
	if builder.score >= 4 {
		return "中"
	}
	return "低"
}

func simpleLevelForScore(score int) string {
	if score >= 7 {
		return "高"
	}
	if score >= 4 {
		return "中"
	}
	return "低"
}

func scenarioFor(builder evidenceBuilder) string {
	if onlyExpectedSignals(builder) {
		return "常见软件行为观察"
	}
	if builder.hasMemory && builder.hasNetwork && builder.hasStrongMem {
		return "疑似内存型远控/注入"
	}
	if builder.hasMemory {
		return "内存异常"
	}
	if builder.hasPersist && builder.hasNetwork {
		return "持久化外联进程"
	}
	if builder.hasPersist {
		return "可疑持久化关联"
	}
	if builder.hasNetwork {
		return "异常网络行为"
	}
	if builder.hasLOLBIN {
		return "系统工具/脚本滥用"
	}
	if builder.hasFileTrace {
		return "近期可疑落地"
	}
	return "多信号关联"
}

func onlyExpectedSignals(builder evidenceBuilder) bool {
	if !builder.hasExpected {
		return false
	}
	if builder.hasPersist || builder.hasLOLBIN || builder.hasFileTrace || builder.hasStrongMem || builder.hasBadPath {
		return false
	}
	for _, signal := range builder.signals {
		switch signal {
		case "常见软件内存线索", "常见网络客户端连接数", "用户可写路径运行":
			continue
		case "无签名可执行文件":
			continue
		default:
			return false
		}
	}
	return true
}

func normalizePath(path string) string {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if path == "" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(path, "/", `\`))
}

func isWritablePath(path string) bool {
	lower := normalizePath(path)
	for _, marker := range []string{
		`\users\`,
		`\appdata\`,
		`\temp\`,
		`\tmp\`,
		`\downloads\`,
		`\desktop\`,
		`\public\`,
		`\programdata\`,
		`\recycler\`,
		`\$recycle.bin\`,
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func expectedProcessProfile(item process.Info) string {
	lowerName := strings.TrimSuffix(strings.ToLower(item.Name), ".exe")
	lowerPath := strings.ToLower(strings.ReplaceAll(item.Path, "/", `\`))
	parentName := strings.TrimSuffix(strings.ToLower(item.ParentName), ".exe")
	if isPowerShellName(lowerName) && selfidentity.IsScannerProcessName(parentName) {
		return "本工具采集 PowerShell 子进程"
	}
	if isPowerShellName(lowerName) {
		return "PowerShell/.NET 运行时动态代码"
	}
	if lowerName == "explorer" && isWindowsExplorerPath(lowerPath) {
		return "Windows Shell/扩展/Hook 动态内存"
	}
	if hasAny(lowerName, lowerPath, []string{"chrome", "msedge", "firefox", "browser"}) {
		return "浏览器/JIT 动态代码"
	}
	if hasAny(lowerName, lowerPath, []string{"wechat", "weixin", "wxwork", "qq", "tim", "teams", "slack", "discord"}) {
		return "聊天客户端动态模块"
	}
	if hasAny(lowerName, lowerPath, []string{"huorong", "hips", "火绒", "360", "defender", "security", "avp", "edr", "xdr"}) {
		return "安全软件 Hook/防护行为"
	}
	if hasAny(lowerName, lowerPath, []string{"code", "codex", "cursor", "node", "electron", "extension-host", "python", "go", "java"}) {
		return "开发工具或运行时动态代码"
	}
	return ""
}

func isExpectedNetworkClient(name, path string) bool {
	lowerName := strings.TrimSuffix(strings.ToLower(name), ".exe")
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return hasAny(lowerName, lowerPath, []string{
		"chrome", "msedge", "firefox", "browser",
		"wechat", "weixin", "wxwork", "qq", "tim",
		"teams", "slack", "discord",
		"code", "codex", "cursor", "node", "electron", "extension-host",
	})
}

func isExpectedUserWritableApp(name, path string) bool {
	lowerName := strings.TrimSuffix(strings.ToLower(name), ".exe")
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	if hasAny(lowerName, lowerPath, []string{"codex", "code", "cursor", "node", "electron", "extension-host"}) {
		return true
	}
	return strings.Contains(lowerPath, `\appdata\local\programs\`) || strings.Contains(lowerPath, `\.codex\`)
}

func isTrustedSignature(signature string) bool {
	return signature == signatureSystem || signature == "已签名"
}

func isScannerPowerShell(item process.Info) bool {
	name := strings.TrimSuffix(strings.ToLower(item.Name), ".exe")
	parent := strings.TrimSuffix(strings.ToLower(item.ParentName), ".exe")
	return isPowerShellName(name) && selfidentity.IsScannerProcessName(parent) && isTrustedSignature(item.Signature) && !isWritablePath(item.Path)
}

func isPowerShellName(name string) bool {
	return name == "powershell" || name == "pwsh"
}

func isWindowsExplorerPath(path string) bool {
	return strings.HasSuffix(path, `\windows\explorer.exe`)
}

func hasAny(name, path string, values []string) bool {
	for _, value := range values {
		if strings.Contains(name, value) || strings.Contains(path, value) {
			return true
		}
	}
	return false
}

func isLOLBIN(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	switch name {
	case "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "msiexec", "schtasks", "curl", "wget":
		return true
	default:
		return false
	}
}

func suspiciousParent(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	switch name {
	case "winword", "excel", "powerpnt", "outlook", "chrome", "msedge", "firefox", "iexplore", "explorer":
		return true
	default:
		return false
	}
}

func suspiciousParentChild(parent, child string) bool {
	parent = strings.TrimSuffix(strings.ToLower(parent), ".exe")
	child = strings.TrimSuffix(strings.ToLower(child), ".exe")
	if suspiciousParent(parent) && isLOLBIN(child) {
		return true
	}
	return false
}

func hasScriptOrLOLBIN(command string) bool {
	lower := strings.ToLower(command)
	for _, marker := range []string{".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func displayName(name, display string) string {
	if display == "" || display == name {
		return name
	}
	return name + "/" + display
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func rank(level string) int {
	switch level {
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

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func Row(item Item) []string {
	return []string{
		item.Level,
		item.Scenario,
		strconv.Itoa(item.Score),
		strconv.FormatUint(uint64(item.PID), 10),
		item.Process,
		item.MD5,
		item.Signature,
		strconv.Itoa(item.Connections),
		item.Summary,
		item.Path,
		item.Evidence,
		item.Related,
	}
}
