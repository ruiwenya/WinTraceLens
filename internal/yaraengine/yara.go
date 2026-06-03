package yaraengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

const (
	LicenseNotice = "YARA 功能只调用本机外部 yara.exe/yara64.exe，不随程序打包第三方规则库。导入或分发规则库前请先完成许可证审查。"
	RuleNotice    = "请仅粘贴自有规则、内部授权规则或已完成许可证审查的规则。"
)

type EngineInfo struct {
	Found         bool   `json:"found"`
	Path          string `json:"path"`
	Version       string `json:"version"`
	Error         string `json:"error"`
	LicenseNotice string `json:"licenseNotice"`
	RuleNotice    string `json:"ruleNotice"`
}

type ValidateRequest struct {
	EnginePath     string `json:"enginePath"`
	Rules          string `json:"rules"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type RulesRequest struct {
	EnginePath     string   `json:"enginePath"`
	RuleDir        string   `json:"ruleDir"`
	RulePaths      []string `json:"rulePaths"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

type ValidateResponse struct {
	Engine EngineInfo `json:"engine"`
	Valid  bool       `json:"valid"`
	Errors []string   `json:"errors"`
	Output string     `json:"output"`
}

type RulesResponse struct {
	Engine       EngineInfo       `json:"engine"`
	RuleDir      string           `json:"ruleDir"`
	Files        []RuleFileStatus `json:"files"`
	ValidFiles   int              `json:"validFiles"`
	InvalidFiles int              `json:"invalidFiles"`
	Errors       []string         `json:"errors"`
}

type RuleFileStatus struct {
	Path       string   `json:"path"`
	Name       string   `json:"name"`
	Valid      bool     `json:"valid"`
	Errors     []string `json:"errors"`
	Output     string   `json:"output"`
	DurationMs int64    `json:"durationMs"`
}

type ScanRequest struct {
	EnginePath           string   `json:"enginePath"`
	RuleDir              string   `json:"ruleDir"`
	RulePaths            []string `json:"rulePaths"`
	Rules                string   `json:"rules"`
	Paths                []string `json:"paths"`
	FolderPaths          []string `json:"folderPaths"`
	PIDs                 []uint32 `json:"pids"`
	IncludeProcessFiles  bool     `json:"includeProcessFiles"`
	IncludeProcessMemory bool     `json:"includeProcessMemory"`
	Recursive            bool     `json:"recursive"`
	MaxFiles             int      `json:"maxFiles"`
	TimeoutSeconds       int      `json:"timeoutSeconds"`
	Concurrency          int      `json:"concurrency"`
}

type ScanResponse struct {
	Engine     EngineInfo       `json:"engine"`
	Valid      bool             `json:"valid"`
	RuleFiles  []RuleFileStatus `json:"ruleFiles"`
	RuleErrors []string         `json:"ruleErrors"`
	Results    []ScanResult     `json:"results"`
	Errors     []string         `json:"errors"`
	StartedAt  string           `json:"startedAt"`
	FinishedAt string           `json:"finishedAt"`
}

type ScanResult struct {
	RuleFile         string   `json:"ruleFile"`
	TargetType       string   `json:"targetType"`
	Target           string   `json:"target"`
	Path             string   `json:"path"`
	PID              uint32   `json:"pid"`
	ProcessName      string   `json:"processName"`
	RelatedPIDs      []uint32 `json:"relatedPids"`
	RelatedProcesses []string `json:"relatedProcesses"`
	Rules            []string `json:"rules"`
	Matched          bool     `json:"matched"`
	Output           string   `json:"output"`
	Error            string   `json:"error"`
	TimedOut         bool     `json:"timedOut"`
	DurationMs       int64    `json:"durationMs"`
}

type scanTarget struct {
	index            int
	targetType       string
	target           string
	path             string
	pid              uint32
	processName      string
	relatedPIDs      []uint32
	relatedProcesses []string
}

type ruleFile struct {
	path    string
	name    string
	cleanup func()
}

type processIndex struct {
	byPID  map[uint32]process.Info
	byPath map[string][]process.Info
}

type commandResult struct {
	output   string
	err      error
	timedOut bool
	duration time.Duration
}

func ResolveEngine(enginePath string) EngineInfo {
	info := EngineInfo{
		LicenseNotice: LicenseNotice,
		RuleNotice:    RuleNotice,
	}

	for _, candidate := range engineCandidates(enginePath) {
		path, ok := resolveCandidate(candidate)
		if !ok {
			continue
		}
		info.Found = true
		info.Path = path
		info.Version = engineVersion(path)
		return info
	}

	info.Error = "未检测到 yara.exe 或 yara64.exe。请将 YARA 引擎放到程序目录、bin 目录，或加入 PATH。"
	return info
}

func Validate(ctx context.Context, req ValidateRequest) ValidateResponse {
	engine := ResolveEngine(req.EnginePath)
	resp := ValidateResponse{Engine: engine}
	if !engine.Found {
		resp.Errors = []string{engine.Error}
		return resp
	}

	rulePath, cleanupRules, err := writeTempRules(req.Rules)
	if err != nil {
		resp.Errors = []string{err.Error()}
		return resp
	}
	defer cleanupRules()

	targetPath, cleanupTarget, err := writeEmptyTarget()
	if err != nil {
		resp.Errors = []string{err.Error()}
		return resp
	}
	defer cleanupTarget()

	result := runYARA(ctx, engine.Path, []string{rulePath, targetPath}, req.TimeoutSeconds)
	resp.Output = strings.TrimSpace(result.output)
	if result.timedOut {
		resp.Errors = []string{fmt.Sprintf("规则编译校验超时（超过 %d 秒）", normalizeTimeout(req.TimeoutSeconds))}
		return resp
	}
	if result.err != nil && (hasYARAErrors(result.output) || len(parseMatchedRules(result.output)) == 0) {
		resp.Errors = outputLines(result.output, result.err)
		return resp
	}

	resp.Valid = true
	return resp
}

func ValidateRules(ctx context.Context, req RulesRequest) RulesResponse {
	engine := ResolveEngine(req.EnginePath)
	resp := RulesResponse{
		Engine:  engine,
		RuleDir: strings.TrimSpace(req.RuleDir),
	}
	if !engine.Found {
		resp.Errors = []string{engine.Error}
		return resp
	}

	rules, statuses, errors := prepareRuleFiles(ctx, engine.Path, req.RuleDir, req.RulePaths, "", req.TimeoutSeconds)
	resp.Files = statuses
	resp.Errors = append(resp.Errors, errors...)
	for _, rule := range rules {
		if rule.cleanup != nil {
			defer rule.cleanup()
		}
	}
	for _, status := range statuses {
		if status.Valid {
			resp.ValidFiles++
		} else {
			resp.InvalidFiles++
		}
	}
	return resp
}

func Scan(ctx context.Context, req ScanRequest, processes []process.Info) (resp ScanResponse) {
	started := time.Now()
	resp = ScanResponse{
		Engine:    ResolveEngine(req.EnginePath),
		StartedAt: started.Format("2006-01-02 15:04:05"),
	}
	defer func() {
		resp.FinishedAt = time.Now().Format("2006-01-02 15:04:05")
	}()

	if !resp.Engine.Found {
		resp.Errors = []string{resp.Engine.Error}
		return resp
	}

	rules, statuses, ruleErrors := prepareRuleFiles(ctx, resp.Engine.Path, req.RuleDir, req.RulePaths, req.Rules, req.TimeoutSeconds)
	resp.RuleFiles = statuses
	resp.RuleErrors = append(resp.RuleErrors, ruleErrors...)
	for _, rule := range rules {
		if rule.cleanup != nil {
			defer rule.cleanup()
		}
	}
	if len(rules) == 0 {
		resp.Valid = false
		if len(resp.RuleErrors) == 0 {
			resp.RuleErrors = []string{"没有可用规则。请选择包含 .yar/.yara/.rule/.rules 文件的规则目录，并确认至少一个规则检测通过。"}
		}
		return resp
	}
	resp.Valid = true

	targets, targetErrors := buildTargets(req, processes)
	resp.Errors = append(resp.Errors, targetErrors...)
	if len(targets) == 0 {
		resp.Errors = append(resp.Errors, "没有可扫描目标。请选择扫描文件夹、填写文件路径、勾选当前进程文件，或选择进程内存扫描目标。")
		return resp
	}

	scanRules, cleanupCombined, err := combinedRuleFile(rules)
	if err != nil {
		resp.RuleErrors = append(resp.RuleErrors, err.Error())
		resp.Valid = false
		return resp
	}
	if cleanupCombined != nil {
		defer cleanupCombined()
	}

	results := runTargets(ctx, resp.Engine.Path, scanRules, targets, normalizeTimeout(req.TimeoutSeconds), normalizeConcurrency(req.Concurrency))
	resp.Results = results
	return resp
}

func prepareRuleFiles(ctx context.Context, enginePath, ruleDir string, rulePaths []string, inlineRules string, timeoutSeconds int) ([]ruleFile, []RuleFileStatus, []string) {
	if strings.TrimSpace(inlineRules) != "" && strings.TrimSpace(ruleDir) == "" && len(rulePaths) == 0 {
		path, cleanup, err := writeTempRules(inlineRules)
		if err != nil {
			return nil, nil, []string{err.Error()}
		}
		status := validateRuleFile(ctx, enginePath, path, timeoutSeconds)
		status.Name = "临时规则"
		if !status.Valid {
			cleanup()
			return nil, []RuleFileStatus{status}, status.Errors
		}
		return []ruleFile{{path: path, name: status.Name, cleanup: cleanup}}, []RuleFileStatus{status}, nil
	}

	paths, collectErrors := collectRulePaths(ruleDir, rulePaths)
	statuses := make([]RuleFileStatus, 0, len(paths))
	rules := make([]ruleFile, 0, len(paths))
	for _, path := range paths {
		status := validateRuleFile(ctx, enginePath, path, timeoutSeconds)
		statuses = append(statuses, status)
		if status.Valid {
			rules = append(rules, ruleFile{path: path, name: status.Name})
		}
	}
	return rules, statuses, collectErrors
}

func validateRuleFile(ctx context.Context, enginePath, rulePath string, timeoutSeconds int) RuleFileStatus {
	status := RuleFileStatus{
		Path: rulePath,
		Name: filepath.Base(rulePath),
	}
	targetPath, cleanupTarget, err := writeEmptyTarget()
	if err != nil {
		status.Errors = []string{err.Error()}
		return status
	}
	defer cleanupTarget()

	result := runYARA(ctx, enginePath, []string{rulePath, targetPath}, timeoutSeconds)
	status.Output = strings.TrimSpace(result.output)
	status.DurationMs = result.duration.Milliseconds()
	if result.timedOut {
		status.Errors = []string{fmt.Sprintf("规则检测超时（超过 %d 秒）", normalizeTimeout(timeoutSeconds))}
		return status
	}
	if result.err != nil && (hasYARAErrors(result.output) || len(parseMatchedRules(result.output)) == 0) {
		status.Errors = outputLines(result.output, result.err)
		return status
	}
	status.Valid = true
	return status
}

func collectRulePaths(ruleDir string, rulePaths []string) ([]string, []string) {
	seen := map[string]struct{}{}
	var paths []string
	var errors []string

	add := func(path string) {
		path = cleanTargetPath(path)
		if path == "" {
			return
		}
		if !isRuleFile(path) {
			return
		}
		key := normalizedPath(path)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		paths = append(paths, path)
	}

	for _, path := range rulePaths {
		add(path)
	}

	ruleDir = cleanTargetPath(ruleDir)
	if ruleDir != "" {
		stat, err := os.Stat(ruleDir)
		if err != nil {
			errors = append(errors, "规则目录不可访问: "+err.Error())
		} else if !stat.IsDir() {
			errors = append(errors, "规则目录不是文件夹: "+ruleDir)
		} else {
			walkErr := filepath.WalkDir(ruleDir, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					errors = append(errors, "读取规则路径失败: "+path+" "+err.Error())
					return nil
				}
				if entry.IsDir() {
					return nil
				}
				add(path)
				return nil
			})
			if walkErr != nil {
				errors = append(errors, "遍历规则目录失败: "+walkErr.Error())
			}
		}
	}

	sort.Strings(paths)
	if len(paths) == 0 && len(errors) == 0 {
		errors = append(errors, "未找到规则文件。支持扩展名: .yar、.yara、.rule、.rules")
	}
	return paths, errors
}

func isRuleFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yar", ".yara", ".rule", ".rules":
		return true
	default:
		return false
	}
}

func buildTargets(req ScanRequest, processes []process.Info) ([]scanTarget, []string) {
	index := buildProcessIndex(processes)
	var targets []scanTarget
	var errors []string
	seenFiles := map[string]struct{}{}
	seenPIDs := map[uint32]struct{}{}
	maxFiles := normalizeMaxFiles(req.MaxFiles)

	addFile := func(path string) {
		path = cleanTargetPath(path)
		if path == "" {
			return
		}
		if len(seenFiles) >= maxFiles {
			return
		}
		key := normalizedPath(path)
		if _, ok := seenFiles[key]; ok {
			return
		}
		seenFiles[key] = struct{}{}

		related := index.byPath[key]
		target := scanTarget{
			index:      len(targets),
			targetType: "file",
			target:     path,
			path:       path,
		}
		target.relatedPIDs, target.relatedProcesses = relatedProcessLists(related)
		if len(related) == 1 {
			target.pid = related[0].PID
			target.processName = related[0].Name
		}
		targets = append(targets, target)
	}

	addFolder := func(folder string) {
		folder = cleanTargetPath(folder)
		if folder == "" {
			return
		}
		stat, err := os.Stat(folder)
		if err != nil {
			errors = append(errors, "扫描文件夹不可访问: "+err.Error())
			return
		}
		if !stat.IsDir() {
			errors = append(errors, "扫描目标不是文件夹: "+folder)
			return
		}
		before := len(seenFiles)
		walkErr := filepath.WalkDir(folder, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				errors = append(errors, "读取扫描路径失败: "+path+" "+err.Error())
				return nil
			}
			if entry.IsDir() {
				if !req.Recursive && path != folder {
					return filepath.SkipDir
				}
				return nil
			}
			addFile(path)
			if len(seenFiles) >= maxFiles {
				return filepath.SkipAll
			}
			return nil
		})
		if walkErr != nil {
			errors = append(errors, "遍历扫描文件夹失败: "+walkErr.Error())
		}
		if len(seenFiles) >= maxFiles && len(seenFiles) > before {
			errors = append(errors, fmt.Sprintf("扫描文件数量已达到上限 %d，后续文件已跳过。", maxFiles))
		}
	}

	addPID := func(pid uint32) {
		if pid == 0 {
			return
		}
		if _, ok := seenPIDs[pid]; ok {
			return
		}
		seenPIDs[pid] = struct{}{}

		info := index.byPID[pid]
		targets = append(targets, scanTarget{
			index:       len(targets),
			targetType:  "process-memory",
			target:      strconv.FormatUint(uint64(pid), 10),
			path:        info.Path,
			pid:         pid,
			processName: info.Name,
		})
	}

	for _, path := range req.Paths {
		addFile(path)
	}

	for _, folder := range req.FolderPaths {
		addFolder(folder)
	}

	if req.IncludeProcessFiles {
		for _, item := range processes {
			addFile(item.Path)
		}
	}

	if req.IncludeProcessMemory {
		if len(req.PIDs) > 0 {
			for _, pid := range req.PIDs {
				addPID(pid)
			}
		} else {
			for _, item := range processes {
				addPID(item.PID)
			}
		}
	}

	return targets, errors
}

func combinedRuleFile(rules []ruleFile) (ruleFile, func(), error) {
	if len(rules) == 0 {
		return ruleFile{}, nil, errors.New("没有可用规则")
	}
	if len(rules) == 1 {
		return rules[0], nil, nil
	}

	file, err := os.CreateTemp("", "WinTraceLens-yara-combined-*.yar")
	if err != nil {
		return ruleFile{}, nil, fmt.Errorf("创建规则集合文件失败: %w", err)
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	for _, rule := range rules {
		if _, err := fmt.Fprintf(file, "include \"%s\"\n", yaraIncludePath(rule.path)); err != nil {
			_ = file.Close()
			cleanup()
			return ruleFile{}, nil, fmt.Errorf("写入规则集合文件失败: %w", err)
		}
	}
	if err := file.Close(); err != nil {
		cleanup()
		return ruleFile{}, nil, fmt.Errorf("关闭规则集合文件失败: %w", err)
	}
	return ruleFile{path: file.Name(), name: fmt.Sprintf("规则集合(%d)", len(rules))}, cleanup, nil
}

func yaraIncludePath(path string) string {
	path = filepath.ToSlash(path)
	path = strings.ReplaceAll(path, `\`, `/`)
	path = strings.ReplaceAll(path, `"`, `\"`)
	return path
}

func runTargets(ctx context.Context, enginePath string, rule ruleFile, targets []scanTarget, timeoutSeconds, concurrency int) []ScanResult {
	total := len(targets)
	jobs := make(chan scanTarget)
	results := make(chan ScanResult, total)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				results <- scanOne(ctx, enginePath, rule, target, timeoutSeconds)
			}
		}()
	}

	go func() {
		cancelled := false
		for _, target := range targets {
			select {
			case <-ctx.Done():
				cancelled = true
			case jobs <- target:
			}
			if cancelled {
				break
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]ScanResult, 0, total)
	for result := range results {
		out = append(out, result)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})
	return out
}

func scanOne(ctx context.Context, enginePath string, rule ruleFile, target scanTarget, timeoutSeconds int) ScanResult {
	cmdResult := runYARA(ctx, enginePath, []string{rule.path, target.target}, timeoutSeconds)
	rules := parseMatchedRules(cmdResult.output)
	result := ScanResult{
		RuleFile:         rule.name,
		TargetType:       target.targetType,
		Target:           target.target,
		Path:             target.path,
		PID:              target.pid,
		ProcessName:      target.processName,
		RelatedPIDs:      target.relatedPIDs,
		RelatedProcesses: target.relatedProcesses,
		Rules:            rules,
		Matched:          len(rules) > 0,
		Output:           strings.TrimSpace(cmdResult.output),
		TimedOut:         cmdResult.timedOut,
		DurationMs:       cmdResult.duration.Milliseconds(),
	}
	if cmdResult.timedOut {
		result.Error = fmt.Sprintf("扫描超时（超过 %d 秒）", timeoutSeconds)
	} else if cmdResult.err != nil && (hasYARAErrors(cmdResult.output) || len(rules) == 0) {
		result.Error = strings.Join(outputLines(cmdResult.output, cmdResult.err), "；")
	}
	return result
}

func runYARA(parent context.Context, enginePath string, args []string, timeoutSeconds int) commandResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, time.Duration(normalizeTimeout(timeoutSeconds))*time.Second)
	defer cancel()

	cmd := winexec.CommandContext(ctx, enginePath, args...)
	output, err := cmd.CombinedOutput()
	result := commandResult{
		output:   string(output),
		err:      err,
		timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
		duration: time.Since(start),
	}
	if result.timedOut && result.err == nil {
		result.err = ctx.Err()
	}
	return result
}

func writeTempRules(rules string) (string, func(), error) {
	if strings.TrimSpace(rules) == "" {
		return "", func() {}, errors.New("规则内容不能为空")
	}

	file, err := os.CreateTemp("", "WinTraceLens-yara-rules-*.yar")
	if err != nil {
		return "", func() {}, fmt.Errorf("创建临时规则文件失败: %w", err)
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if _, err := file.WriteString(rules); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("写入临时规则文件失败: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("关闭临时规则文件失败: %w", err)
	}
	return file.Name(), cleanup, nil
}

func writeEmptyTarget() (string, func(), error) {
	file, err := os.CreateTemp("", "WinTraceLens-yara-empty-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("创建临时校验目标失败: %w", err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", func() {}, fmt.Errorf("关闭临时校验目标失败: %w", err)
	}
	return name, func() { _ = os.Remove(name) }, nil
}

func engineCandidates(enginePath string) []string {
	var candidates []string
	add := func(values ...string) {
		for _, value := range values {
			value = strings.TrimSpace(strings.Trim(value, `"`))
			if value != "" {
				candidates = append(candidates, value)
			}
		}
	}

	add(enginePath)
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		add(
			filepath.Join(dir, "yara64.exe"),
			filepath.Join(dir, "yara.exe"),
			filepath.Join(dir, "bin", "yara64.exe"),
			filepath.Join(dir, "bin", "yara.exe"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		add(
			filepath.Join(wd, "yara64.exe"),
			filepath.Join(wd, "yara.exe"),
			filepath.Join(wd, "bin", "yara64.exe"),
			filepath.Join(wd, "bin", "yara.exe"),
		)
	}
	add("yara64.exe", "yara.exe", "yara64", "yara")
	return candidates
}

func resolveCandidate(candidate string) (string, bool) {
	if strings.ContainsAny(candidate, `\/`) || filepath.IsAbs(candidate) {
		stat, err := os.Stat(candidate)
		if err == nil && !stat.IsDir() {
			abs, absErr := filepath.Abs(candidate)
			if absErr == nil {
				return abs, true
			}
			return candidate, true
		}
		return "", false
	}

	path, err := exec.LookPath(candidate)
	if err != nil {
		return "", false
	}
	stat, err := os.Stat(path)
	if err != nil || stat.IsDir() {
		return "", false
	}
	return path, true
}

func engineVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := winexec.CommandContext(ctx, path, "--version")
	output, err := cmd.CombinedOutput()
	value := strings.TrimSpace(string(output))
	if value != "" {
		return value
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func buildProcessIndex(processes []process.Info) processIndex {
	index := processIndex{
		byPID:  make(map[uint32]process.Info, len(processes)),
		byPath: make(map[string][]process.Info),
	}
	for _, item := range processes {
		index.byPID[item.PID] = item
		if item.Path == "" {
			continue
		}
		key := normalizedPath(item.Path)
		index.byPath[key] = append(index.byPath[key], item)
	}
	return index
}

func relatedProcessLists(items []process.Info) ([]uint32, []string) {
	if len(items) == 0 {
		return nil, nil
	}
	pids := make([]uint32, 0, len(items))
	names := make([]string, 0, len(items))
	seenNames := map[string]struct{}{}
	for _, item := range items {
		pids = append(pids, item.PID)
		if item.Name != "" {
			key := strings.ToLower(item.Name)
			if _, ok := seenNames[key]; !ok {
				seenNames[key] = struct{}{}
				names = append(names, item.Name)
			}
		}
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	sort.Strings(names)
	return pids, names
}

func cleanTargetPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"`)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func normalizedPath(path string) string {
	return strings.ToLower(filepath.Clean(strings.TrimSpace(path)))
}

func parseMatchedRules(output string) []string {
	lines := strings.FieldsFunc(output, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	seen := map[string]struct{}{}
	var rules []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isYARADiagnosticLine(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		rule := fields[0]
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)
	}
	return rules
}

func isYARADiagnosticLine(line string) bool {
	return isYARAWarningLine(line) || isYARAErrorLine(line)
}

func isYARAWarningLine(line string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	first := strings.TrimSuffix(fields[0], ":")
	return first == "warning" || strings.HasPrefix(line, "warning:")
}

func isYARAErrorLine(line string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	first := strings.TrimSuffix(fields[0], ":")
	return first == "error" ||
		first == "fatal" ||
		strings.HasPrefix(line, "error:") ||
		strings.Contains(line, " error:") ||
		strings.Contains(line, "syntax error")
}

func hasYARAErrors(output string) bool {
	for _, line := range strings.FieldsFunc(output, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		if isYARAErrorLine(line) {
			return true
		}
	}
	return false
}

func outputLines(output string, fallback error) []string {
	lines := strings.FieldsFunc(output, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 && fallback != nil {
		out = append(out, fallback.Error())
	}
	return out
}

func normalizeTimeout(value int) int {
	if value <= 0 {
		return 15
	}
	if value > 300 {
		return 300
	}
	return value
}

func normalizeConcurrency(value int) int {
	if value <= 0 {
		return 2
	}
	if value > 6 {
		return 6
	}
	return value
}

func normalizeMaxFiles(value int) int {
	if value <= 0 {
		return 5000
	}
	if value > 50000 {
		return 50000
	}
	return value
}
