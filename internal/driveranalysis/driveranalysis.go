package driveranalysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	amcachedata "github.com/ruiwenya/WinTraceLens/internal/amcache"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

type Options struct {
	HashLimitBytes int64
	MaxRecords     int
	AmcachePath    string
}

type Snapshot struct {
	Items            []Item        `json:"items"`
	Checks           []SourceCheck `json:"checks"`
	CollectionErrors []string      `json:"collectionErrors"`
	GeneratedAt      string        `json:"generatedAt"`
	SourceSummary    string        `json:"sourceSummary"`
	Boundary         string        `json:"boundary"`
	SourceCounts     SourceCounts  `json:"sourceCounts"`
}

type SourceCounts struct {
	KernelModules   int `json:"kernelModules"`
	RegistryDrivers int `json:"registryDrivers"`
	DiskDrivers     int `json:"diskDrivers"`
	AmcacheDrivers  int `json:"amcacheDrivers"`
	LoadEvents      int `json:"loadEvents"`
}

type SourceCheck struct {
	ID             string   `json:"id"`
	Level          string   `json:"level"`
	Status         string   `json:"status"`
	Title          string   `json:"title"`
	Count          int      `json:"count"`
	Detail         string   `json:"detail"`
	Samples        []string `json:"samples"`
	Recommendation string   `json:"recommendation"`
}

type Item struct {
	Level        string `json:"level"`
	Score        int    `json:"score"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	MD5          string `json:"md5"`
	HashError    string `json:"hashError"`
	BaseAddress  string `json:"baseAddress"`
	SizeKB       uint32 `json:"sizeKb"`
	Path         string `json:"path"`
	ServiceName  string `json:"serviceName"`
	ServiceStart string `json:"serviceStart"`
	ServiceType  string `json:"serviceType"`
	ServiceImage string `json:"serviceImage"`
	RegistryPath string `json:"registryPath"`
	EventMatches string `json:"eventMatches"`
	DiskPath     string `json:"diskPath"`
	AmcachePath  string `json:"amcachePath"`
	AmcacheSHA1  string `json:"amcacheSha1"`
	AmcacheInfo  string `json:"amcacheInfo"`
	AmcacheTime  string `json:"amcacheTime"`
	SourceDiff   string `json:"sourceDiff"`
	Reason       string `json:"reason"`
	Evidence     string `json:"evidence"`
}

type diskEntry struct {
	Name string
	Path string
}

type serviceEntry struct {
	Name          string
	DisplayName   string
	ImagePath     string
	ExpandedImage string
	Type          uint64
	TypeText      string
	Start         uint64
	StartText     string
	ErrorControl  uint64
	Group         string
	RegistryPath  string
}

type eventEntry struct {
	Time        string
	Source      string
	EventID     string
	ServiceName string
	ImagePath   string
	Account     string
	Details     string
}

type analysisContext struct {
	services       []serviceEntry
	events         []eventEntry
	files          []diskEntry
	amcacheDrivers []amcachedata.DriverBinary
}

func Collect(opts Options) (Snapshot, error) {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 500
	}
	if opts.MaxRecords > 2000 {
		opts.MaxRecords = 2000
	}

	snapshot := Snapshot{
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
		CollectionErrors: make([]string, 0),
		Boundary:         "V2 当前采用用户态多源交叉验证。Amcache 只证明系统曾记录过驱动清单，不证明驱动已经加载，且 Hive 可被修改；停用驱动、卸载残留和驱动仓库文件也会产生差异。对 DKOM 隐藏目标不能据此排除，仍需离线内存取证或可信内核采集器复核。",
	}

	modules, err := process.Modules(4, process.Options{HashLimitBytes: opts.HashLimitBytes})
	if err != nil {
		return Snapshot{}, err
	}
	services, err := collectDriverServices()
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "驱动服务注册表: "+err.Error())
	}
	events, eventErrors := collectDriverEvents(800)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, eventErrors...)
	files, err := collectDriverFiles()
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "驱动目录扫描: "+err.Error())
	}
	amcacheSnapshot, err := amcachedata.Parse(amcachedata.Options{Path: opts.AmcachePath, MaxDrivers: 5000, SkipApplicationFiles: true})
	amcacheDrivers := make([]amcachedata.DriverBinary, 0)
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Amcache 驱动清单: "+err.Error())
	} else {
		amcacheDrivers = amcacheSnapshot.Drivers
		for _, warning := range amcacheSnapshot.Warnings {
			if strings.Contains(warning, "失败") || strings.Contains(warning, "可能缺少") {
				snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Amcache 驱动清单: "+warning)
			}
		}
	}
	ctx := analysisContext{services: services, events: events, files: files, amcacheDrivers: amcacheDrivers}
	snapshot.SourceCounts = SourceCounts{
		KernelModules:   len(modules),
		RegistryDrivers: len(services),
		DiskDrivers:     len(files),
		AmcacheDrivers:  len(amcacheDrivers),
		LoadEvents:      len(events),
	}
	snapshot.Checks = buildSourceChecks(modules, ctx, snapshot.CollectionErrors)
	loadedServices := matchedLoadedServices(modules, ctx)
	loadedFiles := matchedLoadedFiles(modules, files)
	serviceFiles := matchedServiceFiles(services, files)

	for _, module := range modules {
		if item, ok := analyzeModule(module, ctx); ok {
			snapshot.Items = append(snapshot.Items, item)
		}
	}
	for _, service := range services {
		if _, ok := loadedServices[strings.ToLower(service.Name)]; ok {
			continue
		}
		if item, ok := analyzeServiceOnly(service, ctx, opts); ok {
			snapshot.Items = append(snapshot.Items, item)
		}
	}
	for _, file := range files {
		key := pathKey(file.Path)
		if _, ok := loadedFiles[key]; ok {
			continue
		}
		if _, ok := serviceFiles[key]; ok {
			continue
		}
		if item, ok := analyzeDiskOnly(file, ctx, opts); ok {
			snapshot.Items = append(snapshot.Items, item)
		}
	}
	for _, driver := range amcacheDrivers {
		if amcacheDriverHasCurrentMatch(driver, modules, services, files) {
			continue
		}
		if item, ok := analyzeAmcacheOnly(driver); ok {
			snapshot.Items = append(snapshot.Items, item)
		}
	}

	sort.SliceStable(snapshot.Items, func(i, j int) bool {
		if levelRank(snapshot.Items[i].Level) != levelRank(snapshot.Items[j].Level) {
			return levelRank(snapshot.Items[i].Level) > levelRank(snapshot.Items[j].Level)
		}
		if snapshot.Items[i].Score != snapshot.Items[j].Score {
			return snapshot.Items[i].Score > snapshot.Items[j].Score
		}
		return strings.ToLower(snapshot.Items[i].Name) < strings.ToLower(snapshot.Items[j].Name)
	})
	if len(snapshot.Items) > opts.MaxRecords {
		snapshot.Items = snapshot.Items[:opts.MaxRecords]
	}

	high, medium, low := 0, 0, 0
	for _, item := range snapshot.Items {
		switch item.Level {
		case "高":
			high++
		case "中":
			medium++
		case "低":
			low++
		}
	}
	snapshot.SourceSummary = fmt.Sprintf("内核模块 %d，驱动服务项 %d，驱动目录文件 %d，Amcache 驱动记录 %d，事件证据 %d，风险项 %d，高 %d，中 %d，低 %d", len(modules), len(services), len(files), len(amcacheDrivers), len(events), len(snapshot.Items), high, medium, low)
	return snapshot, nil
}

func analyzeModule(module process.ModuleInfo, ctx analysisContext) (Item, bool) {
	item := Item{
		Name:         module.Name,
		Kind:         module.Kind,
		Signature:    module.Signature,
		SignatureMsg: module.SignatureMsg,
		MD5:          module.MD5,
		HashError:    module.HashError,
		BaseAddress:  module.BaseAddress,
		SizeKB:       module.SizeKB,
		Path:         module.Path,
	}
	services := matchServicesForModule(module, ctx.services)
	events := matchEventsForModule(module, services, ctx.events)
	files := matchFilesForModule(module, ctx.files)
	amcacheDrivers := matchAmcacheDrivers(module.Path, module.Name, "", ctx.amcacheDrivers)
	if len(services) > 0 {
		applyService(&item, services[0])
		if len(amcacheDrivers) == 0 {
			amcacheDrivers = matchAmcacheDrivers(module.Path, module.Name, services[0].Name, ctx.amcacheDrivers)
		}
	}
	if len(files) > 0 {
		item.DiskPath = files[0].Path
	}
	if len(amcacheDrivers) > 0 {
		applyAmcache(&item, amcacheDrivers[0])
	}
	item.SourceDiff = moduleSourceDiff(len(services) > 0, len(files) > 0, len(amcacheDrivers) > 0)
	item.EventMatches = summarizeEvents(events)

	reasons := make([]string, 0)
	evidence := make([]string, 0)
	trusted := module.Signature == "已签名" || module.Signature == "系统文件" || module.Signature == "系统转储驱动"
	dumpDriver := module.Signature == "系统转储驱动" || module.Kind == "系统转储驱动" || isKnownDumpDriver(module.Name)
	score := 0

	if dumpDriver {
		score += 1
		reasons = append(reasons, "系统转储驱动没有独立落地文件")
		evidence = append(evidence, "dump_* 转储驱动通常来自 Windows 崩溃转储/存储转储路径")
	}

	switch module.Signature {
	case "签名异常":
		score += 8
		reasons = append(reasons, "签名异常")
	case "无签名请注意!!!":
		score += 7
		reasons = append(reasons, "内核驱动无可信签名")
	case "":
		if !dumpDriver {
			score += 3
			reasons = append(reasons, "签名状态未知")
		}
	}
	if strings.TrimSpace(module.SignatureMsg) != "" {
		evidence = append(evidence, "签名: "+module.SignatureMsg)
	}
	if len(services) > 0 {
		evidence = append(evidence, "Services注册表: "+summarizeService(services[0]))
	}
	if len(amcacheDrivers) > 0 {
		evidence = append(evidence, "Amcache 驱动清单: "+summarizeAmcacheDriver(amcacheDrivers[0]))
	}
	evidence = append(evidence, "多源对比: "+item.SourceDiff)

	hashErr := strings.TrimSpace(module.HashError)
	if hashErr != "" {
		evidence = append(evidence, "MD5: "+hashErr)
		if !dumpDriver && looksMissingFile(hashErr) {
			score += 7
			reasons = append(reasons, "驱动文件缺失或已删除")
		} else if !dumpDriver && !trusted {
			score += 2
			reasons = append(reasons, "驱动文件无法读取")
		}
	}

	nameSuspicious := suspiciousDriverName(module.Name)
	nameSuspiciousForRisk := nameSuspicious && !(trusted && isExpectedDriverPath(module.Path))
	if nameSuspiciousForRisk && !dumpDriver {
		score += 5
		reasons = append(reasons, "驱动名疑似随机生成")
	}

	if isWritablePath(module.Path) {
		score += writablePathScore(module.Path)
		reasons = append(reasons, writablePathReason(module.Path))
	} else if !dumpDriver && module.Path != "" && !isExpectedDriverPath(module.Path) && !trusted {
		score += 3
		reasons = append(reasons, "驱动路径不在常见系统驱动目录")
	}

	if module.Path == "" && !dumpDriver {
		score += 4
		reasons = append(reasons, "驱动路径为空")
	}
	if len(services) == 0 && !dumpDriver && strings.EqualFold(filepath.Ext(module.Name), ".sys") && (score > 0 || nameSuspiciousForRisk || !trusted) {
		score += 4
		reasons = append(reasons, "未找到对应 Services 驱动注册表项")
	}
	if len(events) > 0 {
		evidence = append(evidence, "事件关联: "+summarizeEvents(events))
		if hasInstallEvent(events) && !dumpDriver && (score > 0 || eventsLookSuspicious(events)) {
			score += 2
			reasons = append(reasons, "发现服务安装或驱动加载事件")
		}
	}

	if score == 0 {
		return Item{}, false
	}

	item.Score = score
	item.Level = scoreLevel(score)
	item.Reason = strings.Join(unique(reasons), "；")
	item.Evidence = strings.Join(unique(evidence), "；")
	return item, true
}

func analyzeServiceOnly(service serviceEntry, ctx analysisContext, opts Options) (Item, bool) {
	path := strings.TrimSpace(service.ExpandedImage)
	name := driverNameFromService(service)
	md5Value, hashErr := "", ""
	sig := process.SignatureResult{}
	cheapSuspicious := isWritablePath(path) || suspiciousDriverName(name) || strings.TrimSpace(path) == "" || !isExpectedDriverPath(path)
	if cheapSuspicious {
		md5Value, hashErr = process.HashFileMD5(path, opts.HashLimitBytes)
		if path != "" {
			sig = process.CheckSignature(path)
		}
	}

	item := Item{
		Name:         name,
		Kind:         "驱动服务注册表（未加载）",
		Path:         path,
		MD5:          md5Value,
		Signature:    sig.Status,
		SignatureMsg: sig.Message,
		HashError:    hashErr,
	}
	applyService(&item, service)
	files := matchFilesForService(service, ctx.files)
	amcacheDrivers := matchAmcacheDrivers(path, name, service.Name, ctx.amcacheDrivers)
	if len(files) > 0 {
		item.DiskPath = files[0].Path
	}
	if len(amcacheDrivers) > 0 {
		applyAmcache(&item, amcacheDrivers[0])
	}
	item.SourceDiff = serviceSourceDiff(len(files) > 0, len(amcacheDrivers) > 0)
	events := matchEventsForService(service, ctx.events)
	item.EventMatches = summarizeEvents(events)

	score := 0
	reasons := make([]string, 0)
	evidence := []string{"Services注册表: " + summarizeService(service), "多源对比: " + item.SourceDiff}
	if len(amcacheDrivers) > 0 {
		evidence = append(evidence, "Amcache 驱动清单: "+summarizeAmcacheDriver(amcacheDrivers[0]))
	}
	if hashErr != "" {
		evidence = append(evidence, "MD5: "+hashErr)
		if looksMissingFile(hashErr) {
			score += 7
			reasons = append(reasons, "驱动服务指向的文件缺失或已删除")
		}
	}
	switch sig.Status {
	case "签名异常":
		score += 8
		reasons = append(reasons, "驱动服务文件签名异常")
	case "无签名请注意!!!":
		score += 7
		reasons = append(reasons, "驱动服务文件无可信签名")
	}
	trusted := sig.Status == "已签名" || sig.Status == "系统文件" || sig.Status == "系统转储驱动"
	if suspiciousDriverName(name) && !(trusted && isExpectedDriverPath(path)) {
		score += 5
		reasons = append(reasons, "驱动服务名疑似随机生成")
	}
	if isWritablePath(path) {
		score += writablePathScore(path)
		reasons = append(reasons, writablePathReason(path))
	} else if path != "" && !isExpectedDriverPath(path) && sig.Status != "已签名" && sig.Status != "系统文件" {
		score += 3
		reasons = append(reasons, "驱动服务路径不在常见系统驱动目录")
	}
	if strings.TrimSpace(path) == "" {
		score += 3
		reasons = append(reasons, "驱动服务 ImagePath 为空")
	}
	if len(events) > 0 {
		evidence = append(evidence, "事件关联: "+summarizeEvents(events))
		if hasInstallEvent(events) && (score > 0 || eventsLookSuspicious(events)) {
			score += 2
			reasons = append(reasons, "发现服务安装或驱动加载事件")
		}
	}
	if score == 0 {
		return Item{}, false
	}
	item.Score = score
	item.Level = scoreLevel(score)
	item.Reason = strings.Join(unique(reasons), "；")
	item.Evidence = strings.Join(unique(evidence), "；")
	return item, true
}

func analyzeDiskOnly(file diskEntry, ctx analysisContext, opts Options) (Item, bool) {
	md5Value, hashErr := process.HashFileMD5(file.Path, opts.HashLimitBytes)
	sig := process.CheckSignature(file.Path)
	amcacheDrivers := matchAmcacheDrivers(file.Path, file.Name, "", ctx.amcacheDrivers)
	score := 0
	reasons := make([]string, 0, 4)
	sourceDiff := diskSourceDiff(len(amcacheDrivers) > 0)
	evidence := []string{"多源对比: " + sourceDiff}
	if len(amcacheDrivers) > 0 {
		evidence = append(evidence, "Amcache 驱动清单: "+summarizeAmcacheDriver(amcacheDrivers[0]))
	}

	switch sig.Status {
	case "签名异常":
		score += 8
		reasons = append(reasons, "孤立驱动文件签名异常")
	case "无签名请注意!!!":
		score += 6
		reasons = append(reasons, "孤立驱动文件无可信签名")
	}
	trusted := sig.Status == "已签名" || sig.Status == "系统文件" || sig.Status == "系统转储驱动"
	if suspiciousDriverName(file.Name) && !(trusted && isExpectedDriverPath(file.Path)) {
		score += 5
		reasons = append(reasons, "孤立驱动文件名疑似随机生成")
	}
	if isWritablePath(file.Path) {
		score += writablePathScore(file.Path)
		reasons = append(reasons, writablePathReason(file.Path))
	}
	if hashErr != "" {
		evidence = append(evidence, "MD5: "+hashErr)
	}
	if sig.Message != "" {
		evidence = append(evidence, "签名: "+sig.Message)
	}
	if score == 0 {
		return Item{}, false
	}
	item := Item{
		Level:        scoreLevel(score),
		Score:        score,
		Name:         file.Name,
		Kind:         "驱动目录孤立文件",
		Signature:    sig.Status,
		SignatureMsg: sig.Message,
		MD5:          md5Value,
		HashError:    hashErr,
		Path:         file.Path,
		DiskPath:     file.Path,
		SourceDiff:   sourceDiff,
		Reason:       strings.Join(unique(reasons), "；"),
		Evidence:     strings.Join(unique(evidence), "；"),
	}
	if len(amcacheDrivers) > 0 {
		applyAmcache(&item, amcacheDrivers[0])
	}
	return item, true
}

func analyzeAmcacheOnly(driver amcachedata.DriverBinary) (Item, bool) {
	path := normalizeDriverImagePath(driver.Path)
	name := strings.TrimSpace(driver.Name)
	if name == "" {
		name = filepath.Base(path)
	}
	score := 0
	reasons := make([]string, 0, 5)
	if isWritablePath(path) {
		score += 5
		reasons = append(reasons, writablePathReason(path))
	}
	if suspiciousDriverName(name) {
		score += 4
		reasons = append(reasons, "Amcache 驱动名疑似随机生成")
	}
	if strings.TrimSpace(path) == "" {
		score += 2
		reasons = append(reasons, "Amcache 驱动路径为空")
	} else {
		score += 2
		reasons = append(reasons, "Amcache 有历史记录但当前磁盘未匹配")
	}
	if strings.TrimSpace(driver.Service) == "" {
		score++
		reasons = append(reasons, "Amcache 条目未记录服务名")
	}
	if amcacheExplicitUnsigned(driver.Signed) {
		score += 3
		reasons = append(reasons, "Amcache 元数据显示驱动未签名")
	}
	if score < 4 {
		return Item{}, false
	}
	item := Item{
		Level:      scoreLevel(score),
		Score:      score,
		Name:       name,
		Kind:       "Amcache 历史驱动条目",
		Path:       path,
		SourceDiff: "内核枚举无 / Services注册表无 / 磁盘无 / Amcache有",
		Reason:     strings.Join(unique(reasons), "；"),
		Evidence:   "Amcache 历史清单: " + summarizeAmcacheDriver(driver) + "；该记录只能证明系统曾记录过此驱动，不证明驱动已经加载",
	}
	applyAmcache(&item, driver)
	return item, true
}

func Row(item Item) []string {
	return []string{
		item.Level,
		fmt.Sprintf("%d", item.Score),
		item.Name,
		item.Kind,
		item.Signature,
		item.SignatureMsg,
		item.MD5,
		item.HashError,
		item.BaseAddress,
		fmt.Sprintf("%d", item.SizeKB),
		item.Path,
		item.ServiceName,
		item.ServiceStart,
		item.ServiceType,
		item.ServiceImage,
		item.RegistryPath,
		item.EventMatches,
		item.DiskPath,
		item.AmcachePath,
		item.AmcacheSHA1,
		item.AmcacheInfo,
		item.AmcacheTime,
		item.SourceDiff,
		item.Reason,
		item.Evidence,
	}
}

func CheckRow(check SourceCheck) []string {
	return []string{
		check.Level,
		check.Status,
		check.Title,
		fmt.Sprintf("%d", check.Count),
		check.Detail,
		strings.Join(check.Samples, "；"),
		check.Recommendation,
	}
}

func buildSourceChecks(modules []process.ModuleInfo, ctx analysisContext, collectionErrors []string) []SourceCheck {
	loadedServices := matchedLoadedServices(modules, ctx)
	loadedFiles := matchedLoadedFiles(modules, ctx.files)
	serviceFiles := matchedServiceFiles(ctx.services, ctx.files)

	kernelWithoutService := make([]string, 0)
	kernelWithoutDisk := make([]string, 0)
	kernelWithoutAmcache := make([]string, 0)
	for _, module := range modules {
		if isKnownDumpDriver(module.Name) || module.Kind == "系统转储驱动" || module.Signature == "系统转储驱动" {
			continue
		}
		if !strings.EqualFold(filepath.Ext(module.Name), ".sys") && !strings.EqualFold(filepath.Ext(module.Path), ".sys") {
			continue
		}
		if len(matchServicesForModule(module, ctx.services)) == 0 {
			kernelWithoutService = append(kernelWithoutService, module.Name)
		}
		if moduleFileIsMissing(module, ctx.files) {
			kernelWithoutDisk = append(kernelWithoutDisk, module.Name)
		}
		if len(matchAmcacheDrivers(module.Path, module.Name, "", ctx.amcacheDrivers)) == 0 {
			kernelWithoutAmcache = append(kernelWithoutAmcache, module.Name)
		}
	}

	registryNotLoaded := make([]string, 0)
	registryMissingFile := make([]string, 0)
	for _, service := range ctx.services {
		if _, ok := loadedServices[strings.ToLower(service.Name)]; !ok {
			registryNotLoaded = append(registryNotLoaded, service.Name)
		}
		if serviceFileIsMissing(service) {
			registryMissingFile = append(registryMissingFile, service.Name)
		}
	}

	diskOnly := make([]string, 0)
	for _, file := range ctx.files {
		key := pathKey(file.Path)
		if _, ok := loadedFiles[key]; ok {
			continue
		}
		if _, ok := serviceFiles[key]; ok {
			continue
		}
		diskOnly = append(diskOnly, file.Name)
	}

	amcacheMissingDisk := make([]string, 0)
	amcacheSuspicious := make([]string, 0)
	for _, driver := range ctx.amcacheDrivers {
		name := driver.Name
		if name == "" {
			name = filepath.Base(normalizeDriverImagePath(driver.Path))
		}
		if len(matchDriverFiles(driver.Path, name, ctx.files)) > 0 {
			continue
		}
		amcacheMissingDisk = append(amcacheMissingDisk, name)
		if isWritablePath(driver.Path) || suspiciousDriverName(name) || amcacheExplicitUnsigned(driver.Signed) {
			amcacheSuspicious = append(amcacheSuspicious, name)
		}
	}

	eventSamples := make([]string, 0, len(ctx.events))
	for _, event := range ctx.events {
		name := strings.TrimSpace(event.ServiceName)
		if name == "" {
			name = strings.TrimSpace(filepath.Base(event.ImagePath))
		}
		if name == "" {
			name = "事件 " + event.EventID
		}
		eventSamples = append(eventSamples, event.Source+"/"+event.EventID+" "+name)
	}

	checks := []SourceCheck{
		newSourceCheck("kernel-registry", "内核枚举与 Services 对比", kernelWithoutService,
			"当前已加载驱动中未匹配到驱动服务项", "核对驱动名、ImagePath、服务安装事件；临时加载或映射失败也可能出现此差异。", "中", "需核查"),
		newSourceCheck("kernel-disk", "内核枚举与驱动目录对比", kernelWithoutDisk,
			"当前已加载驱动中未匹配到磁盘文件", "优先核查文件缺失、已删除、路径被隐藏或非标准加载位置，并结合签名和加载事件判断。", "高", "高关注"),
		newSourceCheck("registry-disk", "Services 与磁盘文件对比", registryMissingFile,
			"驱动服务 ImagePath 指向的文件当前不存在", "核对服务启动类型、注册表最后写入和 7045/4697/Sysmon 6；残留服务项也可能导致此差异。", "高", "高关注"),
		newSourceCheck("registry-kernel", "Services 与内核枚举对比", registryNotLoaded,
			"驱动服务当前未出现在内核枚举中", "停用、按需启动或启动失败的驱动通常不会加载；只有叠加异常路径、随机名或事件证据时才应升级。", "低", "基线差异"),
		newSourceCheck("disk-orphan", "驱动目录孤立文件", diskOnly,
			"驱动目录文件未匹配到当前内核模块或 Services 项", "Windows 驱动仓库和卸载残留会产生大量正常差异，重点筛选无签名、随机名和近期写入文件。", "低", "基线差异"),
		newSourceCheck("kernel-amcache", "内核枚举与 Amcache 对比", kernelWithoutAmcache,
			"当前已加载驱动未匹配到 Amcache 驱动清单", "Amcache 覆盖并不完整，此差异不能单独证明异常；结合 Services、磁盘、签名和加载事件复核。", "低", "基线差异"),
		newSourceCheck("amcache-disk", "Amcache 与当前磁盘对比", amcacheMissingDisk,
			"Amcache 曾记录但当前驱动目录未匹配到文件", "卸载或更新残留很常见；只有叠加随机名、用户可写路径、未签名或加载事件时才升级。", "低", "历史差异"),
		newSourceCheck("amcache-suspicious", "Amcache 高关注历史驱动", amcacheSuspicious,
			"Amcache 历史驱动同时命中随机名、用户可写路径或未签名元数据", "核对对应 Services、7045/4697/Sysmon 6、当前磁盘和离线内存；Amcache 条目本身不证明加载。", "中", "需核查"),
		newSourceCheck("load-events", "驱动加载与安装事件", eventSamples,
			"在当前事件窗口内发现 7045、4697 或 Sysmon 6 证据", "按时间、服务名和映像路径回溯来源，结合可疑连接发生时间建立时间线。", "信息", "事件证据"),
	}

	coverage := SourceCheck{
		ID:             "coverage",
		Level:          "信息",
		Status:         "采集完整",
		Title:          "V2 采集覆盖",
		Count:          len(collectionErrors),
		Detail:         "内核枚举、Services 注册表、驱动目录、Amcache 驱动清单和驱动加载事件均参与交叉验证。",
		Samples:        sampleStrings(collectionErrors, 5),
		Recommendation: "采集错误会形成盲区；请使用管理员权限，并确认相关事件日志存在且可读取。",
	}
	if len(collectionErrors) > 0 {
		coverage.Level = "中"
		coverage.Status = "采集不完整"
		coverage.Detail = fmt.Sprintf("有 %d 类证据采集失败，当前结论存在盲区。", len(collectionErrors))
	}
	checks = append(checks, coverage)
	return checks
}

func newSourceCheck(id, title string, values []string, detail, recommendation, alertLevel, alertStatus string) SourceCheck {
	check := SourceCheck{
		ID:             id,
		Level:          "信息",
		Status:         "未见差异",
		Title:          title,
		Count:          len(values),
		Detail:         detail,
		Samples:        sampleStrings(values, 5),
		Recommendation: recommendation,
	}
	if len(values) > 0 {
		check.Level = alertLevel
		check.Status = alertStatus
	}
	return check
}

func sampleStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) == 0 {
		return []string{}
	}
	values = unique(values)
	sort.SliceStable(values, func(i, j int) bool {
		return strings.ToLower(values[i]) < strings.ToLower(values[j])
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values
}

func serviceFileIsMissing(service serviceEntry) bool {
	path := strings.TrimSpace(service.ExpandedImage)
	if path == "" || !strings.EqualFold(filepath.Ext(path), ".sys") {
		return false
	}
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func moduleFileIsMissing(module process.ModuleInfo, files []diskEntry) bool {
	if len(matchFilesForModule(module, files)) > 0 {
		return false
	}
	if looksMissingFile(module.HashError) {
		return true
	}
	path := strings.TrimSpace(module.Path)
	if path == "" {
		return true
	}
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func matchedLoadedFiles(modules []process.ModuleInfo, files []diskEntry) map[string]struct{} {
	out := make(map[string]struct{})
	for _, module := range modules {
		for _, file := range matchFilesForModule(module, files) {
			out[pathKey(file.Path)] = struct{}{}
		}
	}
	return out
}

func matchedServiceFiles(services []serviceEntry, files []diskEntry) map[string]struct{} {
	out := make(map[string]struct{})
	for _, service := range services {
		for _, file := range matchFilesForService(service, files) {
			out[pathKey(file.Path)] = struct{}{}
		}
	}
	return out
}

func matchFilesForModule(module process.ModuleInfo, files []diskEntry) []diskEntry {
	return matchDriverFiles(module.Path, module.Name, files)
}

func matchFilesForService(service serviceEntry, files []diskEntry) []diskEntry {
	return matchDriverFiles(service.ExpandedImage, driverNameFromService(service), files)
}

func matchDriverFiles(path, name string, files []diskEntry) []diskEntry {
	path = pathKey(path)
	name = strings.ToLower(filepath.Base(name))
	out := make([]diskEntry, 0, 1)
	for _, file := range files {
		if path != "" && pathKey(file.Path) == path {
			return []diskEntry{file}
		}
	}
	if name == "" {
		return out
	}
	for _, file := range files {
		if strings.EqualFold(file.Name, name) {
			out = append(out, file)
		}
	}
	return out
}

func matchAmcacheDrivers(path, name, service string, drivers []amcachedata.DriverBinary) []amcachedata.DriverBinary {
	path = pathKey(path)
	name = strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	service = strings.ToLower(strings.TrimSpace(service))
	result := make([]amcachedata.DriverBinary, 0, 2)
	seen := make(map[string]struct{})
	add := func(driver amcachedata.DriverBinary) {
		key := amcacheDriverKey(driver)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result = append(result, driver)
	}
	for _, driver := range drivers {
		if path != "" && pathKey(driver.Path) == path {
			add(driver)
		}
	}
	for _, driver := range drivers {
		driverName := strings.ToLower(filepath.Base(strings.TrimSpace(driver.Name)))
		if driverName == "" {
			driverName = strings.ToLower(filepath.Base(normalizeDriverImagePath(driver.Path)))
		}
		if name != "" && driverName == name {
			add(driver)
			continue
		}
		if service != "" && strings.EqualFold(strings.TrimSpace(driver.Service), service) {
			add(driver)
		}
	}
	return result
}

func amcacheDriverHasCurrentMatch(driver amcachedata.DriverBinary, modules []process.ModuleInfo, services []serviceEntry, files []diskEntry) bool {
	single := []amcachedata.DriverBinary{driver}
	for _, module := range modules {
		if len(matchAmcacheDrivers(module.Path, module.Name, "", single)) > 0 {
			return true
		}
	}
	for _, service := range services {
		if len(matchAmcacheDrivers(service.ExpandedImage, driverNameFromService(service), service.Name, single)) > 0 {
			return true
		}
	}
	for _, file := range files {
		if len(matchAmcacheDrivers(file.Path, file.Name, "", single)) > 0 {
			return true
		}
	}
	return false
}

func amcacheDriverKey(driver amcachedata.DriverBinary) string {
	return strings.ToLower(strings.Join([]string{pathKey(driver.Path), driver.SHA1, driver.Name, driver.Service}, "|"))
}

func applyAmcache(item *Item, driver amcachedata.DriverBinary) {
	item.AmcachePath = normalizeDriverImagePath(driver.Path)
	item.AmcacheSHA1 = driver.SHA1
	item.AmcacheTime = driver.RecordTime
	item.AmcacheInfo = summarizeAmcacheDriver(driver)
}

func summarizeAmcacheDriver(driver amcachedata.DriverBinary) string {
	parts := make([]string, 0, 9)
	if driver.Name != "" {
		parts = append(parts, "Name="+driver.Name)
	}
	if driver.Service != "" {
		parts = append(parts, "Service="+driver.Service)
	}
	if driver.Path != "" {
		parts = append(parts, "Path="+normalizeDriverImagePath(driver.Path))
	}
	if driver.SHA1 != "" {
		parts = append(parts, "SHA1="+driver.SHA1)
	}
	if driver.Company != "" {
		parts = append(parts, "Company="+driver.Company)
	}
	if driver.DriverVersion != "" {
		parts = append(parts, "Version="+driver.DriverVersion)
	}
	if driver.Signed != "" {
		parts = append(parts, "Signed="+driver.Signed)
	}
	if driver.DriverTimestamp != "" {
		parts = append(parts, "DriverTimestamp="+driver.DriverTimestamp)
	}
	if driver.RecordTime != "" {
		parts = append(parts, "RecordTime="+driver.RecordTime)
	}
	return strings.Join(unique(parts), "，")
}

func amcacheExplicitUnsigned(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "unsigned", "未签名", "否":
		return true
	default:
		return false
	}
}

func moduleSourceDiff(hasService, hasFile, hasAmcache bool) string {
	return fmt.Sprintf("内核枚举有 / Services注册表%s / 磁盘%s / Amcache%s", evidencePresence(hasService), evidencePresence(hasFile), evidencePresence(hasAmcache))
}

func serviceSourceDiff(hasFile, hasAmcache bool) string {
	return fmt.Sprintf("内核枚举无 / Services注册表有 / 磁盘%s / Amcache%s", evidencePresence(hasFile), evidencePresence(hasAmcache))
}

func diskSourceDiff(hasAmcache bool) string {
	return fmt.Sprintf("内核枚举无 / Services注册表无 / 磁盘有 / Amcache%s", evidencePresence(hasAmcache))
}

func evidencePresence(present bool) string {
	if present {
		return "有"
	}
	return "无"
}

func matchedLoadedServices(modules []process.ModuleInfo, ctx analysisContext) map[string]struct{} {
	out := make(map[string]struct{})
	for _, module := range modules {
		for _, service := range matchServicesForModule(module, ctx.services) {
			out[strings.ToLower(service.Name)] = struct{}{}
		}
	}
	return out
}

func applyService(item *Item, service serviceEntry) {
	item.ServiceName = service.Name
	if service.DisplayName != "" && !strings.EqualFold(service.DisplayName, service.Name) {
		item.ServiceName = service.Name + " / " + service.DisplayName
	}
	item.ServiceStart = service.StartText
	item.ServiceType = service.TypeText
	item.ServiceImage = service.ExpandedImage
	if item.ServiceImage == "" {
		item.ServiceImage = service.ImagePath
	}
	item.RegistryPath = service.RegistryPath
}

func matchServicesForModule(module process.ModuleInfo, services []serviceEntry) []serviceEntry {
	matches := make([]serviceEntry, 0, 2)
	seen := make(map[string]struct{})
	add := func(service serviceEntry) {
		key := strings.ToLower(service.Name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		matches = append(matches, service)
	}

	modulePath := pathKey(module.Path)
	moduleName := strings.ToLower(filepath.Base(module.Name))
	moduleStem := strings.TrimSuffix(moduleName, ".sys")
	for _, service := range services {
		if modulePath != "" && pathKey(service.ExpandedImage) == modulePath {
			add(service)
		}
	}
	for _, service := range services {
		if moduleName != "" && strings.EqualFold(filepath.Base(service.ExpandedImage), moduleName) {
			add(service)
		}
	}
	for _, service := range services {
		if moduleStem != "" && strings.EqualFold(service.Name, moduleStem) {
			add(service)
		}
	}
	return matches
}

func matchEventsForModule(module process.ModuleInfo, services []serviceEntry, events []eventEntry) []eventEntry {
	serviceNames := make(map[string]struct{}, len(services))
	for _, service := range services {
		serviceNames[strings.ToLower(service.Name)] = struct{}{}
	}
	modulePath := pathKey(module.Path)
	moduleName := strings.ToLower(filepath.Base(module.Name))
	out := make([]eventEntry, 0, 3)
	for _, event := range events {
		eventService := strings.ToLower(strings.TrimSpace(event.ServiceName))
		eventPath := pathKey(event.ImagePath)
		eventName := strings.ToLower(filepath.Base(normalizeDriverImagePath(event.ImagePath)))
		_, serviceMatched := serviceNames[eventService]
		switch {
		case eventService != "" && serviceMatched:
			out = append(out, event)
		case eventPath != "" && modulePath != "" && eventPath == modulePath:
			out = append(out, event)
		case moduleName != "" && eventName == moduleName:
			out = append(out, event)
		case moduleName != "" && strings.Contains(strings.ToLower(event.Details), moduleName):
			out = append(out, event)
		}
	}
	return limitEvents(out, 6)
}

func matchEventsForService(service serviceEntry, events []eventEntry) []eventEntry {
	serviceName := strings.ToLower(service.Name)
	servicePath := pathKey(service.ExpandedImage)
	serviceBase := strings.ToLower(filepath.Base(service.ExpandedImage))
	out := make([]eventEntry, 0, 3)
	for _, event := range events {
		eventPath := pathKey(event.ImagePath)
		eventBase := strings.ToLower(filepath.Base(normalizeDriverImagePath(event.ImagePath)))
		switch {
		case serviceName != "" && strings.EqualFold(event.ServiceName, serviceName):
			out = append(out, event)
		case servicePath != "" && eventPath == servicePath:
			out = append(out, event)
		case serviceBase != "" && eventBase == serviceBase:
			out = append(out, event)
		}
	}
	return limitEvents(out, 6)
}

func limitEvents(events []eventEntry, max int) []eventEntry {
	if len(events) <= max {
		return events
	}
	return events[:max]
}

func summarizeService(service serviceEntry) string {
	parts := []string{service.RegistryPath}
	if service.TypeText != "" {
		parts = append(parts, "Type="+service.TypeText)
	}
	if service.StartText != "" {
		parts = append(parts, "Start="+service.StartText)
	}
	if service.ExpandedImage != "" {
		parts = append(parts, "ImagePath="+service.ExpandedImage)
	} else if service.ImagePath != "" {
		parts = append(parts, "ImagePath="+service.ImagePath)
	}
	if service.Group != "" {
		parts = append(parts, "Group="+service.Group)
	}
	return strings.Join(unique(parts), "，")
}

func summarizeEvents(events []eventEntry) string {
	if len(events) == 0 {
		return ""
	}
	parts := make([]string, 0, len(events))
	for _, event := range limitEvents(events, 4) {
		item := strings.TrimSpace(strings.Join(unique([]string{
			event.Time,
			event.Source + "/" + event.EventID,
			"Service=" + event.ServiceName,
			"Image=" + normalizeDriverImagePath(event.ImagePath),
			trimText(event.Details, 160),
		}), " "))
		if item != "" {
			parts = append(parts, item)
		}
	}
	if len(events) > 4 {
		parts = append(parts, fmt.Sprintf("另有 %d 条", len(events)-4))
	}
	return strings.Join(parts, "；")
}

func hasInstallEvent(events []eventEntry) bool {
	for _, event := range events {
		if event.EventID == "7045" || event.EventID == "4697" || (event.EventID == "6" && strings.Contains(strings.ToLower(event.Source), "sysmon")) {
			return true
		}
	}
	return false
}

func eventsLookSuspicious(events []eventEntry) bool {
	for _, event := range events {
		path := normalizeDriverImagePath(event.ImagePath)
		if isWritablePath(path) || suspiciousDriverName(filepath.Base(path)) {
			return true
		}
		lower := strings.ToLower(event.Details)
		if strings.Contains(lower, "unsigned") || strings.Contains(lower, "invalid") || strings.Contains(lower, "签名") && strings.Contains(lower, "false") {
			return true
		}
	}
	return false
}

func driverNameFromService(service serviceEntry) string {
	if service.ExpandedImage != "" {
		if base := filepath.Base(service.ExpandedImage); base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	if strings.HasSuffix(strings.ToLower(service.Name), ".sys") {
		return service.Name
	}
	return service.Name + ".sys"
}

func pathKey(path string) string {
	path = normalizeDriverImagePath(path)
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(path))
}

func normalizeDriverImagePath(value string) string {
	path := extractDriverImagePath(value)
	path = expandPercentEnv(path)
	path = strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	path = strings.Trim(path, `"'`)
	if path == "" {
		return ""
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = os.Getenv("windir")
	}
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	systemRoot = strings.TrimRight(systemRoot, `\/`)
	systemDrive := filepath.VolumeName(systemRoot)
	lower := strings.ToLower(path)
	switch {
	case lower == `\systemroot`:
		return filepath.Clean(systemRoot)
	case strings.HasPrefix(lower, `\systemroot\`):
		return filepath.Clean(filepath.Join(systemRoot, path[len(`\SystemRoot\`):]))
	case lower == `systemroot`:
		return filepath.Clean(systemRoot)
	case strings.HasPrefix(lower, `systemroot\`):
		return filepath.Clean(filepath.Join(systemRoot, path[len(`SystemRoot\`):]))
	case strings.HasPrefix(lower, `\??\`):
		return filepath.Clean(path[len(`\??\`):])
	case strings.HasPrefix(lower, `\\?\`):
		return filepath.Clean(path[len(`\\?\`):])
	case systemDrive != "" && strings.HasPrefix(lower, `\windows\`):
		return filepath.Clean(systemDrive + path)
	case strings.HasPrefix(lower, `\system32\`):
		return filepath.Clean(filepath.Join(systemRoot, path[1:]))
	case strings.HasPrefix(lower, `system32\`):
		return filepath.Clean(filepath.Join(systemRoot, path))
	default:
		return filepath.Clean(path)
	}
}

func extractDriverImagePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, `"`) {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			return value[1 : end+1]
		}
	}
	lower := strings.ToLower(value)
	if idx := strings.Index(lower, ".sys"); idx >= 0 {
		return strings.TrimSpace(value[:idx+4])
	}
	fields := strings.Fields(value)
	if len(fields) > 0 {
		return fields[0]
	}
	return value
}

func expandPercentEnv(value string) string {
	for {
		start := strings.Index(value, "%")
		if start < 0 {
			return value
		}
		end := strings.Index(value[start+1:], "%")
		if end < 0 {
			return value
		}
		end += start + 1
		name := value[start+1 : end]
		replacement := os.Getenv(name)
		if replacement == "" {
			return value
		}
		value = value[:start] + replacement + value[end+1:]
	}
}

func trimText(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len([]rune(value)) <= max {
		return value
	}
	runes := []rune(value)
	return string(runes[:max]) + "..."
}

func scoreLevel(score int) string {
	switch {
	case score >= 8:
		return "高"
	case score >= 4:
		return "中"
	default:
		return "低"
	}
}

func levelRank(level string) int {
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

func looksMissingFile(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "文件不存在") ||
		strings.Contains(lower, "路径不存在") ||
		strings.Contains(lower, "已被删除") ||
		strings.Contains(lower, "cannot find the file") ||
		strings.Contains(lower, "cannot find the path")
}

func suspiciousDriverName(name string) bool {
	base := strings.TrimSuffix(filepath.Base(strings.ToLower(name)), ".sys")
	if len(base) < 10 || strings.HasPrefix(base, "dump_") {
		return false
	}
	letters, digits, upper, lower := 0, 0, 0, 0
	transitions := 0
	prevClass := rune(0)
	for _, r := range strings.TrimSuffix(filepath.Base(name), ".sys") {
		class := rune(0)
		switch {
		case unicode.IsDigit(r):
			digits++
			class = 'd'
		case unicode.IsLetter(r):
			letters++
			class = 'l'
			if unicode.IsUpper(r) {
				upper++
			}
			if unicode.IsLower(r) {
				lower++
			}
		default:
			class = 'o'
		}
		if prevClass != 0 && class != prevClass {
			transitions++
		}
		prevClass = class
	}
	return letters >= 6 && digits >= 1 && upper >= 2 && lower >= 2 && transitions >= 2
}

func isWritablePath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	markers := []string{
		`\users\`,
		`\appdata\`,
		`\temp\`,
		`\programdata\`,
		`\recycler\`,
		`\$recycle.bin\`,
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func writablePathScore(path string) int {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	if strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\programdata\`) || strings.Contains(lower, `\appdata\`) {
		return 8
	}
	return 6
}

func writablePathReason(path string) string {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	switch {
	case strings.Contains(lower, `\temp\`):
		return "驱动位于 Temp 临时目录"
	case strings.Contains(lower, `\programdata\`):
		return "驱动位于 ProgramData 目录"
	case strings.Contains(lower, `\appdata\`):
		return "驱动位于 AppData 用户目录"
	case strings.Contains(lower, `\users\`):
		return "驱动位于用户目录"
	default:
		return "驱动位于用户可写目录"
	}
}

func isExpectedDriverPath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	expected := []string{
		`\windows\system32\drivers\`,
		`\windows\system32\driverstore\`,
		`\windows\system32\`,
		`\windows\winsxs\`,
	}
	for _, prefix := range expected {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func isKnownDumpDriver(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "dump_stornvme.sys", "dump_dumpstorport.sys", "dump_dumpfve.sys":
		return true
	default:
		return false
	}
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
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
	return out
}
