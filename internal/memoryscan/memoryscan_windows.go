//go:build windows

package memoryscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/selfidentity"
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	threadQueryInformation  = 0x0040

	th32csSnapProcess  = 0x00000002
	th32csSnapThread   = 0x00000004
	th32csSnapModule   = 0x00000008
	th32csSnapModule32 = 0x00000010

	memCommit  = 0x1000
	memPrivate = 0x20000
	memMapped  = 0x40000
	memImage   = 0x1000000

	pageNoAccess          = 0x01
	pageExecute           = 0x10
	pageExecuteRead       = 0x20
	pageExecuteReadWrite  = 0x40
	pageExecuteWriteCopy  = 0x80
	pageGuard             = 0x100
	maxPath               = 260
	maxModuleName32       = 255
	maxAddressWalkRegions = 200000
	maxFingerprintBytes   = 8 * 1024 * 1024
	maxPreviewBytes       = 256 * 1024
)

var (
	modKernel32                = syscall.NewLazyDLL("kernel32.dll")
	modNTDLL                   = syscall.NewLazyDLL("ntdll.dll")
	procOpenProcess            = modKernel32.NewProc("OpenProcess")
	procOpenThread             = modKernel32.NewProc("OpenThread")
	procCloseHandle            = modKernel32.NewProc("CloseHandle")
	procVirtualQueryEx         = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory      = modKernel32.NewProc("ReadProcessMemory")
	procCreateToolhelpSnapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32FirstW         = modKernel32.NewProc("Module32FirstW")
	procModule32NextW          = modKernel32.NewProc("Module32NextW")
	procThread32First          = modKernel32.NewProc("Thread32First")
	procThread32Next           = modKernel32.NewProc("Thread32Next")
	procNTQueryInfoThread      = modNTDLL.NewProc("NtQueryInformationThread")
	modPSAPI                   = syscall.NewLazyDLL("psapi.dll")
	procGetMappedFileNameW     = modPSAPI.NewProc("GetMappedFileNameW")
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	Module       uintptr
	ModuleName   [maxModuleName32 + 1]uint16
	ExePath      [maxPath]uint16
}

type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type moduleRange struct {
	Base uintptr
	End  uintptr
	Name string
	Path string
}

type execRegion struct {
	Base              uintptr
	End               uintptr
	Size              uintptr
	Protect           uint32
	AllocationProtect uint32
	MemoryType        uint32
	BackingFile       string
	Fingerprint       regionFingerprint
}

type regionFingerprint struct {
	SHA256         string
	HashScope      string
	Entropy        float64
	HexPreview     string
	StringsPreview string
	HasMZ          bool
	HasPE          bool
}

var memoryIndicatorPattern = regexp.MustCompile(`(?i)(https?://|(?:\d{1,3}\.){3}\d{1,3}|powershell|cmd\.exe|rundll32|regsvr32|mshta|virtualalloc|virtualprotect|writeprocessmemory|createremotethread|loadlibrary|getprocaddress|winexec|shellexecute)`)

func Collect(opts Options) (Snapshot, error) {
	processes, err := process.Collect(process.Options{
		SkipHashes:     true,
		SkipSignatures: true,
	})
	if err != nil {
		return Snapshot{}, err
	}
	return CollectForProcesses(processes, opts), nil
}

func CollectForProcesses(processes []process.Info, opts Options) Snapshot {
	opts = normalizedOptions(opts)
	if len(processes) > opts.MaxProcesses {
		processes = processes[:opts.MaxProcesses]
	}

	snapshot := Snapshot{
		Records:          make([]Record, 0),
		CollectionErrors: make([]string, 0),
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}

	for _, item := range processes {
		if len(snapshot.Records) >= opts.MaxRecords {
			break
		}
		if selfidentity.IsSelfProcess(item.PID, item.Path) {
			snapshot.SkippedProcesses++
			continue
		}
		scanned, skipped, records, errors := inspectProcess(item, opts)
		if scanned {
			snapshot.ScannedProcesses++
		}
		if skipped {
			snapshot.SkippedProcesses++
		}
		snapshot.Records = appendRecords(snapshot.Records, records, opts.MaxRecords)
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, errors...)
	}

	sort.SliceStable(snapshot.Records, func(i, j int) bool {
		if rank(snapshot.Records[i].Level) != rank(snapshot.Records[j].Level) {
			return rank(snapshot.Records[i].Level) > rank(snapshot.Records[j].Level)
		}
		if snapshot.Records[i].PID != snapshot.Records[j].PID {
			return snapshot.Records[i].PID < snapshot.Records[j].PID
		}
		return snapshot.Records[i].Base < snapshot.Records[j].Base
	})
	snapshot.CollectionErrors = uniqueStrings(snapshot.CollectionErrors)
	return snapshot
}

func normalizedOptions(opts Options) Options {
	if opts.MaxProcesses <= 0 {
		opts.MaxProcesses = 300
	}
	if opts.MaxProcesses > 800 {
		opts.MaxProcesses = 800
	}
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 1000
	}
	if opts.MaxRecords > 5000 {
		opts.MaxRecords = 5000
	}
	if opts.MaxRegionsPerProcess <= 0 {
		opts.MaxRegionsPerProcess = 64
	}
	if opts.MaxRegionsPerProcess > 512 {
		opts.MaxRegionsPerProcess = 512
	}
	return opts
}

func inspectProcess(item process.Info, opts Options) (bool, bool, []Record, []string) {
	handle, _, err := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(item.PID))
	if handle == 0 {
		_ = err
		return false, true, nil, nil
	}
	defer procCloseHandle.Call(handle)

	records := make([]Record, 0)
	errors := make([]string, 0)
	regions := make([]execRegion, 0)
	address := uintptr(0)
	walked := 0

	for walked < maxAddressWalkRegions {
		var mbi memoryBasicInformation
		ret, _, _ := procVirtualQueryEx.Call(
			handle,
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}
		walked++

		if mbi.State == memCommit && isExecutableProtect(mbi.Protect) && !isGuardOrNoAccess(mbi.Protect) {
			region := execRegion{
				Base:              mbi.BaseAddress,
				End:               safeEnd(mbi.BaseAddress, mbi.RegionSize),
				Size:              mbi.RegionSize,
				Protect:           mbi.Protect,
				AllocationProtect: mbi.AllocationProtect,
				MemoryType:        mbi.Type,
			}
			if level, reason := suspiciousRegion(mbi); reason != "" {
				region.BackingFile = mappedFileName(handle, mbi.BaseAddress)
				region.Fingerprint = fingerprintRegion(handle, region)
				if countProcessRecords(records) < opts.MaxRegionsPerProcess {
					record := Record{
						Level:             level,
						Category:          "内存区域",
						PID:               item.PID,
						Process:           item.Name,
						Path:              item.Path,
						Reason:            reason,
						Base:              hexAddress(mbi.BaseAddress),
						RegionBase:        hexAddress(mbi.BaseAddress),
						Size:              uint64(mbi.RegionSize),
						Protect:           protectName(mbi.Protect),
						AllocationProtect: protectName(mbi.AllocationProtect),
						MemoryType:        memoryTypeName(mbi.Type),
						BackingFile:       region.BackingFile,
						SHA256:            region.Fingerprint.SHA256,
						HashScope:         region.Fingerprint.HashScope,
						Entropy:           region.Fingerprint.Entropy,
						HexPreview:        region.Fingerprint.HexPreview,
						StringsPreview:    region.Fingerprint.StringsPreview,
						HasMZ:             region.Fingerprint.HasMZ,
						HasPE:             region.Fingerprint.HasPE,
						Exportable:        true,
						Details:           fmt.Sprintf("AllocationProtect=%s", protectName(mbi.AllocationProtect)),
					}
					applyRegionSignals(region, &record)
					applyProcessContext(item, &record)
					records = append(records, record)
				}
			}
			regions = append(regions, region)
		}

		next := safeEnd(mbi.BaseAddress, mbi.RegionSize)
		if next == 0 || next <= address {
			break
		}
		address = next
	}

	if walked >= maxAddressWalkRegions {
		errors = append(errors, fmt.Sprintf("PID %d %s: 内存区域过多，已停止枚举", item.PID, item.Name))
	}
	if opts.IncludeThreads && len(records) < opts.MaxRegionsPerProcess {
		modules, err := processModules(item.PID)
		if err == nil && len(modules) > 0 {
			threadRecords, threadErrors := suspiciousThreads(item, modules, regions, opts.MaxRegionsPerProcess-len(records))
			promoteRegionRecords(records, threadRecords)
			records = append(records, threadRecords...)
			errors = append(errors, threadErrors...)
		}
	}
	records = compactExpectedMemoryRecords(records)

	return true, false, records, errors
}

func compactExpectedMemoryRecords(records []Record) []Record {
	if len(records) < 2 {
		return records
	}
	compacted := make([]Record, 0, len(records))
	seen := make(map[string]struct{})
	representatives := 0
	firstExpected := -1
	suppressed := 0
	for _, record := range records {
		if record.Context == "" || record.Level != "低" || record.Category == "线程入口" {
			compacted = append(compacted, record)
			continue
		}
		key := strings.Join([]string{record.Context, record.Category, record.Reason, record.Protect, record.MemoryType}, "\x00")
		if _, ok := seen[key]; ok || representatives >= 3 {
			suppressed++
			continue
		}
		seen[key] = struct{}{}
		representatives++
		compacted = append(compacted, record)
		if firstExpected < 0 {
			firstExpected = len(compacted) - 1
		}
	}
	if suppressed > 0 && firstExpected >= 0 {
		compacted[firstExpected].Details = appendDetail(compacted[firstExpected].Details, fmt.Sprintf("同进程同类低风险记录已合并，省略 %d 条", suppressed))
	}
	return compacted
}

func appendRecords(existing, incoming []Record, max int) []Record {
	if len(existing) >= max {
		return existing
	}
	remaining := max - len(existing)
	if len(incoming) > remaining {
		incoming = incoming[:remaining]
	}
	return append(existing, incoming...)
}

func countProcessRecords(records []Record) int {
	return len(records)
}

func suspiciousRegion(mbi memoryBasicInformation) (string, string) {
	if mbi.Type == memPrivate && mbi.Protect&pageExecuteReadWrite != 0 {
		return "高", "私有 RWX 可执行内存"
	}
	if mbi.Type == memPrivate && mbi.Protect&pageExecuteWriteCopy != 0 {
		return "高", "私有写拷贝可执行内存"
	}
	if mbi.Type == memPrivate && isExecutableProtect(mbi.Protect) {
		return "中", "私有可执行内存"
	}
	if mbi.Type == memMapped && isWritableExecutable(mbi.Protect) {
		return "中", "映射内存具有写入与执行权限"
	}
	if mbi.Type == memImage && isWritableExecutable(mbi.Protect) {
		return "低", "映像内存具有写入与执行权限"
	}
	return "", ""
}

func suspiciousThreads(item process.Info, modules []moduleRange, regions []execRegion, remaining int) ([]Record, []string) {
	if remaining <= 0 {
		return nil, nil
	}
	threads, err := processThreads(item.PID)
	if err != nil {
		_ = err
		return nil, nil
	}

	records := make([]Record, 0)
	errors := make([]string, 0)
	for _, threadID := range threads {
		if len(records) >= remaining {
			break
		}
		start, err := threadStartAddress(threadID)
		if err != nil || start == 0 {
			continue
		}
		module := moduleForAddress(modules, start)
		if module != nil {
			continue
		}
		region := regionForAddress(regions, start)
		level := "中"
		reason := "线程入口不在已加载模块范围"
		details := "StartAddress=" + hexAddress(start)
		if region != nil {
			details += fmt.Sprintf("; Region=%s/%s/%d", memoryTypeName(region.MemoryType), protectName(region.Protect), uint64(region.Size))
			if region.MemoryType == memPrivate {
				level = "高"
				reason = "线程入口位于私有可执行内存"
			} else if region.MemoryType == memMapped && region.BackingFile == "" {
				level = "高"
				reason = "线程入口位于无后备文件的映射可执行内存"
			}
		}
		record := Record{
			Level:      level,
			Category:   "线程入口",
			PID:        item.PID,
			Process:    item.Name,
			Path:       item.Path,
			Reason:     reason,
			Base:       hexAddress(start),
			ThreadID:   threadID,
			Details:    details,
			Exportable: region != nil,
		}
		if region != nil {
			record.RegionBase = hexAddress(region.Base)
			record.Size = uint64(region.Size)
			record.Protect = protectName(region.Protect)
			record.AllocationProtect = protectName(region.AllocationProtect)
			record.MemoryType = memoryTypeName(region.MemoryType)
			record.BackingFile = region.BackingFile
			record.SHA256 = region.Fingerprint.SHA256
			record.HashScope = region.Fingerprint.HashScope
			record.Entropy = region.Fingerprint.Entropy
			record.HexPreview = region.Fingerprint.HexPreview
			record.StringsPreview = region.Fingerprint.StringsPreview
			record.HasMZ = region.Fingerprint.HasMZ
			record.HasPE = region.Fingerprint.HasPE
			record.HardSignals = append(record.HardSignals, "异常线程入口位于未加载模块的可执行区域")
			if region.MemoryType == memPrivate {
				record.HardSignals = append(record.HardSignals, "线程入口位于 MEM_PRIVATE 可执行内存")
			}
			if region.MemoryType == memMapped && region.BackingFile == "" {
				record.HardSignals = append(record.HardSignals, "线程入口位于无后备文件的 MEM_MAPPED 可执行内存")
			}
		}
		applyProcessContext(item, &record)
		records = append(records, record)
	}
	return records, errors
}

func processModules(pid uint32) ([]moduleRange, error) {
	handle, _, err := procCreateToolhelpSnapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	defer procCloseHandle.Call(handle)

	var entry moduleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, err := procModule32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	modules := make([]moduleRange, 0)
	for {
		base := entry.ModBaseAddr
		modules = append(modules, moduleRange{
			Base: base,
			End:  safeEnd(base, uintptr(entry.ModBaseSize)),
			Name: syscall.UTF16ToString(entry.ModuleName[:]),
			Path: syscall.UTF16ToString(entry.ExePath[:]),
		})
		ret, _, _ = procModule32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return modules, nil
}

func processThreads(pid uint32) ([]uint32, error) {
	handle, _, err := procCreateToolhelpSnapshot.Call(th32csSnapThread, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	defer procCloseHandle.Call(handle)

	var entry threadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, err := procThread32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	threads := make([]uint32, 0)
	for {
		if entry.OwnerProcessID == pid {
			threads = append(threads, entry.ThreadID)
		}
		ret, _, _ = procThread32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return threads, nil
}

func threadStartAddress(threadID uint32) (uintptr, error) {
	handle, _, err := procOpenThread.Call(threadQueryInformation, 0, uintptr(threadID))
	if handle == 0 {
		return 0, err
	}
	defer procCloseHandle.Call(handle)

	var start uintptr
	status, _, err := procNTQueryInfoThread.Call(
		handle,
		9,
		uintptr(unsafe.Pointer(&start)),
		unsafe.Sizeof(start),
		0,
	)
	if int32(status) < 0 {
		return 0, err
	}
	return start, nil
}

func moduleForAddress(modules []moduleRange, address uintptr) *moduleRange {
	for i := range modules {
		if address >= modules[i].Base && address < modules[i].End {
			return &modules[i]
		}
	}
	return nil
}

func regionForAddress(regions []execRegion, address uintptr) *execRegion {
	for i := range regions {
		if address >= regions[i].Base && address < regions[i].End {
			return &regions[i]
		}
	}
	return nil
}

func mappedFileName(processHandle uintptr, address uintptr) string {
	buffer := make([]uint16, 32768)
	ret, _, _ := procGetMappedFileNameW.Call(
		processHandle,
		address,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer[:ret])
}

func fingerprintRegion(processHandle uintptr, region execRegion) regionFingerprint {
	limit := region.Size
	if limit > maxFingerprintBytes {
		limit = maxFingerprintBytes
	}
	data, complete := readMemory(processHandle, region.Base, limit)
	if len(data) == 0 {
		return regionFingerprint{}
	}
	sum := sha256.Sum256(data)
	previewData := data
	if len(previewData) > maxPreviewBytes {
		previewData = previewData[:maxPreviewBytes]
	}
	hasPE := containsEmbeddedPE(previewData)
	hashScope := fmt.Sprintf("区域前 %d 字节", len(data))
	if complete && uintptr(len(data)) == region.Size {
		hashScope = "完整区域"
	}
	return regionFingerprint{
		SHA256:         hex.EncodeToString(sum[:]),
		HashScope:      hashScope,
		Entropy:        math.Round(memoryEntropy(previewData)*100) / 100,
		HexPreview:     memoryHexPreview(previewData, 64),
		StringsPreview: memoryStringsPreview(previewData, 320),
		HasMZ:          strings.Contains(string(previewData), "MZ"),
		HasPE:          hasPE,
	}
}

func readMemory(processHandle uintptr, base uintptr, size uintptr) ([]byte, bool) {
	if size == 0 {
		return nil, false
	}
	buffer := make([]byte, int(size))
	var bytesRead uintptr
	ret, _, _ := procReadProcessMemory.Call(
		processHandle,
		base,
		uintptr(unsafe.Pointer(&buffer[0])),
		size,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if bytesRead == 0 {
		return nil, false
	}
	if bytesRead < uintptr(len(buffer)) {
		buffer = buffer[:bytesRead]
	}
	return buffer, ret != 0 && bytesRead == size
}

func applyRegionSignals(region execRegion, record *Record) {
	if region.MemoryType == memPrivate && isWritableExecutable(region.Protect) && region.Size >= 1024*1024 {
		appendHardSignal(record, "大体积私有 RWX 区域")
	}
	if region.Fingerprint.HasPE {
		appendHardSignal(record, "区域中存在有效 PE 结构")
	} else if region.Fingerprint.HasMZ {
		record.Details = appendDetail(record.Details, "区域中出现 MZ 特征，但未确认有效 PE 头")
	}
	if region.MemoryType == memMapped && region.BackingFile == "" {
		record.Details = appendDetail(record.Details, "未解析到映射区域后备文件")
	}
	if region.Fingerprint.Entropy >= 7.20 {
		record.Details = appendDetail(record.Details, fmt.Sprintf("样本熵 %.2f", region.Fingerprint.Entropy))
	}
	if memoryIndicatorPattern.MatchString(region.Fingerprint.StringsPreview) {
		record.Details = appendDetail(record.Details, "区域字符串包含脚本、网络或注入 API 线索")
		if record.Level == "低" {
			record.Level = "中"
		}
	}
	if len(record.HardSignals) > 0 {
		record.Level = "高"
		record.Reason = appendDetail(record.Reason, strings.Join(record.HardSignals, "；"))
	}
}

func promoteRegionRecords(records []Record, threads []Record) {
	for _, thread := range threads {
		if thread.RegionBase == "" {
			continue
		}
		for i := range records {
			if records[i].RegionBase != thread.RegionBase {
				continue
			}
			appendHardSignal(&records[i], fmt.Sprintf("线程 %d 的入口位于该区域", thread.ThreadID))
			if thread.Level == "高" {
				records[i].Level = "高"
			}
			records[i].Reason = appendDetail(records[i].Reason, fmt.Sprintf("异常线程入口 %s", thread.Base))
			break
		}
	}
}

func appendHardSignal(record *Record, signal string) {
	for _, existing := range record.HardSignals {
		if existing == signal {
			return
		}
	}
	record.HardSignals = append(record.HardSignals, signal)
}

func memoryEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range data {
		counts[value]++
	}
	var result float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		result -= p * math.Log2(p)
	}
	return result
}

func containsEmbeddedPE(data []byte) bool {
	for search := 0; search+0x40 < len(data); {
		relative := strings.Index(string(data[search:]), "MZ")
		if relative < 0 {
			return false
		}
		base := search + relative
		if base+0x40 <= len(data) {
			offset := uint32(data[base+0x3c]) | uint32(data[base+0x3d])<<8 | uint32(data[base+0x3e])<<16 | uint32(data[base+0x3f])<<24
			pe := base + int(offset)
			if offset >= 0x40 && pe+4 <= len(data) && string(data[pe:pe+4]) == "PE\x00\x00" {
				return true
			}
		}
		search = base + 2
	}
	return false
}

func memoryHexPreview(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	return strings.ToUpper(hex.EncodeToString(data))
}

func memoryStringsPreview(data []byte, limit int) string {
	parts := make([]string, 0, 12)
	var current strings.Builder
	flush := func() {
		if current.Len() >= 5 {
			parts = append(parts, current.String())
		}
		current.Reset()
	}
	for _, value := range data {
		if value >= 0x20 && value <= 0x7e {
			current.WriteByte(value)
		} else {
			flush()
		}
		if len(parts) >= 16 {
			break
		}
	}
	flush()
	joined := strings.Join(parts, " | ")
	if len(joined) > limit {
		joined = joined[:limit] + "..."
	}
	return joined
}

func ExportRegion(pid uint32, base, size, maxSize uint64) (RegionExport, error) {
	if base == 0 || size == 0 {
		return RegionExport{}, fmt.Errorf("区域基址和大小不能为空")
	}
	if maxSize == 0 {
		maxSize = 128 * 1024 * 1024
	}
	if size > maxSize {
		return RegionExport{}, fmt.Errorf("区域大小 %d 超过导出上限 %d", size, maxSize)
	}
	handle, _, err := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if handle == 0 {
		return RegionExport{}, fmt.Errorf("打开 PID %d 失败: %v", pid, err)
	}
	defer procCloseHandle.Call(handle)
	var mbi memoryBasicInformation
	ret, _, queryErr := procVirtualQueryEx.Call(handle, uintptr(base), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if ret == 0 {
		return RegionExport{}, fmt.Errorf("查询区域失败: %v", queryErr)
	}
	if uint64(mbi.BaseAddress) != base {
		return RegionExport{}, fmt.Errorf("区域基址已变化，请刷新内存异常后重试")
	}
	if mbi.State != memCommit || isGuardOrNoAccess(mbi.Protect) {
		return RegionExport{}, fmt.Errorf("区域已不可读，请刷新内存异常后重试")
	}
	if size > uint64(mbi.RegionSize) {
		size = uint64(mbi.RegionSize)
	}
	data := make([]byte, 0, int(size))
	remaining := size
	current := uintptr(base)
	const chunkSize = uint64(1024 * 1024)
	for remaining > 0 {
		readSize := remaining
		if readSize > chunkSize {
			readSize = chunkSize
		}
		chunk, _ := readMemory(handle, current, uintptr(readSize))
		if len(chunk) == 0 {
			break
		}
		data = append(data, chunk...)
		current += uintptr(len(chunk))
		remaining -= uint64(len(chunk))
		if uint64(len(chunk)) < readSize {
			break
		}
	}
	if len(data) == 0 {
		return RegionExport{}, fmt.Errorf("ReadProcessMemory 未读取到数据")
	}
	sum := sha256.Sum256(data)
	warning := ""
	if uint64(len(data)) != size {
		warning = fmt.Sprintf("区域仅读取 %d / %d 字节，可能因页面状态变化或权限限制", len(data), size)
	}
	return RegionExport{
		PID:               pid,
		Base:              hexAddress(uintptr(base)),
		Size:              size,
		BytesRead:         uint64(len(data)),
		Protect:           protectName(mbi.Protect),
		AllocationProtect: protectName(mbi.AllocationProtect),
		MemoryType:        memoryTypeName(mbi.Type),
		BackingFile:       mappedFileName(handle, mbi.BaseAddress),
		SHA256:            hex.EncodeToString(sum[:]),
		CollectedAt:       time.Now().Format("2006-01-02 15:04:05"),
		Warning:           warning,
		Data:              data,
	}, nil
}

func isExecutableProtect(protect uint32) bool {
	switch protect & 0xff {
	case pageExecute, pageExecuteRead, pageExecuteReadWrite, pageExecuteWriteCopy:
		return true
	default:
		return false
	}
}

func isWritableExecutable(protect uint32) bool {
	return protect&pageExecuteReadWrite != 0 || protect&pageExecuteWriteCopy != 0
}

func isGuardOrNoAccess(protect uint32) bool {
	return protect&pageGuard != 0 || protect&pageNoAccess != 0
}

func safeEnd(base, size uintptr) uintptr {
	end := base + size
	if end < base {
		return ^uintptr(0)
	}
	return end
}

func hexAddress(value uintptr) string {
	return fmt.Sprintf("0x%016X", uint64(value))
}

func protectName(protect uint32) string {
	flags := []struct {
		bit  uint32
		name string
	}{
		{pageExecute, "EXECUTE"},
		{pageExecuteRead, "EXECUTE_READ"},
		{pageExecuteReadWrite, "EXECUTE_READWRITE"},
		{pageExecuteWriteCopy, "EXECUTE_WRITECOPY"},
	}
	for _, flag := range flags {
		if protect&flag.bit != 0 {
			if protect&pageGuard != 0 {
				return flag.name + "|GUARD"
			}
			return flag.name
		}
	}
	if protect&pageNoAccess != 0 {
		return "NOACCESS"
	}
	return fmt.Sprintf("0x%X", protect)
}

func memoryTypeName(value uint32) string {
	switch value {
	case memPrivate:
		return "MEM_PRIVATE"
	case memMapped:
		return "MEM_MAPPED"
	case memImage:
		return "MEM_IMAGE"
	default:
		return fmt.Sprintf("0x%X", value)
	}
}

func applyProcessContext(item process.Info, record *Record) {
	context := expectedMemoryContext(item)
	if context == "" {
		return
	}
	record.Context = context
	if len(record.HardSignals) > 0 {
		record.Details = appendDetail(record.Details, "可信签名或常见软件上下文不覆盖内存硬信号")
		return
	}
	if record.Category == "线程入口" {
		if record.Level == "高" {
			record.Level = "中"
			record.Details = appendDetail(record.Details, "常见软件内存行为已降级，仍需结合其他证据确认")
		}
		return
	}
	if record.Level == "高" || record.Level == "中" {
		record.Level = "低"
		record.Details = appendDetail(record.Details, "常见软件动态代码/JIT/Hook 行为已降级")
	}
}

func expectedMemoryContext(item process.Info) string {
	lowerName := strings.TrimSuffix(strings.ToLower(item.Name), ".exe")
	lowerPath := strings.ToLower(strings.ReplaceAll(item.Path, "/", `\`))
	parentName := strings.TrimSuffix(strings.ToLower(item.ParentName), ".exe")
	trusted := isTrustedMemoryContextProcess(item)
	if isPowerShellName(lowerName) && selfidentity.IsScannerProcessName(parentName) && trusted {
		return "本工具采集 PowerShell 子进程"
	}
	if !trusted {
		return ""
	}
	if isPowerShellName(lowerName) {
		return "PowerShell/.NET 运行时动态内存行为"
	}
	if lowerName == "explorer" && isWindowsExplorerPath(lowerPath) {
		return "Windows Shell/右键菜单扩展/输入法/安全软件 Hook 常见内存行为"
	}
	if isExpectedWindowsRuntimeName(lowerName) {
		return "Windows 组件/WinUI/.NET 常见动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"chrome", "msedge", "firefox", "browser", "wechat", "weixin", "wxwork", "qq", "tim", "teams", "slack", "discord"}) {
		return "常见浏览器/聊天客户端动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"chatgpt", "openai"}) {
		return "OpenAI 客户端/Electron 常见动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"utools", "code", "codex", "cursor", "node", "electron", "extension-host", "python", "go", "java"}) {
		return "常见开发工具或运行时动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"huorong", "hips", "hr", "火绒", "360", "defender", "security", "avp", "edr", "xdr"}) {
		return "安全软件 Hook/防护模块常见内存行为"
	}
	return ""
}

func isTrustedMemoryContextProcess(item process.Info) bool {
	if item.Signature == "系统文件" || item.Signature == "已签名" {
		return true
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.Name)), ".exe")
	path := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(item.Path), "/", `\`))
	return (name == "chatgpt" || name == "codex") && strings.Contains(path, `\program files\windowsapps\openai.`)
}

func isExpectedWindowsRuntimeName(name string) bool {
	switch name {
	case "runtimebroker", "lockapp", "searchhost", "searchapp",
		"shellexperiencehost", "startmenuexperiencehost", "textinputhost",
		"phoneexperiencehost", "crossdeviceservice", "applicationframehost",
		"widgetboard", "widgets", "systemsettings", "securityhealthhost":
		return true
	default:
		return false
	}
}

func isPowerShellName(name string) bool {
	return name == "powershell" || name == "pwsh"
}

func isWindowsExplorerPath(path string) bool {
	return strings.HasSuffix(path, `\windows\explorer.exe`)
}

func hasAny(name, path string, values []string) bool {
	for _, value := range values {
		if len(value) <= 3 {
			if name == value || strings.HasPrefix(name, value+"-") || strings.HasPrefix(name, value+"_") || (value == "360" && strings.HasPrefix(name, value)) {
				return true
			}
			continue
		}
		if strings.Contains(name, value) || strings.Contains(path, value) {
			return true
		}
	}
	return false
}

func appendDetail(existing, value string) string {
	if strings.TrimSpace(existing) == "" {
		return value
	}
	return existing + "; " + value
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
