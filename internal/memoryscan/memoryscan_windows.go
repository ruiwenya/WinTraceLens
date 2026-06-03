//go:build windows

package memoryscan

import (
	"fmt"
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
)

var (
	modKernel32                = syscall.NewLazyDLL("kernel32.dll")
	modNTDLL                   = syscall.NewLazyDLL("ntdll.dll")
	procOpenProcess            = modKernel32.NewProc("OpenProcess")
	procOpenThread             = modKernel32.NewProc("OpenThread")
	procCloseHandle            = modKernel32.NewProc("CloseHandle")
	procVirtualQueryEx         = modKernel32.NewProc("VirtualQueryEx")
	procCreateToolhelpSnapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32FirstW         = modKernel32.NewProc("Module32FirstW")
	procModule32NextW          = modKernel32.NewProc("Module32NextW")
	procThread32First          = modKernel32.NewProc("Thread32First")
	procThread32Next           = modKernel32.NewProc("Thread32Next")
	procNTQueryInfoThread      = modNTDLL.NewProc("NtQueryInformationThread")
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
	Base       uintptr
	End        uintptr
	Size       uintptr
	Protect    uint32
	MemoryType uint32
}

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
				Base:       mbi.BaseAddress,
				End:        safeEnd(mbi.BaseAddress, mbi.RegionSize),
				Size:       mbi.RegionSize,
				Protect:    mbi.Protect,
				MemoryType: mbi.Type,
			}
			regions = append(regions, region)
			if level, reason := suspiciousRegion(mbi); reason != "" {
				if countProcessRecords(records) < opts.MaxRegionsPerProcess {
					record := Record{
						Level:      level,
						Category:   "内存区域",
						PID:        item.PID,
						Process:    item.Name,
						Path:       item.Path,
						Reason:     reason,
						Base:       hexAddress(mbi.BaseAddress),
						Size:       uint64(mbi.RegionSize),
						Protect:    protectName(mbi.Protect),
						MemoryType: memoryTypeName(mbi.Type),
						Details:    fmt.Sprintf("AllocationProtect=%s", protectName(mbi.AllocationProtect)),
					}
					applyProcessContext(item, &record)
					records = append(records, record)
				}
			}
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
			records = append(records, threadRecords...)
			errors = append(errors, threadErrors...)
		}
	}

	return true, false, records, errors
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
			}
		}
		record := Record{
			Level:    level,
			Category: "线程入口",
			PID:      item.PID,
			Process:  item.Name,
			Path:     item.Path,
			Reason:   reason,
			Base:     hexAddress(start),
			ThreadID: threadID,
			Details:  details,
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
	if isPowerShellName(lowerName) && selfidentity.IsScannerProcessName(parentName) {
		return "本工具采集 PowerShell 子进程"
	}
	if isPowerShellName(lowerName) {
		return "PowerShell/.NET 运行时动态内存行为"
	}
	if lowerName == "explorer" && isWindowsExplorerPath(lowerPath) {
		return "Windows Shell/右键菜单扩展/输入法/安全软件 Hook 常见内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"chrome", "msedge", "firefox", "browser", "wechat", "weixin", "wxwork", "qq", "tim", "teams", "slack", "discord"}) {
		return "常见浏览器/聊天客户端动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"code", "codex", "cursor", "node", "electron", "extension-host", "python", "go", "java"}) {
		return "常见开发工具或运行时动态内存行为"
	}
	if hasAny(lowerName, lowerPath, []string{"huorong", "hips", "hr", "火绒", "360", "defender", "security", "avp", "edr", "xdr"}) {
		return "安全软件 Hook/防护模块常见内存行为"
	}
	return ""
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
