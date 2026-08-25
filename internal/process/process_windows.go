//go:build windows

package process

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	th32csSnapProcess              = 0x00000002
	th32csSnapModule               = 0x00000008
	th32csSnapModule32             = 0x00000010
	processQueryLimitedInformation = 0x1000
	maxPath                        = 260
	maxModuleName32                = 255
)

var (
	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW            = modKernel32.NewProc("Process32NextW")
	procModule32FirstW            = modKernel32.NewProc("Module32FirstW")
	procModule32NextW             = modKernel32.NewProc("Module32NextW")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessTimes           = modKernel32.NewProc("GetProcessTimes")
)

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
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

func Collect(opts Options) ([]Info, error) {
	entries, err := snapshotProcesses()
	if err != nil {
		return nil, err
	}

	names := make(map[uint32]string, len(entries))
	toolhelpPIDs := make(map[uint32]struct{}, len(entries))
	for _, entry := range entries {
		names[entry.ProcessID] = utf16String(entry.ExeFile[:])
		toolhelpPIDs[entry.ProcessID] = struct{}{}
	}
	nativeProcesses, nativeErr := snapshotProcessesNative()
	wmiProcesses, wmiErr := snapshotProcessesWMI()
	createdByPID := make(map[uint32]time.Time, len(entries))
	for _, entry := range entries {
		createdByPID[entry.ProcessID] = queryProcessCreatedAt(entry.ProcessID)
	}

	hashCache := make(map[string]struct {
		value string
		err   string
	})

	signatureCache := make(map[string]SignatureResult)
	connectionCount := make(map[uint32]int)
	if connections, err := CollectConnections(); err == nil {
		for _, connection := range connections {
			connectionCount[connection.PID]++
		}
	}

	items := make([]Info, 0, len(entries))
	for _, entry := range entries {
		path, pathErr := queryProcessPath(entry.ProcessID)
		createdAt := createdByPID[entry.ProcessID]
		contextInfo := queryProcessContext(entry.ProcessID)
		wmiInfo, inWMI := wmiProcesses[entry.ProcessID]
		if contextInfo.CommandLine == "" {
			contextInfo.CommandLine = wmiInfo.CommandLine
		}
		if contextInfo.ThreadCount == 0 {
			contextInfo.ThreadCount = firstNonZeroUint32(entry.Threads, wmiInfo.ThreadCount)
		}
		if contextInfo.HandleCount == 0 {
			contextInfo.HandleCount = wmiInfo.HandleCount
		}
		if contextInfo.WorkingSetBytes == 0 {
			contextInfo.WorkingSetBytes = wmiInfo.WorkingSetBytes
		}
		if contextInfo.PrivateMemoryBytes == 0 {
			contextInfo.PrivateMemoryBytes = wmiInfo.PrivateMemoryBytes
		}
		fileCreated, fileModified := fileTimes(path)

		var md5Value, hashErr string
		var sig SignatureResult
		if path != "" {
			key := strings.ToLower(path)
			if !opts.SkipHashes {
				if cached, ok := hashCache[key]; ok {
					md5Value = cached.value
					hashErr = cached.err
				} else {
					md5Value, hashErr = fileMD5(path, opts.HashLimitBytes)
					hashCache[key] = struct {
						value string
						err   string
					}{value: md5Value, err: hashErr}
				}
			}

			if opts.SkipSignatures {
				sig = SignatureResult{}
			} else if cached, ok := signatureCache[key]; ok {
				sig = cached
			} else {
				sig = CheckSignature(path)
				signatureCache[key] = sig
			}
		}

		sources := "Toolhelp32 进程视图"
		warning := ""
		if nativeErr == nil {
			if _, ok := nativeProcesses[entry.ProcessID]; ok {
				sources += " + NT 系统信息视图"
			} else if path != "" {
				warning = "Toolhelp32 视图可见，但 NT 系统信息视图未发现；请排除进程瞬时退出或枚举链路被干扰"
			}
		}
		if wmiErr == nil && inWMI {
			sources += " + WMI 提供程序视图"
		} else if wmiErr == nil && !inWMI && path != "" && !createdAt.IsZero() && time.Since(createdAt) > 5*time.Second {
			warning = appendWarning(warning, "Toolhelp32 视图可见，但 WMI 提供程序视图未发现；请排除进程瞬时退出或提供程序延迟")
		} else if wmiErr != nil {
			sources += "；WMI 视图不可用"
		}
		items = append(items, Info{
			PID:                entry.ProcessID,
			Name:               names[entry.ProcessID],
			ParentPID:          entry.ParentProcessID,
			ParentName:         names[entry.ParentProcessID],
			CreatedAt:          formatTime(createdAt),
			ParentCreatedAt:    formatTime(createdByPID[entry.ParentProcessID]),
			Path:               path,
			CommandLine:        contextInfo.CommandLine,
			UserName:           contextInfo.UserName,
			UserSID:            contextInfo.UserSID,
			SessionID:          contextInfo.SessionID,
			IntegrityLevel:     contextInfo.IntegrityLevel,
			Architecture:       contextInfo.Architecture,
			Protection:         contextInfo.Protection,
			ThreadCount:        contextInfo.ThreadCount,
			HandleCount:        contextInfo.HandleCount,
			PrivateMemoryBytes: contextInfo.PrivateMemoryBytes,
			WorkingSetBytes:    contextInfo.WorkingSetBytes,
			FileCreated:        formatTime(fileCreated),
			FileModified:       formatTime(fileModified),
			MD5:                md5Value,
			Signature:          sig.Status,
			SignatureMsg:       sig.Message,
			ConnectionCount:    connectionCount[entry.ProcessID],
			HashError:          hashErr,
			PathError:          pathErr,
			EnumerationSources: sources,
			EnumerationWarning: warning,
		})
	}

	if nativeErr == nil {
		for pid, name := range nativeProcesses {
			if _, ok := toolhelpPIDs[pid]; ok {
				continue
			}
			path, pathErr := queryProcessPath(pid)
			contextInfo := queryProcessContext(pid)
			wmiInfo, inWMI := wmiProcesses[pid]
			mergeProcessContext(&contextInfo, wmiInfo)
			if path == "" {
				path = contextInfo.Path
			}
			sources := "NT 系统信息视图"
			if wmiErr == nil && inWMI {
				sources += " + WMI 提供程序视图"
			}
			items = append(items, Info{
				PID:                pid,
				Name:               firstNonEmpty(name, "[NT 枚举进程]"),
				Path:               path,
				CommandLine:        contextInfo.CommandLine,
				UserName:           contextInfo.UserName,
				UserSID:            contextInfo.UserSID,
				SessionID:          contextInfo.SessionID,
				IntegrityLevel:     contextInfo.IntegrityLevel,
				Architecture:       contextInfo.Architecture,
				Protection:         contextInfo.Protection,
				ThreadCount:        contextInfo.ThreadCount,
				HandleCount:        contextInfo.HandleCount,
				PrivateMemoryBytes: contextInfo.PrivateMemoryBytes,
				WorkingSetBytes:    contextInfo.WorkingSetBytes,
				PathError:          pathErr,
				ConnectionCount:    connectionCount[pid],
				EnumerationSources: sources,
				EnumerationWarning: "NT 系统信息视图可见，但 Toolhelp32 视图未发现；可能是进程创建/退出竞态，也可能存在枚举差异",
			})
		}
		for pid, count := range connectionCount {
			if pid == 0 {
				continue
			}
			if _, inToolhelp := toolhelpPIDs[pid]; inToolhelp {
				continue
			}
			if _, inNative := nativeProcesses[pid]; inNative {
				continue
			}
			if _, inWMI := wmiProcesses[pid]; wmiErr == nil && inWMI {
				continue
			}
			path, pathErr := queryProcessPath(pid)
			items = append(items, Info{
				PID:                pid,
				Name:               "[连接表 PID]",
				Path:               path,
				PathError:          pathErr,
				ConnectionCount:    count,
				EnumerationSources: "TCP/UDP 连接表",
				EnumerationWarning: "连接表仍引用该 PID，但两种进程视图均未发现；请先排除连接残留和进程退出竞态",
			})
		}
	}

	if wmiErr == nil {
		for pid, wmiInfo := range wmiProcesses {
			if _, ok := toolhelpPIDs[pid]; ok {
				continue
			}
			if _, ok := nativeProcesses[pid]; ok {
				continue
			}
			contextInfo := queryProcessContext(pid)
			mergeProcessContext(&contextInfo, wmiInfo)
			items = append(items, Info{
				PID: pid, Name: firstNonEmpty(contextInfo.Name, "[WMI 枚举进程]"),
				ParentPID: contextInfo.ParentPID, ParentName: names[contextInfo.ParentPID],
				Path: contextInfo.Path, CommandLine: contextInfo.CommandLine,
				UserName: contextInfo.UserName, UserSID: contextInfo.UserSID,
				SessionID: contextInfo.SessionID, IntegrityLevel: contextInfo.IntegrityLevel,
				Architecture: contextInfo.Architecture, Protection: contextInfo.Protection,
				ThreadCount: contextInfo.ThreadCount, HandleCount: contextInfo.HandleCount,
				PrivateMemoryBytes: contextInfo.PrivateMemoryBytes, WorkingSetBytes: contextInfo.WorkingSetBytes,
				ConnectionCount: connectionCount[pid], EnumerationSources: "WMI 提供程序视图",
				EnumerationWarning: "WMI 提供程序视图可见，但 Toolhelp32 与 NT 系统信息视图均未发现；请优先核查，同时排除进程创建/退出竞态",
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].PID < items[j].PID
	})

	return items, nil
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func appendWarning(current, value string) string {
	current = strings.TrimSpace(current)
	value = strings.TrimSpace(value)
	if current == "" {
		return value
	}
	if value == "" || strings.Contains(current, value) {
		return current
	}
	return current + "；" + value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func Modules(pid uint32, opts Options) ([]ModuleInfo, error) {
	if pid == 4 {
		return kernelModules(opts)
	}
	return processModules(pid, opts)
}

func processModules(pid uint32, opts Options) ([]ModuleInfo, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
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

	hashCache := make(map[string]struct {
		value string
		err   string
	})
	signatureCache := make(map[string]SignatureResult)

	var modules []ModuleInfo
	for {
		path := utf16String(entry.ExePath[:])
		md5Value, hashErr, sig := moduleFileMetadata(path, opts, hashCache, signatureCache)

		modules = append(modules, ModuleInfo{
			Name:         utf16String(entry.ModuleName[:]),
			Kind:         "进程模块",
			Path:         path,
			BaseAddress:  fmt.Sprintf("0x%X", entry.ModBaseAddr),
			SizeKB:       entry.ModBaseSize / 1024,
			MD5:          md5Value,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})

		ret, _, _ = procModule32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	sort.Slice(modules, func(i, j int) bool {
		return strings.ToLower(modules[i].Name) < strings.ToLower(modules[j].Name)
	})

	return modules, nil
}

func moduleFileMetadata(path string, opts Options, hashCache map[string]struct {
	value string
	err   string
}, signatureCache map[string]SignatureResult) (string, string, SignatureResult) {
	if path == "" {
		return "", "", SignatureResult{}
	}

	key := strings.ToLower(path)
	var md5Value, hashErr string
	if !opts.SkipHashes {
		if cached, ok := hashCache[key]; ok {
			md5Value = cached.value
			hashErr = cached.err
		} else {
			md5Value, hashErr = fileMD5(path, opts.HashLimitBytes)
			hashCache[key] = struct {
				value string
				err   string
			}{value: md5Value, err: hashErr}
		}
	}

	var sig SignatureResult
	if !opts.SkipSignatures {
		if cached, ok := signatureCache[key]; ok {
			sig = cached
		} else {
			sig = CheckSignature(path)
			signatureCache[key] = sig
		}
	}

	return md5Value, hashErr, sig
}

func snapshotProcesses() ([]processEntry32, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	defer procCloseHandle.Call(handle)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	var entries []processEntry32
	for {
		entries = append(entries, entry)
		ret, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return entries, nil
}

func queryProcessPath(pid uint32) (string, string) {
	handle, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		if pid == 0 || pid == 4 {
			return "", "系统进程路径无法通过常规接口读取"
		}
		return "", friendlyFileError(err)
	}
	defer procCloseHandle.Call(handle)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageName.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		if pid == 0 || pid == 4 {
			return "", "系统进程路径无法通过常规接口读取"
		}
		return "", friendlyFileError(err)
	}

	return syscall.UTF16ToString(buf[:size]), ""
}

func queryProcessCreatedAt(pid uint32) time.Time {
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return time.Time{}
	}
	defer procCloseHandle.Call(handle)

	var creation, exit, kernel, user syscall.Filetime
	ret, _, _ := procGetProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return time.Time{}
	}

	return time.Unix(0, creation.Nanoseconds()).Local()
}

func fileTimes(path string) (time.Time, time.Time) {
	if path == "" {
		return time.Time{}, time.Time{}
	}

	var data syscall.Win32FileAttributeData
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	if err := syscall.GetFileAttributesEx(p, syscall.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&data))); err != nil {
		if stat, statErr := os.Stat(path); statErr == nil {
			return time.Time{}, stat.ModTime().Local()
		}
		return time.Time{}, time.Time{}
	}

	created := time.Unix(0, data.CreationTime.Nanoseconds()).Local()
	modified := time.Unix(0, data.LastWriteTime.Nanoseconds()).Local()
	return created, modified
}

func utf16String(value []uint16) string {
	return syscall.UTF16ToString(value)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}
