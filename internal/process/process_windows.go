//go:build windows

package process

import (
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
	for _, entry := range entries {
		names[entry.ProcessID] = utf16String(entry.ExeFile[:])
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
		createdAt := queryProcessCreatedAt(entry.ProcessID)
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

		items = append(items, Info{
			PID:             entry.ProcessID,
			Name:            names[entry.ProcessID],
			ParentPID:       entry.ParentProcessID,
			ParentName:      names[entry.ParentProcessID],
			CreatedAt:       formatTime(createdAt),
			Path:            path,
			FileCreated:     formatTime(fileCreated),
			FileModified:    formatTime(fileModified),
			MD5:             md5Value,
			Signature:       sig.Status,
			SignatureMsg:    sig.Message,
			ConnectionCount: connectionCount[entry.ProcessID],
			HashError:       hashErr,
			PathError:       pathErr,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].PID < items[j].PID
	})

	return items, nil
}

func Modules(pid uint32, opts Options) ([]ModuleInfo, error) {
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
		key := strings.ToLower(path)

		var md5Value, hashErr string
		if path != "" && !opts.SkipHashes {
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
		if path != "" && !opts.SkipSignatures {
			if cached, ok := signatureCache[key]; ok {
				sig = cached
			} else {
				sig = CheckSignature(path)
				signatureCache[key] = sig
			}
		}

		modules = append(modules, ModuleInfo{
			Name:         utf16String(entry.ModuleName[:]),
			Path:         path,
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
		return "", err.Error()
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
		return "", err.Error()
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
