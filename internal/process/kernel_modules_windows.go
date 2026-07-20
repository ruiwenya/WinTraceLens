//go:build windows

package process

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const (
	systemModuleInformation  = 11
	statusInfoLengthMismatch = 0xC0000004
)

var (
	modNTDLL                     = syscall.NewLazyDLL("ntdll.dll")
	modPsapi                     = syscall.NewLazyDLL("psapi.dll")
	procNtQuerySystemInformation = modNTDLL.NewProc("NtQuerySystemInformation")
	procEnumDeviceDrivers        = modPsapi.NewProc("EnumDeviceDrivers")
	procGetDeviceDriverBaseNameW = modPsapi.NewProc("GetDeviceDriverBaseNameW")
	procGetDeviceDriverFileNameW = modPsapi.NewProc("GetDeviceDriverFileNameW")
)

type rtlProcessModuleInformation struct {
	Section          uintptr
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

type rtlProcessModulesHeader struct {
	NumberOfModules uint32
	Modules         [1]rtlProcessModuleInformation
}

func kernelModules(opts Options) ([]ModuleInfo, error) {
	modules, err := kernelModulesNT(opts)
	if err == nil {
		return modules, nil
	}

	fallback, fallbackErr := kernelModulesPSAPI(opts)
	if fallbackErr == nil {
		return fallback, nil
	}

	return nil, fmt.Errorf("内核驱动枚举失败: NtQuerySystemInformation: %v; PSAPI: %v", err, fallbackErr)
}

func kernelModulesNT(opts Options) ([]ModuleInfo, error) {
	size := uint32(1024 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]byte, size)
		var needed uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			uintptr(systemModuleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if status == 0 {
			return parseSystemModules(buf, opts)
		}
		if uint32(status) != statusInfoLengthMismatch {
			return nil, fmt.Errorf("NTSTATUS 0x%X", uint32(status))
		}
		if needed > size {
			size = needed + 64*1024
		} else {
			size *= 2
		}
	}
	return nil, fmt.Errorf("系统模块缓冲区持续不足")
}

func parseSystemModules(buf []byte, opts Options) ([]ModuleInfo, error) {
	if len(buf) < int(unsafe.Sizeof(rtlProcessModulesHeader{})) {
		return nil, fmt.Errorf("系统模块返回数据过短")
	}

	var layout rtlProcessModulesHeader
	header := (*rtlProcessModulesHeader)(unsafe.Pointer(&buf[0]))
	count := int(header.NumberOfModules)
	if count < 0 || count > 20000 {
		return nil, fmt.Errorf("系统模块数量异常: %d", count)
	}

	entryOffset := unsafe.Offsetof(layout.Modules)
	entrySize := unsafe.Sizeof(rtlProcessModuleInformation{})
	hashCache := make(map[string]struct {
		value string
		err   string
	})
	signatureCache := make(map[string]SignatureResult)
	modules := make([]ModuleInfo, 0, count)

	for i := 0; i < count; i++ {
		offset := entryOffset + uintptr(i)*entrySize
		if offset+entrySize > uintptr(len(buf)) {
			return nil, fmt.Errorf("系统模块返回数据不完整")
		}
		entry := (*rtlProcessModuleInformation)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))
		nativePath := nullTerminatedBytes(entry.FullPathName[:])
		name := kernelModuleName(nativePath, entry.OffsetToFileName)
		path := normalizeKernelPath(nativePath)
		md5Value, hashErr, sig := moduleFileMetadata(path, opts, hashCache, signatureCache)
		kind, hashErr, sig := classifyKernelModule(name, md5Value, hashErr, sig)

		modules = append(modules, ModuleInfo{
			Name:         name,
			Kind:         kind,
			Path:         path,
			BaseAddress:  fmt.Sprintf("0x%X", entry.ImageBase),
			SizeKB:       entry.ImageSize / 1024,
			MD5:          md5Value,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}

	sortModules(modules)
	return modules, nil
}

func kernelModulesPSAPI(opts Options) ([]ModuleInfo, error) {
	baseCount := 2048
	hashCache := make(map[string]struct {
		value string
		err   string
	})
	signatureCache := make(map[string]SignatureResult)

	for attempt := 0; attempt < 5; attempt++ {
		bases := make([]uintptr, baseCount)
		var needed uint32
		ret, _, err := procEnumDeviceDrivers.Call(
			uintptr(unsafe.Pointer(&bases[0])),
			uintptr(len(bases)*int(unsafe.Sizeof(uintptr(0)))),
			uintptr(unsafe.Pointer(&needed)),
		)
		if ret == 0 {
			return nil, err
		}
		required := int(needed) / int(unsafe.Sizeof(uintptr(0)))
		if required > len(bases) {
			baseCount = required + 256
			continue
		}

		modules := make([]ModuleInfo, 0, required)
		for _, base := range bases[:required] {
			if base == 0 {
				continue
			}
			name := deviceDriverString(procGetDeviceDriverBaseNameW, base)
			nativePath := deviceDriverString(procGetDeviceDriverFileNameW, base)
			path := normalizeKernelPath(nativePath)
			if name == "" {
				name = filepath.Base(path)
			}
			md5Value, hashErr, sig := moduleFileMetadata(path, opts, hashCache, signatureCache)
			kind, hashErr, sig := classifyKernelModule(name, md5Value, hashErr, sig)
			modules = append(modules, ModuleInfo{
				Name:         name,
				Kind:         kind,
				Path:         path,
				BaseAddress:  fmt.Sprintf("0x%X", base),
				MD5:          md5Value,
				Signature:    sig.Status,
				SignatureMsg: sig.Message,
				HashError:    hashErr,
			})
		}
		sortModules(modules)
		return modules, nil
	}

	return nil, fmt.Errorf("PSAPI 驱动数组持续不足")
}

func classifyKernelModule(name, md5Value, hashErr string, sig SignatureResult) (string, string, SignatureResult) {
	if !isKnownDumpDriver(name) {
		return "内核驱动", hashErr, sig
	}

	if strings.TrimSpace(md5Value) == "" {
		hashErr = "系统转储驱动通常没有独立落地文件，无法计算 MD5"
	}
	sig = SignatureResult{
		Status:  "系统转储驱动",
		Message: "Windows 崩溃转储/存储转储路径使用的 dump_* 内核模块名，可能没有独立落地文件；通常不等同于普通恶意驱动。",
	}
	return "系统转储驱动", hashErr, sig
}

func isKnownDumpDriver(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "dump_stornvme.sys", "dump_dumpstorport.sys", "dump_dumpfve.sys":
		return true
	default:
		return false
	}
}

func nullTerminatedBytes(raw []byte) string {
	if idx := bytes.IndexByte(raw, 0); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.TrimSpace(string(raw))
}

func kernelModuleName(nativePath string, offset uint16) string {
	if nativePath == "" {
		return ""
	}
	if int(offset) > 0 && int(offset) < len(nativePath) {
		return nativePath[int(offset):]
	}
	return filepath.Base(strings.ReplaceAll(nativePath, "/", `\`))
}

func deviceDriverString(proc *syscall.LazyProc, base uintptr) string {
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	ret, _, _ := proc.Call(
		base,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	if int(ret) < len(buf) {
		return syscall.UTF16ToString(buf[:ret])
	}
	return syscall.UTF16ToString(buf)
}

func normalizeKernelPath(path string) string {
	path = strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
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
	default:
		return path
	}
}

func sortModules(modules []ModuleInfo) {
	sort.Slice(modules, func(i, j int) bool {
		left := strings.ToLower(modules[i].Name)
		right := strings.ToLower(modules[j].Name)
		if left == right {
			return strings.ToLower(modules[i].Path) < strings.ToLower(modules[j].Path)
		}
		return left < right
	})
}
