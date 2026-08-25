//go:build windows

package process

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processQueryInformation       = 0x0400
	processVMRead                 = 0x0010
	processProtectionInformation  = 61
	processCommandLineInformation = 60
	imageFileMachineI386          = 0x014c
	imageFileMachineAMD64         = 0x8664
	imageFileMachineARM64         = 0xaa64
	securityMandatoryLowRID       = 0x1000
	securityMandatoryMediumRID    = 0x2000
	securityMandatoryHighRID      = 0x3000
	securityMandatorySystemRID    = 0x4000
	securityMandatoryProtectedRID = 0x5000
)

var (
	modPSAPI                      = syscall.NewLazyDLL("psapi.dll")
	procGetProcessMemoryInfo      = modPSAPI.NewProc("GetProcessMemoryInfo")
	procGetProcessHandleCount     = modKernel32.NewProc("GetProcessHandleCount")
	procNtQueryInformationProcess = modNTDLL.NewProc("NtQueryInformationProcess")
)

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

type processContext struct {
	Name               string
	Path               string
	ParentPID          uint32
	CommandLine        string
	UserName           string
	UserSID            string
	SessionID          uint32
	IntegrityLevel     string
	Architecture       string
	Protection         string
	ThreadCount        uint32
	HandleCount        uint32
	PrivateMemoryBytes uint64
	WorkingSetBytes    uint64
}

func queryProcessContext(pid uint32) processContext {
	result := processContext{Protection: "未知"}
	_ = windows.ProcessIdToSessionId(pid, &result.SessionID)

	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation|processQueryInformation|processVMRead, 0, uintptr(pid))
	if handle == 0 {
		handle, _, _ = procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	}
	if handle == 0 {
		return result
	}
	defer procCloseHandle.Call(handle)

	result.Architecture = processArchitecture(windows.Handle(handle))
	result.Protection = processProtection(handle)
	result.CommandLine = processCommandLine(handle)
	queryProcessMetrics(handle, &result)
	queryProcessToken(windows.Handle(handle), &result)
	return result
}

func processCommandLine(handle uintptr) string {
	var needed uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		handle,
		uintptr(processCommandLineInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if status == 0 || needed == 0 || needed > 1024*1024 {
		return ""
	}
	buffer := make([]byte, needed)
	status, _, _ = procNtQueryInformationProcess.Call(
		handle,
		uintptr(processCommandLineInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if status != 0 || len(buffer) < int(unsafe.Sizeof(nativeUnicodeString{})) {
		return ""
	}
	value := (*nativeUnicodeString)(unsafe.Pointer(&buffer[0]))
	if value.Length == 0 || value.Buffer == 0 || value.Length%2 != 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buffer[0]))
	end := base + uintptr(len(buffer))
	if value.Buffer < base || value.Buffer+uintptr(value.Length) > end {
		return ""
	}
	chars := unsafe.Slice((*uint16)(unsafe.Pointer(value.Buffer)), int(value.Length/2))
	return strings.TrimSpace(syscall.UTF16ToString(chars))
}

func queryProcessMetrics(handle uintptr, result *processContext) {
	var handles uint32
	if ok, _, _ := procGetProcessHandleCount.Call(handle, uintptr(unsafe.Pointer(&handles))); ok != 0 {
		result.HandleCount = handles
	}

	counters := processMemoryCountersEx{CB: uint32(unsafe.Sizeof(processMemoryCountersEx{}))}
	if ok, _, _ := procGetProcessMemoryInfo.Call(handle, uintptr(unsafe.Pointer(&counters)), uintptr(counters.CB)); ok != 0 {
		result.WorkingSetBytes = uint64(counters.WorkingSetSize)
		result.PrivateMemoryBytes = uint64(counters.PrivateUsage)
	}
}

func queryProcessToken(handle windows.Handle, result *processContext) {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return
	}
	defer token.Close()

	if user, err := token.GetTokenUser(); err == nil && user.User.Sid != nil {
		result.UserSID = user.User.Sid.String()
		account, domain, _, lookupErr := user.User.Sid.LookupAccount("")
		if lookupErr == nil {
			result.UserName = strings.Trim(strings.Join([]string{domain, account}, `\`), `\`)
		}
	}
	result.IntegrityLevel = tokenIntegrityLevel(token)
}

func tokenIntegrityLevel(token windows.Token) string {
	var needed uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &needed)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || needed == 0 {
		return ""
	}
	buffer := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], needed, &needed); err != nil {
		return ""
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil || label.Label.Sid.SubAuthorityCount() == 0 {
		return ""
	}
	rid := label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount() - 1))
	return integrityLabel(rid)
}

func integrityLabel(rid uint32) string {
	switch {
	case rid < securityMandatoryLowRID:
		return "不受信任"
	case rid < securityMandatoryMediumRID:
		return "低"
	case rid < securityMandatoryHighRID:
		return "中"
	case rid < securityMandatorySystemRID:
		return "高"
	case rid < securityMandatoryProtectedRID:
		return "系统"
	default:
		return "受保护"
	}
}

func processArchitecture(handle windows.Handle) string {
	var processMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(handle, &processMachine, &nativeMachine); err == nil {
		if processMachine == 0 {
			processMachine = nativeMachine
		}
		return machineLabel(processMachine)
	}
	var wow64 bool
	if err := windows.IsWow64Process(handle, &wow64); err == nil {
		if wow64 {
			return "x86"
		}
		if runtime.GOARCH == "amd64" {
			return "x64"
		}
		return runtime.GOARCH
	}
	return ""
}

func machineLabel(machine uint16) string {
	switch machine {
	case imageFileMachineI386:
		return "x86"
	case imageFileMachineAMD64:
		return "x64"
	case imageFileMachineARM64:
		return "ARM64"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04X", machine)
	}
}

func processProtection(handle uintptr) string {
	var protection byte
	status, _, _ := procNtQueryInformationProcess.Call(
		handle,
		uintptr(processProtectionInformation),
		uintptr(unsafe.Pointer(&protection)),
		uintptr(unsafe.Sizeof(protection)),
		0,
	)
	if status != 0 {
		return "未知"
	}
	protectionType := protection & 0x7
	if protectionType == 0 {
		return "未保护"
	}
	typeName := map[byte]string{1: "PPL", 2: "受保护进程"}[protectionType]
	if typeName == "" {
		typeName = fmt.Sprintf("保护类型%d", protectionType)
	}
	signer := map[byte]string{
		1: "Authenticode", 2: "CodeGen", 3: "Antimalware", 4: "LSA",
		5: "Windows", 6: "WinTcb", 7: "WinSystem", 8: "App",
	}[protection>>4]
	if signer == "" {
		return typeName
	}
	return typeName + " / " + signer
}

func mergeProcessContext(dst *processContext, src processContext) {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Path == "" {
		dst.Path = src.Path
	}
	if dst.ParentPID == 0 {
		dst.ParentPID = src.ParentPID
	}
	if dst.CommandLine == "" {
		dst.CommandLine = src.CommandLine
	}
	if dst.ThreadCount == 0 {
		dst.ThreadCount = src.ThreadCount
	}
	if dst.HandleCount == 0 {
		dst.HandleCount = src.HandleCount
	}
	if dst.PrivateMemoryBytes == 0 {
		dst.PrivateMemoryBytes = src.PrivateMemoryBytes
	}
	if dst.WorkingSetBytes == 0 {
		dst.WorkingSetBytes = src.WorkingSetBytes
	}
}
