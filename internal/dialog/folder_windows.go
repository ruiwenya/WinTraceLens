//go:build windows

package dialog

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

type FolderResult struct {
	OK    bool   `json:"ok"`
	Path  string `json:"path"`
	Error string `json:"error"`
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

const (
	coinitApartmentThreaded = 0x2
	clsctxInprocServer      = 0x1
	fosNoChangeDir          = 0x00000008
	fosPickFolders          = 0x00000020
	fosForceFileSystem      = 0x00000040
	fosPathMustExist        = 0x00000800
	sigdnFileSysPath        = 0x80058000
	hresultCancelled        = 0x800704C7
)

var (
	ole32                   = syscall.NewLazyDLL("ole32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procCoInitializeEx      = ole32.NewProc("CoInitializeEx")
	procCoUninitialize      = ole32.NewProc("CoUninitialize")
	procCoCreateInstance    = ole32.NewProc("CoCreateInstance")
	procCoTaskMemFree       = ole32.NewProc("CoTaskMemFree")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	clsidFileOpenDialog     = guid{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog      = guid{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

func SelectFolder(title string) FolderResult {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "选择文件夹"
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	initialized := succeeded(hr)
	if initialized {
		defer procCoUninitialize.Call()
	} else if hr != 0x80010106 {
		return FolderResult{Error: formatHRESULT("初始化文件夹选择器失败", hr)}
	}

	var dialog uintptr
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidFileOpenDialog)),
		0,
		clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIFileOpenDialog)),
		uintptr(unsafe.Pointer(&dialog)),
	)
	if failed(hr) || dialog == 0 {
		return FolderResult{Error: formatHRESULT("创建文件夹选择器失败", hr)}
	}
	defer comRelease(dialog)

	vtable := comVTable(dialog)
	options := uintptr(fosPickFolders | fosForceFileSystem | fosPathMustExist | fosNoChangeDir)
	hr, _, _ = syscall.SyscallN(vtable[9], dialog, options)
	if failed(hr) {
		return FolderResult{Error: formatHRESULT("设置文件夹选择器选项失败", hr)}
	}

	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err == nil {
		hr, _, _ = syscall.SyscallN(vtable[17], dialog, uintptr(unsafe.Pointer(titlePtr)))
		if failed(hr) {
			return FolderResult{Error: formatHRESULT("设置文件夹选择器标题失败", hr)}
		}
	}

	owner, _, _ := procGetForegroundWindow.Call()
	hr, _, _ = syscall.SyscallN(vtable[3], dialog, owner)
	if uint32(hr) == hresultCancelled {
		return FolderResult{OK: false}
	}
	if failed(hr) {
		return FolderResult{Error: formatHRESULT("显示文件夹选择器失败", hr)}
	}

	var item uintptr
	hr, _, _ = syscall.SyscallN(vtable[20], dialog, uintptr(unsafe.Pointer(&item)))
	if failed(hr) || item == 0 {
		return FolderResult{Error: formatHRESULT("读取已选择文件夹失败", hr)}
	}
	defer comRelease(item)

	itemVTable := comVTable(item)
	var pathPtr uintptr
	hr, _, _ = syscall.SyscallN(itemVTable[5], item, sigdnFileSysPath, uintptr(unsafe.Pointer(&pathPtr)))
	if failed(hr) || pathPtr == 0 {
		return FolderResult{Error: formatHRESULT("解析文件夹路径失败", hr)}
	}
	defer procCoTaskMemFree.Call(pathPtr)

	path := utf16PtrToString((*uint16)(unsafe.Pointer(pathPtr)))
	if path == "" {
		return FolderResult{OK: false}
	}
	return FolderResult{OK: true, Path: path}
}

func comVTable(obj uintptr) *[32]uintptr {
	return *(**[32]uintptr)(unsafe.Pointer(obj))
}

func comRelease(obj uintptr) {
	vtable := comVTable(obj)
	_, _, _ = syscall.SyscallN(vtable[2], obj)
}

func succeeded(hr uintptr) bool {
	return int32(hr) >= 0
}

func failed(hr uintptr) bool {
	return int32(hr) < 0
}

func formatHRESULT(prefix string, hr uintptr) string {
	return fmt.Sprintf("%s: HRESULT 0x%08X", prefix, uint32(hr))
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	var values []uint16
	for offset := uintptr(0); ; offset += unsafe.Sizeof(*ptr) {
		value := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + offset))
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return syscall.UTF16ToString(values)
}
