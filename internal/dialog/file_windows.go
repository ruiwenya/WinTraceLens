//go:build windows

package dialog

import (
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const fosFileMustExist = 0x00001000

type FileResult struct {
	OK    bool   `json:"ok"`
	Path  string `json:"path"`
	Error string `json:"error"`
}

func SelectFile(title string) FileResult {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "选择文件"
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	initialized := succeeded(hr)
	if initialized {
		defer procCoUninitialize.Call()
	} else if hr != 0x80010106 {
		return FileResult{Error: formatHRESULT("初始化文件选择器失败", hr)}
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
		return FileResult{Error: formatHRESULT("创建文件选择器失败", hr)}
	}
	defer comRelease(dialog)

	vtable := comVTable(dialog)
	options := uintptr(fosForceFileSystem | fosPathMustExist | fosFileMustExist | fosNoChangeDir)
	hr, _, _ = syscall.SyscallN(vtable[9], dialog, options)
	if failed(hr) {
		return FileResult{Error: formatHRESULT("设置文件选择器选项失败", hr)}
	}
	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err == nil {
		hr, _, _ = syscall.SyscallN(vtable[17], dialog, uintptr(unsafe.Pointer(titlePtr)))
		if failed(hr) {
			return FileResult{Error: formatHRESULT("设置文件选择器标题失败", hr)}
		}
	}

	owner, _, _ := procGetForegroundWindow.Call()
	hr, _, _ = syscall.SyscallN(vtable[3], dialog, owner)
	if uint32(hr) == hresultCancelled {
		return FileResult{OK: false}
	}
	if failed(hr) {
		return FileResult{Error: formatHRESULT("显示文件选择器失败", hr)}
	}

	var item uintptr
	hr, _, _ = syscall.SyscallN(vtable[20], dialog, uintptr(unsafe.Pointer(&item)))
	if failed(hr) || item == 0 {
		return FileResult{Error: formatHRESULT("读取已选择文件失败", hr)}
	}
	defer comRelease(item)
	itemVTable := comVTable(item)
	var pathPtr uintptr
	hr, _, _ = syscall.SyscallN(itemVTable[5], item, sigdnFileSysPath, uintptr(unsafe.Pointer(&pathPtr)))
	if failed(hr) || pathPtr == 0 {
		return FileResult{Error: formatHRESULT("解析文件路径失败", hr)}
	}
	defer procCoTaskMemFree.Call(pathPtr)
	path := utf16PtrToString((*uint16)(unsafe.Pointer(pathPtr)))
	if path == "" {
		return FileResult{OK: false}
	}
	return FileResult{OK: true, Path: path}
}
