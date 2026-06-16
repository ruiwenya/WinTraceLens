//go:build windows

package systemtools

import (
	"fmt"
	"syscall"
	"unsafe"
)

var shellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func Open(id string) (Tool, error) {
	tool, err := Resolve(id)
	if err != nil {
		return Tool{}, err
	}

	file, err := syscall.UTF16PtrFromString(tool.Command)
	if err != nil {
		return Tool{}, err
	}
	verb, _ := syscall.UTF16PtrFromString("open")
	ret, _, callErr := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		0,
		uintptr(1),
	)
	if ret <= 32 {
		if ret == 0 && callErr != syscall.Errno(0) {
			return Tool{}, callErr
		}
		return Tool{}, fmt.Errorf("无法启动 %s，ShellExecute 返回码 %d", tool.Command, ret)
	}
	return tool, nil
}
