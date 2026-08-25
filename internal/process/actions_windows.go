//go:build windows

package process

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var processShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func OpenFileLocation(pid uint32) error {
	path, pathErr := queryProcessPath(pid)
	if path == "" {
		if pathErr == "" {
			pathErr = "process path is empty"
		}
		return errors.New(pathErr)
	}

	target, err := normalizeExplorerTarget(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("无法打开文件位置：目标文件已不存在：%s", target)
		}
		return fmt.Errorf("无法打开文件位置：无法访问目标文件 %s：%w", target, err)
	}

	return shellOpenExplorerSelection(target)
}

func normalizeExplorerTarget(rawPath string) (string, error) {
	path := strings.TrimSpace(rawPath)
	if len(path) >= 2 && path[0] == '"' && path[len(path)-1] == '"' {
		path = strings.TrimSpace(path[1 : len(path)-1])
	}
	if path == "" {
		return "", fmt.Errorf("无法打开文件位置：进程路径为空")
	}

	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("无法打开文件位置：进程路径不是绝对路径：%s", path)
	}
	return path, nil
}

func explorerSelectParameters(path string) string {
	return `/select,"` + path + `"`
}

func shellOpenExplorerSelection(path string) error {
	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString("explorer.exe")
	if err != nil {
		return err
	}
	parameters, err := syscall.UTF16PtrFromString(explorerSelectParameters(path))
	if err != nil {
		return err
	}

	ret, _, callErr := processShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(parameters)),
		0,
		uintptr(1),
	)
	if ret <= 32 {
		if ret == 0 && callErr != syscall.Errno(0) {
			return fmt.Errorf("无法启动文件资源管理器：%w", callErr)
		}
		return fmt.Errorf("无法启动文件资源管理器，ShellExecute 返回码 %d", ret)
	}
	return nil
}
