//go:build windows

package runtimeinfo

import "syscall"

func adminStatus() (bool, bool) {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	if err := isUserAnAdmin.Find(); err != nil {
		return false, false
	}
	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0, true
}

func compatibilitySummary() string {
	return "Windows 10/11 与 Windows Server 2016+ 推荐；Windows 7/Server 2008 R2 需使用兼容构建链，部分日志能力可能降级。"
}
