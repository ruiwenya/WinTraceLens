//go:build !windows

package runtimeinfo

func adminStatus() (bool, bool) {
	return false, false
}

func compatibilitySummary() string {
	return "基础版主要面向 Windows，本平台仅用于开发或接口验证。"
}
