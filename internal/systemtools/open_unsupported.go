//go:build !windows

package systemtools

import "runtime"

func Open(id string) (Tool, error) {
	tool, err := Resolve(id)
	if err != nil {
		return Tool{}, err
	}
	return Tool{}, UnsupportedError{Tool: tool, OS: runtime.GOOS}
}

type UnsupportedError struct {
	Tool Tool
	OS   string
}

func (e UnsupportedError) Error() string {
	return "系统工具打开功能仅支持 Windows，当前系统: " + e.OS
}
