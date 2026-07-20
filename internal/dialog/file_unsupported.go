//go:build !windows

package dialog

type FileResult struct {
	OK    bool   `json:"ok"`
	Path  string `json:"path"`
	Error string `json:"error"`
}

func SelectFile(title string) FileResult {
	return FileResult{Error: "当前系统不支持选择文件对话框"}
}
