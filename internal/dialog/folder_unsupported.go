//go:build !windows

package dialog

type FolderResult struct {
	OK    bool   `json:"ok"`
	Path  string `json:"path"`
	Error string `json:"error"`
}

func SelectFolder(title string) FolderResult {
	return FolderResult{Error: "当前系统不支持选择文件夹对话框"}
}
