package selfidentity

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	selfOnce   sync.Once
	selfPID    uint32
	selfPath   string
	selfPathOK bool
)

func IsSelfProcess(pid uint32, path string) bool {
	initSelf()
	if pid != selfPID {
		return false
	}
	if path == "" {
		return true
	}
	return selfPathOK && normalizePath(path) == selfPath
}

func IsSelfExecutablePath(path string) bool {
	initSelf()
	if !selfPathOK {
		return false
	}
	return normalizePath(path) == selfPath
}

func IsScannerProcessName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".exe")
	switch name {
	case "wintracelens", "wintracelens-cli":
		return true
	default:
		return false
	}
}

func initSelf() {
	selfOnce.Do(func() {
		selfPID = uint32(os.Getpid())
		exe, err := os.Executable()
		if err != nil {
			return
		}
		selfPath = normalizePath(exe)
		selfPathOK = selfPath != ""
	})
}

func normalizePath(path string) string {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	path = filepath.Clean(path)
	return strings.ToLower(strings.ReplaceAll(path, "/", `\`))
}
