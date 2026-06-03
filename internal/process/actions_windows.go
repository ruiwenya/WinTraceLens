//go:build windows

package process

import (
	"fmt"
	"os/exec"
)

func OpenFileLocation(pid uint32) error {
	path, pathErr := queryProcessPath(pid)
	if path == "" {
		if pathErr == "" {
			pathErr = "process path is empty"
		}
		return fmt.Errorf(pathErr)
	}

	return exec.Command("explorer.exe", "/select,"+path).Start()
}
