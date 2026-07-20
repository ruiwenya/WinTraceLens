//go:build !windows

package process

import "fmt"

func snapshotProcessesNative() (map[uint32]string, error) {
	return nil, fmt.Errorf("unsupported platform")
}
