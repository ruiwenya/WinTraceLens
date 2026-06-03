//go:build !windows

package loghealth

import "errors"

func Collect() (Snapshot, error) {
	return Snapshot{}, errors.New("log source health check is only supported on Windows")
}
