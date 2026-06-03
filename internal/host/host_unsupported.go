//go:build !windows

package host

import "runtime"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, &UnsupportedOSError{OS: runtime.GOOS}
}

type UnsupportedOSError struct {
	OS string
}

func (e *UnsupportedOSError) Error() string {
	return "host collection is only supported on Windows, current OS: " + e.OS
}
