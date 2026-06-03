//go:build !windows

package process

import "runtime"

func Collect(opts Options) ([]Info, error) {
	return nil, &UnsupportedOSError{OS: runtime.GOOS}
}

func Modules(pid uint32, opts Options) ([]ModuleInfo, error) {
	return nil, &UnsupportedOSError{OS: runtime.GOOS}
}

func Connections(pid uint32) ([]ConnectionInfo, error) {
	return nil, &UnsupportedOSError{OS: runtime.GOOS}
}

func OpenFileLocation(pid uint32) error {
	return &UnsupportedOSError{OS: runtime.GOOS}
}

type UnsupportedOSError struct {
	OS string
}

func (e *UnsupportedOSError) Error() string {
	return "process collection is only supported on Windows, current OS: " + e.OS
}
