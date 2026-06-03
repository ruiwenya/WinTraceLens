//go:build !windows

package filetrace

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("file trace collection is only supported on Windows")
}
