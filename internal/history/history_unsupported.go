//go:build !windows

package history

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("historical communication collection is only supported on Windows")
}
