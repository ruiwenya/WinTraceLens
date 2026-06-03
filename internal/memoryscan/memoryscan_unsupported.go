//go:build !windows

package memoryscan

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("memory anomaly collection is only supported on Windows")
}
