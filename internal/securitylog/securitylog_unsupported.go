//go:build !windows

package securitylog

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("security event collection is only supported on Windows")
}
