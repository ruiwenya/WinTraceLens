//go:build !windows

package memoryscan

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("memory anomaly collection is only supported on Windows")
}

func ExportRegion(pid uint32, base, size, maxSize uint64) (RegionExport, error) {
	return RegionExport{}, errors.New("memory region export is only supported on Windows")
}
