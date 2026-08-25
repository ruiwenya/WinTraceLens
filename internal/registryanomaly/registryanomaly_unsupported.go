//go:build !windows

package registryanomaly

import (
	"errors"
	"time"
)

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("注册表异常采集仅支持 Windows")
}
func ReadExportValue(ref ExportReference, maxSize int) ([]byte, uint32, time.Time, error) {
	return nil, 0, time.Time{}, errors.New("注册表值导出仅支持 Windows")
}
