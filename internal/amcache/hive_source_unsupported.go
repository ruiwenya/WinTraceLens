//go:build !windows

package amcache

import "os"

func openHiveSource(path string) (*os.File, string, string, func(), error) {
	hive, err := os.Open(path)
	if err != nil {
		return nil, "", "", nil, err
	}
	return hive, path, "direct", func() {}, nil
}
