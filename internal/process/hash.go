package process

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func fileMD5(path string, limitBytes int64) (string, string) {
	if path == "" {
		return "", "empty path"
	}

	stat, err := os.Stat(path)
	if err != nil {
		return "", err.Error()
	}
	if stat.IsDir() {
		return "", "path is a directory"
	}
	if limitBytes > 0 && stat.Size() > limitBytes {
		return "", fmt.Sprintf("file exceeds hash limit (%d MB)", limitBytes/1024/1024)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err.Error()
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err.Error()
	}

	return hex.EncodeToString(h.Sum(nil)), ""
}

func HashFileMD5(path string, limitBytes int64) (string, string) {
	return fileMD5(path, limitBytes)
}
