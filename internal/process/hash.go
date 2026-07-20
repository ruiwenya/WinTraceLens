package process

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

func fileMD5(path string, limitBytes int64) (string, string) {
	if path == "" {
		return "", "路径为空，无法计算 MD5"
	}

	stat, err := os.Stat(path)
	if err != nil {
		return "", friendlyFileError(err)
	}
	if stat.IsDir() {
		return "", "目标是目录，无法计算 MD5"
	}
	if limitBytes > 0 && stat.Size() > limitBytes {
		return "", fmt.Sprintf("文件超过哈希计算限制（%d MB）", limitBytes/1024/1024)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", friendlyFileError(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", friendlyFileError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), ""
}

func HashFileMD5(path string, limitBytes int64) (string, string) {
	return fileMD5(path, limitBytes)
}

func friendlyFileError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrNotExist) {
		return "文件不存在，可能已被删除或仅为内存/虚拟模块"
	}
	if errors.Is(err, os.ErrPermission) {
		return "权限不足，无法读取文件"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 2:
			return "文件不存在，可能已被删除或仅为内存/虚拟模块"
		case 3:
			return "路径不存在，无法读取文件"
		case 5:
			return "权限不足，无法读取文件"
		case 31:
			return "系统设备路径无法通过常规接口读取"
		case 32:
			return "文件正在被其他进程占用，无法读取"
		case 87:
			return "系统接口参数无效，无法读取文件"
		}
	}
	text := err.Error()
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "a device attached to the system is not functioning"):
		return "系统设备路径无法通过常规接口读取"
	case strings.Contains(lower, "access is denied"):
		return "权限不足，无法读取文件"
	case strings.Contains(lower, "cannot find the file") || strings.Contains(lower, "cannot find the path"):
		return "文件或路径不存在，可能已被删除"
	}
	return text
}
