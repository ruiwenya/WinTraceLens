//go:build windows

package registryanomaly

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

type scanRoot struct {
	hive        registry.Key
	hiveName    string
	sid         string
	path        string
	maxDepth    int
	traditional bool
	userScan    bool
}

type collector struct {
	opts     Options
	deadline time.Time
	snapshot Snapshot
	seen     map[string]struct{}
}

var traditionalRoots = []struct {
	hive registry.Key
	name string
	path string
}{
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows NT\CurrentVersion\Windows`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`},
	{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`},
	{registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager`},
	{registry.LOCAL_MACHINE, "HKLM", `SYSTEM\CurrentControlSet\Services`},
}

func Collect(opts Options) (Snapshot, error) {
	opts = normalizeOptions(opts)
	c := &collector{opts: opts, deadline: time.Now().Add(opts.Timeout), seen: make(map[string]struct{})}
	for _, root := range traditionalRoots {
		depth := 2
		if strings.HasSuffix(root.path, "Services") {
			depth = 3
		}
		c.walk(scanRoot{hive: root.hive, hiveName: root.name, path: root.path, maxDepth: depth, traditional: true}, 0)
		if c.stop() {
			break
		}
	}
	if !c.stop() {
		c.scanLoadedUsers()
	}
	c.snapshot.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	c.snapshot.CollectionErrors = uniqueStrings(c.snapshot.CollectionErrors)
	sort.SliceStable(c.snapshot.Records, func(i, j int) bool {
		if c.snapshot.Records[i].Score != c.snapshot.Records[j].Score {
			return c.snapshot.Records[i].Score > c.snapshot.Records[j].Score
		}
		return strings.ToLower(c.snapshot.Records[i].KeyPath) < strings.ToLower(c.snapshot.Records[j].KeyPath)
	})
	return c.snapshot, nil
}

func (c *collector) scanLoadedUsers() {
	names, err := registry.USERS.ReadSubKeyNames(-1)
	if err != nil {
		c.snapshot.CollectionErrors = append(c.snapshot.CollectionErrors, "枚举 HKEY_USERS 失败: "+err.Error())
		return
	}
	for _, sid := range names {
		if !strings.HasPrefix(sid, "S-1-5-") || strings.HasSuffix(strings.ToLower(sid), "_classes") {
			continue
		}
		c.walk(scanRoot{hive: registry.USERS, hiveName: "HKU", sid: sid, path: sid + `\Software`, maxDepth: c.opts.MaxDepth, userScan: true}, 0)
		if c.stop() {
			return
		}
	}
}

func (c *collector) walk(root scanRoot, depth int) {
	if c.stop() || depth > root.maxDepth {
		return
	}
	keyID := strings.ToLower(root.hiveName + `\` + root.path)
	if _, ok := c.seen[keyID]; ok {
		return
	}
	c.seen[keyID] = struct{}{}
	key, err := registry.OpenKey(root.hive, root.path, registry.READ)
	if err != nil {
		if depth == 0 && !errors.Is(err, registry.ErrNotExist) {
			c.snapshot.CollectionErrors = append(c.snapshot.CollectionErrors, root.hiveName+`\`+root.path+": "+err.Error())
		}
		return
	}
	defer key.Close()
	c.snapshot.ScannedKeys++
	info, _ := key.Stat()
	var modified time.Time
	if info != nil {
		modified = info.ModTime()
	}
	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			if c.stop() {
				return
			}
			c.snapshot.ScannedValues++
			data, valueType, size, truncated, readErr := readRegistryValue(key, name, c.opts.MaxDataSize)
			if readErr != nil {
				continue
			}
			evidence := valueEvidence{
				hive: root.hiveName, sid: root.sid, keyPath: root.path, valueName: name,
				valueType: valueType, dataLength: size, lastWrite: modified, data: data,
				truncated: truncated, traditional: root.traditional, nonTraditional: root.userScan,
			}
			if record, ok := analyzeValue(evidence); ok {
				c.snapshot.Records = append(c.snapshot.Records, record)
			}
		}
	}
	if depth >= root.maxDepth || c.stop() {
		return
	}
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, subkey := range subkeys {
		if shouldSkipUserSubtree(root, depth, subkey) {
			continue
		}
		next := root
		next.path = root.path + `\` + subkey
		c.walk(next, depth+1)
		if c.stop() {
			return
		}
	}
}

func (c *collector) stop() bool {
	if time.Now().After(c.deadline) || c.snapshot.ScannedKeys >= c.opts.MaxKeys || c.snapshot.ScannedValues >= c.opts.MaxValues || len(c.snapshot.Records) >= c.opts.MaxRecords {
		c.snapshot.Truncated = true
		return true
	}
	return false
}

func shouldSkipUserSubtree(root scanRoot, depth int, name string) bool {
	if !root.userScan {
		return false
	}
	lower := strings.ToLower(name)
	if depth == 0 && (lower == "classes" || lower == "microsoft") {
		return false
	}
	return lower == "installer" || lower == "package repository" || lower == "component based servicing"
}

func readRegistryValue(key registry.Key, name string, limit int) ([]byte, uint32, int, bool, error) {
	size, valueType, err := key.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return nil, valueType, 0, false, err
	}
	if size < 0 {
		return nil, valueType, 0, false, fmt.Errorf("无效注册表数据长度")
	}
	readSize := size
	truncated := false
	if readSize > limit {
		readSize = limit
		truncated = true
	}
	if readSize == 0 {
		return nil, valueType, size, false, nil
	}
	buffer := make([]byte, readSize)
	n, actualType, err := key.GetValue(name, buffer)
	if err != nil {
		if err == syscall.ERROR_MORE_DATA && truncated {
			return buffer, actualType, size, true, nil
		}
		return nil, actualType, size, truncated, err
	}
	if n < len(buffer) {
		buffer = buffer[:n]
	}
	return buffer, actualType, size, truncated, nil
}

func ReadExportValue(ref ExportReference, maxSize int) ([]byte, uint32, time.Time, error) {
	var hive registry.Key
	switch strings.ToUpper(ref.Hive) {
	case "HKCU":
		hive = registry.CURRENT_USER
	case "HKLM":
		hive = registry.LOCAL_MACHINE
	case "HKU":
		hive = registry.USERS
	default:
		return nil, 0, time.Time{}, fmt.Errorf("不支持的注册表 Hive")
	}
	key, err := registry.OpenKey(hive, ref.KeyPath, registry.READ)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	defer key.Close()
	if maxSize <= 0 {
		maxSize = 32 * 1024 * 1024
	}
	data, valueType, size, truncated, err := readRegistryValue(key, ref.ValueName, maxSize)
	if err != nil {
		return nil, valueType, time.Time{}, err
	}
	if truncated || size > maxSize {
		return nil, valueType, time.Time{}, fmt.Errorf("注册表值超过导出上限 %s", byteSize(maxSize))
	}
	info, _ := key.Stat()
	var modified time.Time
	if info != nil {
		modified = info.ModTime()
	}
	return data, valueType, modified, nil
}
