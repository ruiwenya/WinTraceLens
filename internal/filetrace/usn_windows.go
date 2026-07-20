//go:build windows

package filetrace

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fsctlQueryUSNJournal = 0x000900f4
	fsctlReadUSNJournal  = 0x000900bb
	usnReasonAll         = 0xffffffff
)

type usnJournalDataV0 struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readUSNJournalDataV0 struct {
	StartUSN          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	JournalID         uint64
}

func collectNTFSArtifacts(roots []string, maxRecords int) ([]Record, []string) {
	volumes := traceVolumes(roots)
	records := make([]Record, 0, maxRecords+len(volumes))
	warnings := make([]string, 0, len(volumes))
	perVolume := maxRecords
	if len(volumes) > 0 {
		perVolume = maxRecords / len(volumes)
	}
	if perVolume < 100 {
		perVolume = 100
	}
	for _, volume := range volumes {
		records = append(records, Record{
			Category:  "NTFS 元数据",
			Source:    "MFT 证据定位",
			Name:      "$MFT",
			Path:      volume + `\$MFT`,
			Directory: volume + `\`,
			Details:   "NTFS 主文件表原始证据位置；在线模式不直接解析或复制锁定中的 $MFT，建议导出卷镜像后使用专用解析器核验。",
		})
		items, err := readUSNJournal(volume, perVolume)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("USN Journal %s: %v", volume, err))
			continue
		}
		records = append(records, items...)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return recordTimestamp(records[i]).After(recordTimestamp(records[j]))
	})
	return records, warnings
}

func traceVolumes(roots []string) []string {
	seen := make(map[string]bool)
	volumes := make([]string, 0, len(roots)+1)
	add := func(value string) {
		volume := strings.TrimSuffix(filepath.VolumeName(strings.TrimSpace(value)), `\`)
		if len(volume) != 2 || volume[1] != ':' {
			return
		}
		volume = strings.ToUpper(volume)
		if !seen[volume] {
			seen[volume] = true
			volumes = append(volumes, volume)
		}
	}
	for _, root := range roots {
		add(root)
	}
	if len(volumes) == 0 {
		add(os.Getenv("SystemDrive") + `\`)
	}
	if len(volumes) == 0 {
		add(`C:\`)
	}
	return volumes
}

func readUSNJournal(volume string, maxRecords int) ([]Record, error) {
	device, err := syscall.UTF16PtrFromString(`\\.\` + volume)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		device,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("无法打开卷，请使用管理员权限运行: %w", err)
	}
	defer windows.CloseHandle(handle)

	var journal usnJournalDataV0
	var returned uint32
	err = windows.DeviceIoControl(
		handle,
		fsctlQueryUSNJournal,
		nil,
		0,
		(*byte)(unsafe.Pointer(&journal)),
		uint32(unsafe.Sizeof(journal)),
		&returned,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("USN Journal 不可用或未启用: %w", err)
	}

	start := journal.NextUSN - 64*1024*1024
	if start < journal.FirstUSN {
		start = journal.FirstUSN
	}
	query := readUSNJournalDataV0{
		StartUSN:   start,
		ReasonMask: usnReasonAll,
		JournalID:  journal.JournalID,
	}
	buffer := make([]byte, 1024*1024)
	records := make([]Record, 0, maxRecords)
	for len(records) < maxRecords && query.StartUSN < journal.NextUSN {
		returned = 0
		err = windows.DeviceIoControl(
			handle,
			fsctlReadUSNJournal,
			(*byte)(unsafe.Pointer(&query)),
			uint32(unsafe.Sizeof(query)),
			&buffer[0],
			uint32(len(buffer)),
			&returned,
			nil,
		)
		if err != nil {
			return records, fmt.Errorf("读取 USN Journal 失败: %w", err)
		}
		if returned <= 8 {
			break
		}
		next := int64(binary.LittleEndian.Uint64(buffer[:8]))
		for offset := 8; offset+60 <= int(returned) && len(records) < maxRecords; {
			recordLength := int(binary.LittleEndian.Uint32(buffer[offset : offset+4]))
			if recordLength < 60 || offset+recordLength > int(returned) {
				break
			}
			if item, ok := parseUSNRecord(volume, buffer[offset:offset+recordLength]); ok {
				records = append(records, item)
			}
			offset += recordLength
		}
		if next <= query.StartUSN {
			break
		}
		query.StartUSN = next
	}
	return records, nil
}

func parseUSNRecord(volume string, data []byte) (Record, bool) {
	if len(data) < 60 || binary.LittleEndian.Uint16(data[4:6]) != 2 {
		return Record{}, false
	}
	nameLength := int(binary.LittleEndian.Uint16(data[56:58]))
	nameOffset := int(binary.LittleEndian.Uint16(data[58:60]))
	if nameLength <= 0 || nameOffset < 60 || nameOffset+nameLength > len(data) || nameLength%2 != 0 {
		return Record{}, false
	}
	units := make([]uint16, nameLength/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[nameOffset+i*2:])
	}
	name := strings.TrimSpace(string(utf16.Decode(units)))
	if name == "" {
		return Record{}, false
	}
	fileReference := binary.LittleEndian.Uint64(data[8:16])
	parentReference := binary.LittleEndian.Uint64(data[16:24])
	usn := int64(binary.LittleEndian.Uint64(data[24:32]))
	stamp := fileTimeString(int64(binary.LittleEndian.Uint64(data[32:40])))
	reason := binary.LittleEndian.Uint32(data[40:44])
	reasonText := usnReasonText(reason)
	level, riskReason := usnSuspicion(name, reason)
	return Record{
		Category:  "NTFS 变更痕迹",
		Source:    "USN Journal",
		Name:      name,
		Path:      fmt.Sprintf(`%s\[FRN 0x%X]\%s`, volume, fileReference, name),
		Directory: volume + `\`,
		Extension: filepath.Ext(name),
		Modified:  stamp,
		Suspicion: level,
		Reason:    riskReason,
		Details: fmt.Sprintf(
			"USN=%d；原因=%s；ParentFRN=0x%X；路径中的 FRN 仅为文件引用号，不代表已还原完整父目录。",
			usn,
			reasonText,
			parentReference,
		),
	}, true
}

func fileTimeString(value int64) string {
	const windowsToUnixTicks = 116444736000000000
	if value <= windowsToUnixTicks {
		return ""
	}
	stamp := time.Unix(0, (value-windowsToUnixTicks)*100).Local()
	if stamp.Year() < 2000 || stamp.Year() > 2200 {
		return ""
	}
	return stamp.Format("2006-01-02 15:04:05")
}

func usnReasonText(reason uint32) string {
	values := make([]string, 0, 8)
	labels := []struct {
		mask uint32
		name string
	}{
		{0x00000100, "创建"},
		{0x00000200, "删除"},
		{0x00000001, "数据覆盖"},
		{0x00000002, "数据扩展"},
		{0x00001000, "重命名前"},
		{0x00002000, "重命名后"},
		{0x00008000, "基本信息变更"},
		{0x80000000, "关闭"},
	}
	for _, label := range labels {
		if reason&label.mask != 0 {
			values = append(values, label.name)
		}
	}
	if len(values) == 0 {
		return fmt.Sprintf("0x%08X", reason)
	}
	return strings.Join(values, "/")
}

func usnSuspicion(name string, reason uint32) (string, string) {
	extension := strings.ToLower(filepath.Ext(name))
	if !strings.Contains("|.exe|.dll|.sys|.scr|.com|.bat|.cmd|.ps1|.vbs|.js|.hta|", "|"+extension+"|") {
		return "", ""
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if looksRandomTraceName(base) {
		return "中", "USN 记录中的可执行文件名疑似随机；需结合完整路径、签名和时间线核查"
	}
	if reason&0x00000200 != 0 {
		return "中", "可执行文件出现删除记录；需核查是否为落地后自删除"
	}
	return "", ""
}

func looksRandomTraceName(value string) bool {
	if len(value) < 12 {
		return false
	}
	alnum := 0
	digits := 0
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			alnum++
		case r >= '0' && r <= '9':
			alnum++
			digits++
		}
	}
	return alnum == len(value) && digits >= 2
}

func recordTimestamp(item Record) time.Time {
	for _, value := range []string{item.LastRun, item.EvidenceTime, item.Modified, item.Created, item.Accessed} {
		if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.Local); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
