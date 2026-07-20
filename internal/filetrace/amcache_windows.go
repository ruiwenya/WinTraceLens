//go:build windows

package filetrace

import (
	"os"
	"path/filepath"
	"strings"

	amcachedata "github.com/ruiwenya/WinTraceLens/internal/amcache"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func collectNativeAmcache(opts Options, maxRecords int) ([]Record, []string, []string, bool) {
	limit := maxRecords
	if limit < 500 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	snapshot, err := amcachedata.Parse(amcachedata.Options{
		Path:                opts.AmcachePath,
		MaxApplicationFiles: limit,
		MaxDrivers:          2000,
	})
	if err != nil {
		return nil, []string{"Amcache 原生 Hive: " + err.Error()}, nil, false
	}

	records := make([]Record, 0, len(snapshot.ApplicationFiles))
	for _, item := range snapshot.ApplicationFiles {
		records = append(records, amcacheRecord(item))
	}
	warnings := make([]string, 0, len(snapshot.Warnings))
	for _, warning := range snapshot.Warnings {
		warnings = append(warnings, "Amcache 原生 Hive: "+warning)
	}
	notices := make([]string, 0, 1)
	switch snapshot.ReadMode {
	case "vss":
		notices = append(notices, "实时 Amcache Hive 被系统占用，已创建临时 VSS 卷影副本读取；解析完成后已自动删除该卷影副本。")
	case "registry-snapshot":
		notices = append(notices, "实时 Amcache Hive 被系统占用，已通过 Windows 注册表备份接口创建临时一致性快照；解析完成后已自动删除临时文件。")
	}
	return records, warnings, notices, true
}

func amcacheRecord(item amcachedata.ApplicationFile) Record {
	suspicion, reason, signature, signatureMsg := assessAmcacheRecord(item)
	details := make([]string, 0, 8)
	if item.KeyName != "" {
		details = append(details, "键="+item.KeyName)
	}
	if item.FileID != "" {
		details = append(details, "FileId="+item.FileID)
	}
	if item.BinFileVersion != "" {
		details = append(details, "文件版本="+item.BinFileVersion)
	}
	if item.OriginalName != "" {
		details = append(details, "原始文件名="+item.OriginalName)
	}
	if item.TimeMeaning != "" {
		details = append(details, item.TimeMeaning)
	}
	return Record{
		Category:       "执行痕迹",
		Source:         "Amcache Hive",
		Name:           item.Name,
		Path:           item.Path,
		Directory:      windowsDirectory(item.Path),
		Extension:      strings.ToLower(filepath.Ext(item.Name)),
		Size:           item.Size,
		Created:        item.Created,
		Modified:       item.Modified,
		Suspicion:      suspicion,
		Reason:         reason,
		Details:        strings.Join(details, "；"),
		Schema:         item.Schema,
		SHA1:           item.SHA1,
		Publisher:      item.Publisher,
		ProductName:    item.ProductName,
		ProductVersion: item.ProductVersion,
		BinaryType:     item.BinaryType,
		ProgramID:      item.ProgramID,
		Association:    item.Association,
		EvidenceTime:   item.RecordTime,
		TimeMeaning:    item.TimeMeaning,
		LinkDate:       item.LinkDate,
		Signature:      signature,
		SignatureMsg:   signatureMsg,
	}
}

func assessAmcacheRecord(item amcachedata.ApplicationFile) (string, string, string, string) {
	score := 0
	reasons := make([]string, 0, 5)
	unassociated := item.Association == "未关联" || item.Association == "关联项缺失"
	if unassociated {
		score += 3
		if item.Association == "关联项缺失" {
			reasons = append(reasons, "ProgramId 未找到对应应用清单")
		} else {
			reasons = append(reasons, "未关联到已安装应用")
		}
	}

	pathScore, pathReason := amcacheWritablePathRisk(item.Path)
	if unassociated && pathScore > 0 {
		score += pathScore
		reasons = append(reasons, pathReason)
	}
	base := strings.TrimSuffix(item.Name, filepath.Ext(item.Name))
	if unassociated && looksRandomTraceName(base) {
		score += 2
		reasons = append(reasons, "文件名疑似随机生成")
	}
	if unassociated && looksLikeDisguisedPE(item.Path, item.BinaryType) {
		score += 2
		reasons = append(reasons, "PE 类型与文件扩展名不一致")
	}

	signature, signatureMsg := "", ""
	if score >= 5 && item.Path != "" {
		if info, err := os.Stat(item.Path); err == nil && !info.IsDir() {
			result := process.CheckSignature(item.Path)
			signature, signatureMsg = result.Status, result.Message
			switch result.Status {
			case "签名异常":
				score += 3
				reasons = append(reasons, "当前文件签名异常")
			case "无签名请注意!!!":
				score += 2
				reasons = append(reasons, "当前文件无可信签名")
			}
		}
	}

	level := ""
	switch {
	case score >= 8:
		level = "高"
	case score >= 5:
		level = "中"
	}
	if level == "" {
		reasons = nil
	}
	return level, strings.Join(uniqueTraceStrings(reasons), "；"), signature, signatureMsg
}

func amcacheWritablePathRisk(path string) (int, string) {
	lower := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "/", `\`))
	switch {
	case strings.Contains(lower, `\appdata\local\temp\`), strings.Contains(lower, `\windows\temp\`), strings.Contains(lower, `\temp\`):
		return 4, "位于临时目录"
	case strings.Contains(lower, `\appdata\`):
		return 3, "位于用户 AppData 目录"
	case strings.Contains(lower, `\programdata\`):
		return 3, "位于 ProgramData 目录"
	case strings.Contains(lower, `\users\`):
		return 2, "位于用户可写目录"
	default:
		return 0, ""
	}
}

func looksLikeDisguisedPE(path, binaryType string) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(binaryType)), "pe") {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".efi":
		return false
	default:
		return strings.TrimSpace(path) != ""
	}
}

func windowsDirectory(path string) string {
	path = strings.TrimRight(strings.ReplaceAll(path, "/", `\`), `\`)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[:index]
	}
	return ""
}

func uniqueTraceStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
