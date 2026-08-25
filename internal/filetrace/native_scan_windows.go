//go:build windows

package filetrace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

const (
	fileAttributeHidden       = 0x2
	fileAttributeSystem       = 0x4
	fileAttributeReparsePoint = 0x400
	nativeHeadLimit           = 512 * 1024
	nativeTailLimit           = 64 * 1024
)

type nativeScanRoot struct {
	path  string
	depth int
}

var (
	riskyFileExtensions    = map[string]bool{".exe": true, ".dll": true, ".scr": true, ".com": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".msi": true, ".sys": true}
	randomFileNamePattern  = regexp.MustCompile(`(?i)^[a-z0-9]{12,}$`)
	scriptIndicatorPattern = regexp.MustCompile(`(?i)\b(sc(?:\.exe)?\s+(?:create|start|config)|schtasks(?:\.exe)?|powershell(?:\.exe)?\s+-(?:e|en|enc|encodedcommand)\b|\biex\b|downloadstring|invoke-webrequest|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|wmic(?:\.exe)?|taskkill(?:\.exe)?)\b`)
	serviceCommandPattern  = regexp.MustCompile(`(?i)\bsc(?:\.exe)?\s+(?:start|create|config)\s+["']?([A-Za-z0-9_.-]{2,128})`)
)

// CollectNative runs only the bounded Go-native landing-file scanner. It is
// used by focused correlations that should not invoke the full PowerShell and
// traditional-artifact pipeline.
func CollectNative(opts Options) (Snapshot, error) {
	limit := opts.MaxRecords
	if limit <= 0 {
		limit = 500
	}
	records, warnings := collectNativeLandingFiles(opts, limit)
	return Snapshot{
		Records: records, CollectionErrors: warnings,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}, nil
}

func collectNativeLandingFiles(opts Options, limit int) ([]Record, []string) {
	if limit <= 0 {
		limit = 300
	}
	if limit > 1200 {
		limit = 1200
	}
	hours := opts.Hours
	if hours <= 0 {
		hours = 72
	}
	deadline := time.Now().Add(10 * time.Second)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	roots := nativeLandingRoots(opts.ModifiedRoots)
	records := make([]Record, 0, limit)
	warnings := make([]string, 0)
	seen := make(map[string]struct{})
	filesSeen := 0
	for _, root := range roots {
		if len(records) >= limit || time.Now().After(deadline) || filesSeen >= 30000 {
			break
		}
		root = normalizeNativeRoot(root)
		if root.path == "" {
			continue
		}
		rootDepth := pathDepth(root.path)
		err := filepath.WalkDir(root.path, func(path string, entry os.DirEntry, walkErr error) error {
			if time.Now().After(deadline) || len(records) >= limit || filesSeen >= 30000 {
				return filepath.SkipAll
			}
			if walkErr != nil {
				return nil
			}
			depth := pathDepth(path) - rootDepth
			if entry.IsDir() {
				if depth > root.depth || isReparsePoint(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if depth > root.depth || isReparsePoint(path) {
				return nil
			}
			filesSeen++
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			key := strings.ToLower(filepath.Clean(path))
			if _, ok := seen[key]; ok {
				return nil
			}
			seen[key] = struct{}{}
			if strings.EqualFold(filepath.Base(path), "desktop.ini") {
				if item, ok := inspectDesktopINI(path, info); ok {
					records = append(records, item)
					if len(records) >= limit {
						return filepath.SkipAll
					}
				}
			}
			if opts.ArtifactsOnly || info.ModTime().Before(since) {
				return nil
			}
			if item, ok := inspectLandingFile(path, info); ok {
				records = append(records, item)
			}
			return nil
		})
		if err != nil && err != filepath.SkipAll {
			warnings = append(warnings, "Go 原生落地点扫描 "+root.path+": "+err.Error())
		}
	}
	if time.Now().After(deadline) {
		warnings = append(warnings, "Go 原生落地点扫描达到 10 秒时间上限，已保留当前结果")
	}
	if filesSeen >= 30000 {
		warnings = append(warnings, "Go 原生落地点扫描达到 30000 个文件上限，已保留当前结果")
	}
	sort.SliceStable(records, func(i, j int) bool {
		if suspicionRank(records[i].Suspicion) != suspicionRank(records[j].Suspicion) {
			return suspicionRank(records[i].Suspicion) > suspicionRank(records[j].Suspicion)
		}
		return records[i].Modified > records[j].Modified
	})
	return records, warnings
}

func inspectDesktopINI(path string, info os.FileInfo) (Record, bool) {
	reasons := make([]string, 0, 8)
	score := 0
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		programData = `C:\ProgramData`
	}
	programDataRoot := strings.EqualFold(filepath.Clean(path), filepath.Join(programData, "desktop.ini"))
	if info.Size() == 0 {
		if programDataRoot {
			add(8, "ProgramData 根目录存在零字节 desktop.ini")
		} else {
			add(3, "desktop.ini 为零字节文件")
		}
		return desktopINIRecord(path, info, score, reasons, "空文件", "", 0), true
	}

	file, err := os.Open(path)
	if err != nil {
		return Record{}, false
	}
	defer file.Close()
	readLimit := info.Size()
	if readLimit > 1024*1024 {
		readLimit = 1024 * 1024
	}
	raw := make([]byte, int(readLimit))
	n, err := io.ReadFull(file, raw)
	if err != nil && err != io.ErrUnexpectedEOF {
		return Record{}, false
	}
	raw = raw[:n]
	text, encoding := decodeDesktopINI(raw)
	lower := strings.ToLower(text)
	hasShellClass := strings.Contains(lower, "[.shellclassinfo]") || strings.Contains(lower, "[shellclassinfo]")
	hasShellAnchor := hasShellClass && (strings.Contains(lower, "localizedresourcename=") || strings.Contains(lower, "iconresource=") || strings.Contains(lower, "iconfile="))
	invalidLines := invalidINILines(text)
	trailingWhitespace := trailingWhitespaceRunes(text)
	lineLengths := trailingWhitespaceLineLengths(text)

	if info.Size() > 2048 {
		add(3, fmt.Sprintf("desktop.ini 体积异常（%d 字节）", info.Size()))
	}
	if !hasShellClass {
		add(3, "缺少 ShellClassInfo 节，结构不像常规 desktop.ini")
	}
	if len(invalidLines) > 0 {
		add(3, "存在不符合 INI 键值结构的非空内容")
	}
	if hasShellAnchor && trailingWhitespace >= 64 {
		add(5, fmt.Sprintf("常规 ShellClassInfo 配置后存在 %d 个连续空白或控制字符", trailingWhitespace))
	}
	if len(lineLengths) >= 3 {
		add(4, "尾部存在多行异常长度的纯空白内容，可能用于编码数据")
	}
	if programDataRoot {
		add(2, "文件位于 ProgramData 根目录")
	}
	if score < 3 {
		return Record{}, false
	}
	details := fmt.Sprintf("编码=%s；ShellClassInfo=%t；结构锚点=%t；尾部连续空白=%d 字符；异常空白行长度=%v；INI异常行=%d",
		encoding, hasShellClass, hasShellAnchor, trailingWhitespace, lineLengths, len(invalidLines))
	return desktopINIRecord(path, info, score, reasons, encoding, details, fileEntropy(raw)), true
}

func desktopINIRecord(path string, info os.FileInfo, score int, reasons []string, encoding, details string, entropy float64) Record {
	level := "低"
	if score >= 8 {
		level = "高"
	} else if score >= 5 {
		level = "中"
	}
	sha, hashErr := fileSHA256(path, 16*1024*1024)
	if hashErr != "" {
		reasons = append(reasons, "SHA-256: "+hashErr)
	}
	if details == "" {
		details = "编码=" + encoding
	}
	return Record{
		Category: "文件结构异常", Source: "敏感文件结构校验", Name: filepath.Base(path), Path: path, Directory: filepath.Dir(path), Extension: ".ini",
		Size: info.Size(), Created: formatNativeTime(fileCreationTime(info)), Modified: formatNativeTime(info.ModTime()), Accessed: formatNativeTime(fileAccessTime(info)),
		Suspicion: level, Reason: strings.Join(uniqueNativeStrings(reasons), "；"), Details: fmt.Sprintf("评分=%d；%s", score, details),
		SHA256: sha, Magic: "INI/" + encoding, Entropy: math.Round(entropy*100) / 100, Attributes: fileAttributes(path),
	}
}

func decodeDesktopINI(raw []byte) (string, string) {
	if len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
		return decodeUTF16Bytes(raw[2:], false), "UTF-16LE"
	}
	if len(raw) >= 2 && raw[0] == 0xfe && raw[1] == 0xff {
		return decodeUTF16Bytes(raw[2:], true), "UTF-16BE"
	}
	if looksLikeUTF16LE(raw) {
		return decodeUTF16Bytes(raw, false), "UTF-16LE（无 BOM）"
	}
	if len(raw) >= 3 && bytes.Equal(raw[:3], []byte{0xef, 0xbb, 0xbf}) {
		return string(raw[3:]), "UTF-8 BOM"
	}
	return string(raw), "ANSI/UTF-8"
}

func decodeUTF16Bytes(raw []byte, bigEndian bool) string {
	values := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		value := uint16(raw[i]) | uint16(raw[i+1])<<8
		if bigEndian {
			value = uint16(raw[i])<<8 | uint16(raw[i+1])
		}
		values = append(values, value)
	}
	return string(utf16.Decode(values))
}

func looksLikeUTF16LE(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	checked, zeros := 0, 0
	for i := 1; i < len(raw) && checked < 256; i += 2 {
		checked++
		if raw[i] == 0 {
			zeros++
		}
	}
	return checked > 0 && zeros*100/checked >= 60
}

func invalidINILines(value string) []string {
	invalid := make([]string, 0)
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		if strings.Contains(line, "=") {
			continue
		}
		invalid = append(invalid, limitedText(line, 80))
		if len(invalid) >= 5 {
			break
		}
	}
	return invalid
}

func trailingWhitespaceRunes(value string) int {
	count := 0
	for _, r := range reverseRunes(value) {
		if !unicode.IsSpace(r) && !unicode.IsControl(r) {
			break
		}
		count++
	}
	return count
}

func trailingWhitespaceLineLengths(value string) []int {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	lengths := make([]int, 0, 12)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSuffix(lines[i], "\r")
		if strings.TrimSpace(line) != "" {
			break
		}
		length := len([]rune(line))
		if length >= 8 {
			lengths = append(lengths, length)
		}
		if len(lengths) >= 12 {
			break
		}
	}
	for left, right := 0, len(lengths)-1; left < right; left, right = left+1, right-1 {
		lengths[left], lengths[right] = lengths[right], lengths[left]
	}
	return lengths
}

func reverseRunes(value string) []rune {
	runes := []rune(value)
	for left, right := 0, len(runes)-1; left < right; left, right = left+1, right-1 {
		runes[left], runes[right] = runes[right], runes[left]
	}
	return runes
}

func limitedText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func nativeLandingRoots(custom []string) []nativeScanRoot {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	users := filepath.Join(filepath.VolumeName(root)+`\`, "Users")
	items := []nativeScanRoot{{root, 0}, {filepath.Join(root, "Temp"), 4}, {programData, 3}, {filepath.Join(users, "Public"), 4}}
	profiles, _ := os.ReadDir(users)
	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}
		base := filepath.Join(users, profile.Name())
		items = append(items,
			nativeScanRoot{filepath.Join(base, "AppData", "Roaming"), 3}, nativeScanRoot{filepath.Join(base, "AppData", "Local"), 2},
			nativeScanRoot{filepath.Join(base, "AppData", "Local", "Temp"), 5}, nativeScanRoot{filepath.Join(base, "Downloads"), 3}, nativeScanRoot{filepath.Join(base, "Desktop"), 3},
			nativeScanRoot{filepath.Join(base, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), 3},
		)
	}
	items = append(items, nativeScanRoot{filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), 3})
	for _, path := range custom {
		items = append(items, nativeScanRoot{path, 5})
	}
	return items
}

func normalizeNativeRoot(root nativeScanRoot) nativeScanRoot {
	root.path = strings.Trim(strings.TrimSpace(root.path), `"'`)
	if root.path == "" {
		return nativeScanRoot{}
	}
	clean, err := filepath.Abs(root.path)
	if err != nil {
		return nativeScanRoot{}
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return nativeScanRoot{}
	}
	root.path = filepath.Clean(clean)
	return root
}

func inspectLandingFile(path string, info os.FileInfo) (Record, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	attributes := fileAttributes(path)
	head, tail, err := readFileEdges(path, info.Size())
	if err != nil {
		return Record{}, false
	}
	magic := detectMagic(head)
	reasons := make([]string, 0, 10)
	score := 0
	add := func(points int, reason string) { score += points; reasons = append(reasons, reason) }
	if writableFileLocation(path) {
		add(2, "位于用户可写或公共落地点")
	}
	if time.Since(info.ModTime()) >= 0 && time.Since(info.ModTime()) <= 24*time.Hour {
		add(1, "文件在最近 24 小时内写入")
	}
	if riskyFileExtensions[ext] {
		add(2, "可执行文件或脚本扩展名")
	}
	if randomFileName(base) {
		add(1, "文件名疑似随机")
	}
	if strings.Contains(attributes, "隐藏") || strings.Contains(attributes, "系统") {
		add(1, "文件带隐藏或系统属性")
	}
	hiddenPE := len(head) >= 2 && string(head[:2]) == "MZ" && ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".com"
	if hiddenPE {
		add(4, "扩展名与内容不一致，文件内部为 PE")
	}
	if imageTrailingData(ext, tail, info.Size()) {
		add(3, "图片结束标记后存在大量尾随数据")
	}
	entropy := fileEntropy(head)
	if len(head) >= 4096 && entropy >= 7.30 {
		add(2, fmt.Sprintf("文件头样本熵较高（%.2f）", entropy))
	}
	content := safeScriptText(head)
	relatedServices := serviceReferences(content)
	if scriptIndicatorPattern.MatchString(content) {
		add(2, "脚本包含持久化、下载或系统执行命令")
	}
	if len(relatedServices) > 0 {
		add(2, "脚本直接创建、配置或启动服务")
	}
	var signature process.SignatureResult
	if magic == "PE" {
		signature = process.CheckSignature(path)
		if signature.Status == "无签名请注意!!!" {
			add(2, "PE 文件无可信签名")
		}
		if signature.Status == "签名异常" {
			add(3, "PE 文件签名异常")
		}
	}
	if score < 3 {
		return Record{}, false
	}
	sha, hashErr := fileSHA256(path, 64*1024*1024)
	if hashErr != "" {
		reasons = append(reasons, "SHA-256: "+hashErr)
	}
	level := "低"
	if score >= 8 {
		level = "高"
	} else if score >= 5 {
		level = "中"
	}
	return Record{
		Category: "可疑落地文件", Source: "Go 原生落地点扫描", Name: filepath.Base(path), Path: path, Directory: filepath.Dir(path), Extension: ext, Size: info.Size(),
		Created: formatNativeTime(fileCreationTime(info)), Modified: formatNativeTime(info.ModTime()), Accessed: formatNativeTime(fileAccessTime(info)), Suspicion: level,
		Reason: strings.Join(uniqueNativeStrings(reasons), "；"), Details: fmt.Sprintf("评分=%d；Magic=%s；属性=%s", score, magic, attributes), SHA256: sha, Magic: magic,
		Entropy: math.Round(entropy*100) / 100, Attributes: attributes, RelatedServices: relatedServices, Signature: signature.Status, SignatureMsg: signature.Message,
	}, true
}

func readFileEdges(path string, size int64) ([]byte, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	headSize := int64(nativeHeadLimit)
	if size < headSize {
		headSize = size
	}
	head := make([]byte, int(headSize))
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, nil, err
	}
	head = head[:n]
	tail := head
	if size > nativeTailLimit {
		tail = make([]byte, nativeTailLimit)
		n, err = file.ReadAt(tail, size-nativeTailLimit)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		tail = tail[:n]
	}
	return head, tail, nil
}
func detectMagic(data []byte) string {
	if len(data) >= 2 && string(data[:2]) == "MZ" {
		return "PE"
	}
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		return "PNG"
	}
	if len(data) >= 3 && bytes.Equal(data[:3], []byte{0xff, 0xd8, 0xff}) {
		return "JPEG"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) {
		return "ZIP"
	}
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "PE"
	}
	return "未知/文本"
}
func imageTrailingData(ext string, tail []byte, size int64) bool {
	if size < 2048 {
		return false
	}
	if ext == ".jpg" || ext == ".jpeg" {
		idx := bytes.LastIndex(tail, []byte{0xff, 0xd9})
		return idx >= 0 && len(tail)-(idx+2) > 1024
	}
	if ext == ".png" {
		idx := bytes.LastIndex(tail, []byte("IEND"))
		return idx >= 0 && len(tail)-(idx+8) > 1024
	}
	return false
}
func safeScriptText(data []byte) string {
	if len(data) > nativeHeadLimit {
		data = data[:nativeHeadLimit]
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			return r
		}
		return ' '
	}, string(data))
}
func serviceReferences(text string) []string {
	matches := serviceCommandPattern.FindAllStringSubmatch(text, 20)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			out = append(out, match[1])
		}
	}
	return uniqueNativeStrings(out)
}
func randomFileName(value string) bool {
	if len(value) < 12 || !randomFileNamePattern.MatchString(value) {
		return false
	}
	letters, digits := 0, 0
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letters++
		}
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return letters > 0 && digits > 0
}
func writableFileLocation(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{`\users\`, `\appdata\`, `\temp\`, `\programdata\`, `\public\`, `\downloads\`, `\desktop\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func fileAttributes(path string) string {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return ""
	}
	parts := []string{}
	if attrs&fileAttributeHidden != 0 {
		parts = append(parts, "隐藏")
	}
	if attrs&fileAttributeSystem != 0 {
		parts = append(parts, "系统")
	}
	if attrs&fileAttributeReparsePoint != 0 {
		parts = append(parts, "重解析点")
	}
	if len(parts) == 0 {
		return "普通"
	}
	return strings.Join(parts, "|")
}
func isReparsePoint(path string) bool { return strings.Contains(fileAttributes(path), "重解析点") }
func fileEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var out float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		out -= p * math.Log2(p)
	}
	return out
}
func fileSHA256(path string, limit int64) (string, string) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err.Error()
	}
	if limit > 0 && info.Size() > limit {
		return "", fmt.Sprintf("文件超过 %d MB 哈希上限", limit/1024/1024)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err.Error()
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err.Error()
	}
	return hex.EncodeToString(hash.Sum(nil)), ""
}
func pathDepth(path string) int {
	return len(strings.FieldsFunc(filepath.Clean(path), func(r rune) bool { return r == '\\' || r == '/' }))
}
func formatNativeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Local().Format("2006-01-02 15:04:05")
}
func fileCreationTime(info os.FileInfo) time.Time {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, data.CreationTime.Nanoseconds())
	}
	return time.Time{}
}
func fileAccessTime(info os.FileInfo) time.Time {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, data.LastAccessTime.Nanoseconds())
	}
	return time.Time{}
}
func uniqueNativeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
func suspicionRank(value string) int {
	switch value {
	case "高":
		return 3
	case "中":
		return 2
	case "低":
		return 1
	default:
		return 0
	}
}
