package amcache

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"
)

const (
	maxHiveBytes           = int64(512 << 20)
	defaultMaxApplications = 10000
	defaultMaxDrivers      = 5000
	maxProgramIDs          = 100000
)

type Options struct {
	Path                 string
	MaxApplicationFiles  int
	MaxDrivers           int
	SkipApplicationFiles bool
}

type Snapshot struct {
	HivePath         string
	Schema           string
	ReadMode         string
	ProgramCount     int
	ApplicationFiles []ApplicationFile
	Drivers          []DriverBinary
	Warnings         []string
}

// ApplicationFile is historical Amcache metadata. SHA1 is a cached identifier,
// not a fresh full-file hash, and RecordTime must never be presented as proof
// that the file executed. The Hive itself is also not tamper-proof evidence.
type ApplicationFile struct {
	Schema         string
	KeyName        string
	Name           string
	Path           string
	ProgramID      string
	FileID         string
	SHA1           string
	Publisher      string
	BinaryType     string
	ProductName    string
	ProductVersion string
	BinFileVersion string
	OriginalName   string
	LinkDate       string
	Size           int64
	Created        string
	Modified       string
	RecordTime     string
	TimeMeaning    string
	Association    string
}

// DriverBinary records that Amcache observed driver metadata; it does not prove
// that the driver was loaded and may outlive the current file or service entry.
type DriverBinary struct {
	KeyName         string
	Name            string
	Path            string
	SHA1            string
	Company         string
	Service         string
	DriverType      string
	DriverVersion   string
	Product         string
	ProductVersion  string
	Signed          string
	DriverTimestamp string
	Size            int64
	RecordTime      string
	TimeMeaning     string
}

func DefaultPath() string {
	systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if systemRoot == "" {
		systemRoot = strings.TrimSpace(os.Getenv("windir"))
	}
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	return filepath.Join(systemRoot, "AppCompat", "Programs", "Amcache.hve")
}

func Parse(opts Options) (snapshot Snapshot, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			snapshot = Snapshot{}
			err = fmt.Errorf("Amcache Hive 解析异常: %v", recovered)
		}
	}()

	path := strings.Trim(strings.TrimSpace(opts.Path), `"`)
	if path == "" {
		path = DefaultPath()
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("无法读取 Amcache Hive %s: %w", path, err)
	}
	if info.IsDir() {
		return Snapshot{}, fmt.Errorf("Amcache 路径指向目录而不是 Hive 文件: %s", path)
	}
	if info.Size() <= 0 {
		return Snapshot{}, fmt.Errorf("Amcache Hive 为空: %s", path)
	}
	if info.Size() > maxHiveBytes {
		return Snapshot{}, fmt.Errorf("Amcache Hive 超过 %d MB 安全上限: %s", maxHiveBytes>>20, path)
	}

	registry, cleanup, warnings, readMode, err := openRegistry(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer cleanup()

	opts.MaxApplicationFiles = boundedLimit(opts.MaxApplicationFiles, defaultMaxApplications, 20000)
	opts.MaxDrivers = boundedLimit(opts.MaxDrivers, defaultMaxDrivers, 10000)
	snapshot = Snapshot{HivePath: path, ReadMode: readMode, Warnings: warnings}
	supportedSchema := false
	if !opts.SkipApplicationFiles {
		programIDs, programCatalogAvailable := collectProgramIDs(registry)
		snapshot.ProgramCount = len(programIDs)
		if key := registry.OpenKey(`Root\InventoryApplicationFile`); key != nil {
			supportedSchema = true
			snapshot.ApplicationFiles = append(snapshot.ApplicationFiles, parseNewApplicationFiles(key, programIDs, programCatalogAvailable, opts.MaxApplicationFiles)...)
			snapshot.Schema = "new"
		}
		if key := registry.OpenKey(`Root\File`); key != nil && len(snapshot.ApplicationFiles) < opts.MaxApplicationFiles {
			supportedSchema = true
			remaining := opts.MaxApplicationFiles - len(snapshot.ApplicationFiles)
			snapshot.ApplicationFiles = append(snapshot.ApplicationFiles, parseOldApplicationFiles(key, programIDs, programCatalogAvailable, remaining)...)
			if snapshot.Schema == "new" {
				snapshot.Schema = "new+old"
			} else {
				snapshot.Schema = "old"
			}
		}
	} else if registry.OpenKey(`Root\InventoryApplicationFile`) != nil || registry.OpenKey(`Root\File`) != nil {
		supportedSchema = true
	}
	if key := registry.OpenKey(`Root\InventoryDriverBinary`); key != nil {
		supportedSchema = true
		snapshot.Drivers = parseDriverBinaries(key, opts.MaxDrivers)
	}
	if !supportedSchema {
		return Snapshot{}, fmt.Errorf("Amcache Hive 中未找到受支持的 Root\\InventoryApplicationFile、Root\\File 或 Root\\InventoryDriverBinary")
	}

	snapshot.ApplicationFiles = deduplicateApplications(snapshot.ApplicationFiles)
	sort.SliceStable(snapshot.ApplicationFiles, func(i, j int) bool {
		return timestampSortKey(snapshot.ApplicationFiles[i].RecordTime).After(timestampSortKey(snapshot.ApplicationFiles[j].RecordTime))
	})
	snapshot.Drivers = deduplicateDrivers(snapshot.Drivers)
	sort.SliceStable(snapshot.Drivers, func(i, j int) bool {
		return timestampSortKey(snapshot.Drivers[i].RecordTime).After(timestampSortKey(snapshot.Drivers[j].RecordTime))
	})
	return snapshot, nil
}

func openRegistry(path string) (*regparser.Registry, func(), []string, string, error) {
	hive, activePath, readMode, sourceCleanup, err := openHiveSource(path)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("打开 Amcache Hive 失败: %w", err)
	}
	closeSource := func() {
		_ = hive.Close()
		sourceCleanup()
	}
	direct, err := regparser.NewRegistry(hive)
	if err != nil {
		closeSource()
		return nil, nil, nil, "", fmt.Errorf("Amcache Hive 格式无效: %w", err)
	}

	warnings := make([]string, 0, 2)
	if direct.BaseBlock.Sequence1() == direct.BaseBlock.Sequence2() {
		return direct, closeSource, warnings, readMode, nil
	}

	logs := make([]*os.File, 0, 2)
	for _, suffix := range []string{".LOG1", ".LOG2"} {
		logFile, openErr := os.Open(activePath + suffix)
		if openErr == nil {
			logs = append(logs, logFile)
		}
	}
	if len(logs) == 0 {
		warnings = append(warnings, "Amcache Hive 事务序列不一致，且未找到可读的 LOG1/LOG2；结果可能缺少尚未落盘的最新条目。")
		return direct, closeSource, warnings, readMode, nil
	}

	_, _ = hive.Seek(0, 0)
	recovered, recoverErr := regparser.RecoverHive(hive, logs...)
	for _, logFile := range logs {
		_ = logFile.Close()
	}
	if recoverErr != nil {
		warnings = append(warnings, "Amcache 事务日志恢复失败，已使用基础 Hive: "+recoverErr.Error())
		return direct, closeSource, warnings, readMode, nil
	}
	parsed, parseErr := regparser.NewRegistry(recovered)
	if parseErr != nil {
		name := recovered.Name()
		_ = recovered.Close()
		_ = os.Remove(name)
		warnings = append(warnings, "恢复后的 Amcache Hive 无法解析，已使用基础 Hive: "+parseErr.Error())
		return direct, closeSource, warnings, readMode, nil
	}
	warnings = append(warnings, "Amcache Hive 事务序列不一致，已应用可用的 LOG1/LOG2 后解析。")
	return parsed, func() {
		name := recovered.Name()
		_ = recovered.Close()
		_ = os.Remove(name)
		closeSource()
	}, warnings, readMode, nil
}

func collectProgramIDs(registry *regparser.Registry) (map[string]struct{}, bool) {
	result := make(map[string]struct{})
	available := false
	for _, path := range []string{`Root\InventoryApplication`, `Root\Programs`} {
		root := registry.OpenKey(path)
		if root == nil {
			continue
		}
		available = true
		for _, key := range root.Subkeys() {
			addProgramID(result, key.Name())
			values := keyValues(key)
			for _, name := range []string{"ProgramId", "ProgramInstanceId"} {
				addProgramID(result, valueText(values, name))
			}
			if len(result) >= maxProgramIDs {
				return result, available
			}
		}
	}
	return result, available
}

func parseNewApplicationFiles(root *regparser.CM_KEY_NODE, programIDs map[string]struct{}, programCatalogAvailable bool, limit int) []ApplicationFile {
	items := make([]ApplicationFile, 0, min(limit, 1024))
	for _, key := range root.Subkeys() {
		if len(items) >= limit {
			break
		}
		values := keyValues(key)
		path := cleanPath(firstText(values, "LowerCaseLongPath", "LongPath", "FullPath"))
		name := firstText(values, "Name", "OriginalFileName")
		if name == "" {
			name = windowsBase(path)
		}
		programID := firstText(values, "ProgramId", "ProgramID")
		fileID := firstText(values, "FileId", "FileID")
		item := ApplicationFile{
			Schema:         "new",
			KeyName:        cleanText(key.Name()),
			Name:           cleanText(name),
			Path:           path,
			ProgramID:      cleanText(programID),
			FileID:         cleanText(fileID),
			SHA1:           NormalizeSHA1(fileID),
			Publisher:      firstText(values, "Publisher"),
			BinaryType:     firstText(values, "BinaryType"),
			ProductName:    firstText(values, "ProductName"),
			ProductVersion: firstText(values, "ProductVersion"),
			BinFileVersion: firstText(values, "BinFileVersion"),
			OriginalName:   firstText(values, "OriginalFileName"),
			LinkDate:       valueTimestamp(values, "LinkDate"),
			Size:           valueInt64(values, "Size"),
			RecordTime:     keyTimestamp(key),
			TimeMeaning:    "兼容性评估器记录或更新该条目的时间，不代表文件执行时间",
			Association:    programAssociation(programID, programIDs, programCatalogAvailable),
		}
		if item.Path == "" && item.Name == "" && item.SHA1 == "" {
			continue
		}
		items = append(items, item)
	}
	return items
}

func parseOldApplicationFiles(root *regparser.CM_KEY_NODE, programIDs map[string]struct{}, programCatalogAvailable bool, limit int) []ApplicationFile {
	items := make([]ApplicationFile, 0, min(limit, 1024))
	for _, volume := range root.Subkeys() {
		for _, key := range volume.Subkeys() {
			if len(items) >= limit {
				return items
			}
			values := keyValues(key)
			path := oldSchemaPath(values)
			programID := firstText(values, "100", "ProgramId", "ProgramID")
			fileID := firstText(values, "101", "FileId", "FileID", "c")
			item := ApplicationFile{
				Schema:         "old",
				KeyName:        cleanText(volume.Name()) + `\` + cleanText(key.Name()),
				Name:           windowsBase(path),
				Path:           path,
				ProgramID:      cleanText(programID),
				FileID:         cleanText(fileID),
				SHA1:           NormalizeSHA1(fileID),
				Publisher:      firstText(values, "1", "CompanyName", "Publisher"),
				ProductName:    firstText(values, "0", "ProductName"),
				ProductVersion: firstText(values, "2", "5", "ProductVersion"),
				LinkDate:       valueTimestamp(values, "f", "LinkDate"),
				Size:           valueInt64(values, "6", "Size"),
				Modified:       valueFiletime(values, "11"),
				Created:        valueFiletime(values, "12"),
				RecordTime:     keyTimestamp(key),
				TimeMeaning:    "旧 schema 注册表条目最后写入时间；可能与兼容性处理相关，但仍不能单独证明执行",
				Association:    programAssociation(programID, programIDs, programCatalogAvailable),
			}
			if item.Name == "" {
				item.Name = cleanText(key.Name())
			}
			if item.Path == "" && item.Name == "" && item.SHA1 == "" {
				continue
			}
			items = append(items, item)
		}
	}
	return items
}

func parseDriverBinaries(root *regparser.CM_KEY_NODE, limit int) []DriverBinary {
	items := make([]DriverBinary, 0, min(limit, 512))
	for _, key := range root.Subkeys() {
		if len(items) >= limit {
			break
		}
		values := keyValues(key)
		keyName := cleanText(key.Name())
		path := cleanPath(firstText(values, "FullPath", "LowerCaseLongPath", "DriverPath", "ImagePath"))
		if path == "" {
			path = pathFromDriverKeyName(keyName)
		}
		name := firstText(values, "DriverName", "Name")
		if name == "" {
			name = windowsBase(path)
		}
		driverID := firstText(values, "DriverId", "DriverID", "FileId")
		sha1 := NormalizeSHA1(driverID)
		if sha1 == "" {
			sha1 = NormalizeSHA1(keyName)
		}
		item := DriverBinary{
			KeyName:         keyName,
			Name:            cleanText(name),
			Path:            path,
			SHA1:            sha1,
			Company:         firstText(values, "DriverCompany", "CompanyName", "Publisher"),
			Service:         firstText(values, "Service", "ServiceName"),
			DriverType:      firstText(values, "DriverType", "BinaryType"),
			DriverVersion:   firstText(values, "DriverVersion", "Version"),
			Product:         firstText(values, "Product", "ProductName"),
			ProductVersion:  firstText(values, "ProductVersion"),
			Signed:          firstText(values, "DriverSigned", "Signed"),
			DriverTimestamp: valueTimestamp(values, "DriverTimeStamp", "DriverTimestamp", "LinkDate"),
			Size:            valueInt64(values, "ImageSize", "Size"),
			RecordTime:      keyTimestamp(key),
			TimeMeaning:     "Amcache 记录该驱动清单条目的时间，不代表驱动加载时间",
		}
		if item.Path == "" && item.Name == "" && item.SHA1 == "" {
			continue
		}
		items = append(items, item)
	}
	return items
}

type registryValues map[string]*regparser.ValueData

func keyValues(key *regparser.CM_KEY_NODE) registryValues {
	result := make(registryValues)
	for _, value := range key.Values() {
		data := value.ValueData()
		if data == nil || data.Error != nil {
			continue
		}
		result[strings.ToLower(cleanText(value.ValueName()))] = data
	}
	return result
}

func valueText(values registryValues, name string) string {
	value := values[strings.ToLower(name)]
	if value == nil {
		return ""
	}
	if text := cleanText(value.String); text != "" {
		return text
	}
	if len(value.MultiSz) > 0 {
		return cleanText(strings.Join(value.MultiSz, "; "))
	}
	if value.Type == regparser.REG_DWORD || value.Type == regparser.REG_DWORD_BIG_ENDIAN || value.Type == regparser.REG_QWORD {
		return strconv.FormatUint(value.Uint64, 10)
	}
	return ""
}

func firstText(values registryValues, names ...string) string {
	for _, name := range names {
		if value := valueText(values, name); value != "" {
			return value
		}
	}
	return ""
}

func valueInt64(values registryValues, names ...string) int64 {
	for _, name := range names {
		value := values[strings.ToLower(name)]
		if value == nil {
			continue
		}
		if value.Type == regparser.REG_DWORD || value.Type == regparser.REG_DWORD_BIG_ENDIAN || value.Type == regparser.REG_QWORD {
			if value.Uint64 > math.MaxInt64 {
				return math.MaxInt64
			}
			return int64(value.Uint64)
		}
		if parsed, err := strconv.ParseInt(strings.TrimSpace(value.String), 0, 64); err == nil {
			return parsed
		}
	}
	return 0
}

func valueTimestamp(values registryValues, names ...string) string {
	for _, name := range names {
		value := values[strings.ToLower(name)]
		if value == nil {
			continue
		}
		if text := cleanText(value.String); text != "" {
			return text
		}
		if formatted := numericTimestamp(value.Uint64); formatted != "" {
			return formatted
		}
	}
	return ""
}

func valueFiletime(values registryValues, names ...string) string {
	for _, name := range names {
		value := values[strings.ToLower(name)]
		if value == nil {
			continue
		}
		if formatted := windowsFiletime(value.Uint64); formatted != "" {
			return formatted
		}
	}
	return ""
}

func keyTimestamp(key *regparser.CM_KEY_NODE) string {
	if key == nil || key.LastWriteTime() == nil {
		return ""
	}
	return formatTime(key.LastWriteTime().Time)
}

func numericTimestamp(value uint64) string {
	if value == 0 {
		return ""
	}
	if value >= 315532800 && value <= 7258118400 {
		return formatTime(time.Unix(int64(value), 0))
	}
	return windowsFiletime(value)
}

func windowsFiletime(value uint64) string {
	const windowsEpoch = uint64(116444736000000000)
	if value <= windowsEpoch {
		return ""
	}
	seconds := (value - windowsEpoch) / 10000000
	if seconds > math.MaxInt64 {
		return ""
	}
	return formatTime(time.Unix(int64(seconds), 0))
}

func formatTime(value time.Time) string {
	if value.IsZero() || value.Year() < 1980 || value.Year() > 2200 {
		return ""
	}
	return value.Local().Format("2006-01-02 15:04:05")
}

func timestampSortKey(value string) time.Time {
	parsed, _ := time.ParseInLocation("2006-01-02 15:04:05", value, time.Local)
	return parsed
}

func oldSchemaPath(values registryValues) string {
	for _, name := range []string{"LowerCaseLongPath", "FullPath", "FilePath", "15", "17"} {
		candidate := cleanPath(valueText(values, name))
		if looksLikePath(candidate) {
			return candidate
		}
	}
	return ""
}

func pathFromDriverKeyName(value string) string {
	if start := strings.Index(value, `"`); start >= 0 {
		if end := strings.Index(value[start+1:], `"`); end >= 0 {
			return cleanPath(value[start+1 : start+1+end])
		}
	}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '|' || r == ',' || r == ';' }) {
		part = cleanPath(part)
		if looksLikePath(part) {
			return part
		}
	}
	return ""
}

func cleanPath(value string) string {
	value = cleanText(value)
	value = strings.Trim(value, `"'`)
	return strings.ReplaceAll(value, "/", `\`)
}

func looksLikePath(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, `:\`) || strings.HasPrefix(lower, `\`) || strings.HasPrefix(lower, `%`) || strings.Contains(lower, `.exe`) || strings.Contains(lower, `.dll`) || strings.Contains(lower, `.sys`)
}

func windowsBase(value string) string {
	value = strings.TrimRight(cleanPath(value), `\`)
	if index := strings.LastIndex(value, `\`); index >= 0 {
		return value[index+1:]
	}
	return value
}

func cleanText(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	return strings.TrimSpace(value)
}

func addProgramID(values map[string]struct{}, value string) {
	if normalized := normalizeProgramID(value); normalized != "" && !allZero(normalized) {
		values[normalized] = struct{}{}
	}
}

func programAssociation(programID string, known map[string]struct{}, catalogAvailable bool) string {
	normalized := normalizeProgramID(programID)
	if normalized == "" || allZero(normalized) {
		return "未关联"
	}
	if !catalogAvailable {
		return "应用清单不可用"
	}
	if _, ok := known[normalized]; ok {
		return "已关联"
	}
	return "关联项缺失"
}

func normalizeProgramID(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(cleanText(value)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	normalized := builder.String()
	if len(normalized) > 40 && len(normalized) <= 64 && isHexString(normalized) {
		return normalized[len(normalized)-40:]
	}
	return normalized
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func allZero(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r != '0' {
			return false
		}
	}
	return true
}

// NormalizeSHA1 takes the final 40-character hexadecimal run. This removes
// Amcache's synthetic prefix without deleting genuine leading zeroes in SHA1.
func NormalizeSHA1(value string) string {
	value = strings.ToLower(cleanText(value))
	best := ""
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		run := value[start:end]
		if len(run) >= 40 {
			best = run[len(run)-40:]
		}
		start = -1
	}
	for index, r := range value {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			if start < 0 {
				start = index
			}
			continue
		}
		flush(index)
	}
	flush(len(value))
	return best
}

func deduplicateApplications(values []ApplicationFile) []ApplicationFile {
	seen := make(map[string]struct{}, len(values))
	result := make([]ApplicationFile, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.Join([]string{value.Schema, value.Path, value.SHA1, value.Name}, "|"))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func deduplicateDrivers(values []DriverBinary) []DriverBinary {
	seen := make(map[string]struct{}, len(values))
	result := make([]DriverBinary, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.Join([]string{value.Path, value.SHA1, value.Name, value.Service}, "|"))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func boundedLimit(value, fallback, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
