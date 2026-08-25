package registryanomaly

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

type Options struct {
	MaxRecords  int
	MaxKeys     int
	MaxValues   int
	MaxDepth    int
	MaxDataSize int
	Timeout     time.Duration
}

type Snapshot struct {
	Records          []Record `json:"records"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
	ScannedKeys      int      `json:"scannedKeys"`
	ScannedValues    int      `json:"scannedValues"`
	Truncated        bool     `json:"truncated"`
}

type Record struct {
	ID              string   `json:"id"`
	Level           string   `json:"level"`
	Score           int      `json:"score"`
	Hive            string   `json:"hive"`
	SID             string   `json:"sid,omitempty"`
	KeyPath         string   `json:"keyPath"`
	ValueName       string   `json:"valueName"`
	ValueType       string   `json:"valueType"`
	DataLength      int      `json:"dataLength"`
	LastWrite       string   `json:"lastWrite"`
	SHA256          string   `json:"sha256,omitempty"`
	HashScope       string   `json:"hashScope,omitempty"`
	Entropy         float64  `json:"entropy,omitempty"`
	HexPreview      string   `json:"hexPreview,omitempty"`
	StringsPreview  string   `json:"stringsPreview,omitempty"`
	Reasons         []string `json:"reasons"`
	Associations    []string `json:"associations,omitempty"`
	DataTruncated   bool     `json:"dataTruncated,omitempty"`
	TraditionalPath bool     `json:"traditionalPath,omitempty"`
}

type ExportReference struct {
	Hive      string
	KeyPath   string
	ValueName string
}

type valueEvidence struct {
	hive           string
	sid            string
	keyPath        string
	valueName      string
	valueType      uint32
	dataLength     int
	lastWrite      time.Time
	data           []byte
	truncated      bool
	traditional    bool
	nonTraditional bool
}

var (
	urlPattern            = regexp.MustCompile(`(?i)https?://[^\s"'<>]{4,}`)
	ipPattern             = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	base64Pattern         = regexp.MustCompile(`(?i)(?:[A-Za-z0-9+/]{4}){16,}(?:==|=)?`)
	hexPattern            = regexp.MustCompile(`(?i)(?:0x)?[a-f0-9]{128,}`)
	randomNamePattern     = regexp.MustCompile(`(?i)^[a-z0-9]{10,}$`)
	suspiciousTextPattern = regexp.MustCompile(`(?i)(powershell|pwsh|cmd\.exe|rundll32|regsvr32|mshta|certutil|bitsadmin|invoke-webrequest|downloadstring|virtualalloc|writeprocessmemory|createremotethread|loadlibrary|getprocaddress|winexec|shellexecute|schtasks|sc\s+(?:create|start|config))`)
)

func normalizeOptions(opts Options) Options {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 500
	}
	if opts.MaxRecords > 3000 {
		opts.MaxRecords = 3000
	}
	if opts.MaxKeys <= 0 {
		opts.MaxKeys = 6000
	}
	if opts.MaxKeys > 30000 {
		opts.MaxKeys = 30000
	}
	if opts.MaxValues <= 0 {
		opts.MaxValues = 30000
	}
	if opts.MaxValues > 150000 {
		opts.MaxValues = 150000
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 5
	}
	if opts.MaxDepth > 10 {
		opts.MaxDepth = 10
	}
	if opts.MaxDataSize <= 0 {
		opts.MaxDataSize = 4 * 1024 * 1024
	}
	if opts.MaxDataSize > 32*1024*1024 {
		opts.MaxDataSize = 32 * 1024 * 1024
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Timeout > 60*time.Second {
		opts.Timeout = 60 * time.Second
	}
	return opts
}

func analyzeValue(item valueEvidence) (Record, bool) {
	text := valueText(item.data, item.valueType)
	printable := printableStrings(item.data)
	searchable := strings.Join([]string{text, printable, item.keyPath, item.valueName}, " ")
	entropy := shannonEntropy(item.data)
	score := 0
	reasons := make([]string, 0, 8)
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}

	if item.valueType == 3 && item.dataLength >= 1024 {
		add(2, fmt.Sprintf("REG_BINARY 数据较大（%s）", byteSize(item.dataLength)))
	}
	if len(item.data) >= 256 && entropy >= 7.20 {
		add(2, fmt.Sprintf("数据熵较高（%.2f）", entropy))
	}
	if offset, ok := embeddedPEOffset(item.data); ok {
		add(5, fmt.Sprintf("发现有效嵌入式 PE 结构（偏移 0x%X）", offset))
	} else if bytesContainMZ(item.data) {
		add(2, "数据中出现 MZ 文件头特征")
	}
	if suspiciousTextPattern.MatchString(searchable) {
		add(2, "包含可执行代码 API、脚本或系统命令特征")
	}
	if urlPattern.MatchString(searchable) || ipPattern.MatchString(searchable) {
		add(1, "包含 URL 或 IP 网络线索")
	}
	if item.valueType == 1 || item.valueType == 2 || item.valueType == 7 {
		if len([]rune(text)) >= 512 {
			add(2, "注册表字符串异常长")
		}
		if base64Pattern.MatchString(text) || hexPattern.MatchString(strings.ReplaceAll(text, " ", "")) {
			add(2, "字符串呈长 Base64 或十六进制编码形态")
		}
		if writablePath(text) {
			add(3, "数据指向用户可写目录")
		}
	}
	if randomRegistryName(item.keyPath) || randomNamePattern.MatchString(strings.TrimSpace(item.valueName)) {
		add(1, "键名或值名疑似随机")
	}
	if !item.lastWrite.IsZero() && time.Since(item.lastWrite) >= 0 && time.Since(item.lastWrite) <= 14*24*time.Hour {
		add(1, "注册表键近期发生写入")
	}
	if item.traditional {
		add(1, "位于高价值持久化位置")
	}
	if item.nonTraditional && item.valueType == 3 && item.dataLength >= 1024 {
		add(1, "普通用户 Software 键中存在大体积二进制数据")
	}
	if knownNoisyRegistryPath(item.keyPath) && score < 6 {
		score -= 2
		reasons = append(reasons, "常见高噪声软件数据区域，已降低权重")
	}
	if score < 3 {
		return Record{}, false
	}

	level := "低"
	if score >= 8 {
		level = "高"
	} else if score >= 5 {
		level = "中"
	}
	hash := ""
	hashScope := ""
	if len(item.data) > 0 {
		sum := sha256.Sum256(item.data)
		hash = hex.EncodeToString(sum[:])
		hashScope = "完整注册表值"
		if item.truncated {
			hashScope = fmt.Sprintf("前 %s 数据样本", byteSize(len(item.data)))
		}
	}
	return Record{
		ID:              encodeReference(ExportReference{Hive: item.hive, KeyPath: item.keyPath, ValueName: item.valueName}),
		Level:           level,
		Score:           score,
		Hive:            item.hive,
		SID:             item.sid,
		KeyPath:         item.keyPath,
		ValueName:       displayValueName(item.valueName),
		ValueType:       registryTypeName(item.valueType),
		DataLength:      item.dataLength,
		LastWrite:       formatTime(item.lastWrite),
		SHA256:          hash,
		HashScope:       hashScope,
		Entropy:         math.Round(entropy*100) / 100,
		HexPreview:      hexPreview(item.data, 64),
		StringsPreview:  truncateRunes(firstNonEmpty(text, printable), 320),
		Reasons:         uniqueStrings(reasons),
		DataTruncated:   item.truncated,
		TraditionalPath: item.traditional,
	}, true
}

func Correlate(snapshot Snapshot, processes []process.Info, machine host.Snapshot) Snapshot {
	for i := range snapshot.Records {
		item := &snapshot.Records[i]
		search := strings.ToLower(strings.Join([]string{item.KeyPath, item.ValueName, item.StringsPreview}, " "))
		add := func(value string) {
			for _, existing := range item.Associations {
				if existing == value {
					return
				}
			}
			item.Associations = append(item.Associations, value)
		}
		for _, proc := range processes {
			if proc.Path != "" && strings.Contains(search, strings.ToLower(proc.Path)) {
				add(fmt.Sprintf("进程 %s (PID %d)", proc.Name, proc.PID))
			}
		}
		for _, svc := range machine.Services {
			if (svc.Path != "" && strings.Contains(search, strings.ToLower(svc.Path))) || (svc.Name != "" && containsToken(search, svc.Name)) {
				add("服务 " + svc.Name)
			}
		}
		for _, task := range machine.ScheduledTasks {
			if task.Executable != "" && strings.Contains(search, strings.ToLower(task.Executable)) {
				add("计划任务 " + task.Name)
			}
		}
		for _, startup := range machine.StartupItems {
			if startup.Path != "" && strings.Contains(search, strings.ToLower(startup.Path)) {
				add("启动项 " + startup.Name)
			}
		}
		if len(item.Associations) > 0 {
			item.Score += 2
			item.Reasons = append(item.Reasons, "与当前进程、服务、任务或启动项证据关联")
			if item.Score >= 8 {
				item.Level = "高"
			} else if item.Score >= 5 {
				item.Level = "中"
			}
		}
	}
	sort.SliceStable(snapshot.Records, func(i, j int) bool {
		if snapshot.Records[i].Score != snapshot.Records[j].Score {
			return snapshot.Records[i].Score > snapshot.Records[j].Score
		}
		return strings.ToLower(snapshot.Records[i].KeyPath) < strings.ToLower(snapshot.Records[j].KeyPath)
	})
	return snapshot
}

func encodeReference(ref ExportReference) string {
	raw := strings.Join([]string{ref.Hive, ref.KeyPath, ref.ValueName}, "\x00")
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func DecodeReference(value string) (ExportReference, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return ExportReference{}, err
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return ExportReference{}, fmt.Errorf("无效注册表导出标识")
	}
	return ExportReference{Hive: parts[0], KeyPath: parts[1], ValueName: parts[2]}, nil
}

func valueText(data []byte, valueType uint32) string {
	if valueType != 1 && valueType != 2 && valueType != 7 {
		return ""
	}
	if len(data) < 2 {
		return strings.Trim(string(data), "\x00")
	}
	words := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		words = append(words, uint16(data[i])|uint16(data[i+1])<<8)
	}
	return strings.TrimSpace(strings.Trim(string(utf16.Decode(words)), "\x00"))
}

func printableStrings(data []byte) string {
	parts := make([]string, 0, 8)
	var current strings.Builder
	flush := func() {
		if current.Len() >= 5 {
			parts = append(parts, current.String())
		}
		current.Reset()
	}
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			current.WriteByte(b)
		} else {
			flush()
		}
		if len(parts) >= 12 {
			break
		}
	}
	flush()
	return truncateRunes(strings.Join(parts, " | "), 320)
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var result float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(data))
		result -= p * math.Log2(p)
	}
	return result
}

func embeddedPEOffset(data []byte) (int, bool) {
	for start := 0; start+64 < len(data); {
		idx := strings.Index(string(data[start:]), "MZ")
		if idx < 0 {
			return 0, false
		}
		offset := start + idx
		if offset+0x40 <= len(data) {
			peOffset := int(uint32(data[offset+0x3c]) | uint32(data[offset+0x3d])<<8 | uint32(data[offset+0x3e])<<16 | uint32(data[offset+0x3f])<<24)
			pos := offset + peOffset
			if peOffset >= 0x40 && pos+4 <= len(data) && string(data[pos:pos+4]) == "PE\x00\x00" {
				return offset, true
			}
		}
		start = offset + 2
	}
	return 0, false
}

func bytesContainMZ(data []byte) bool { return strings.Contains(string(data), "MZ") }
func writablePath(value string) bool {
	lower := strings.ToLower(strings.ReplaceAll(value, "/", `\`))
	for _, marker := range []string{`\appdata\`, `\temp\`, `\programdata\`, `\users\public\`, `\downloads\`, `\desktop\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func randomRegistryName(path string) bool {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
	if len(parts) == 0 {
		return false
	}
	name := parts[len(parts)-1]
	if len(name) < 10 || !randomNamePattern.MatchString(name) {
		return false
	}
	letters, digits := 0, 0
	for _, r := range name {
		if unicode.IsLetter(r) {
			letters++
		}
		if unicode.IsDigit(r) {
			digits++
		}
	}
	return letters > 0 && digits > 0
}
func knownNoisyRegistryPath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{`\classes\`, `\microsoft\windows\currentversion\explorer\`, `\microsoft\internet explorer\`, `\microsoft\office\`, `\google\chrome\`, `\mozilla\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func containsToken(haystack, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if len(needle) < 4 {
		return false
	}
	return strings.Contains(haystack, needle)
}
func hexPreview(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	return strings.ToUpper(hex.EncodeToString(data))
}
func truncateRunes(value string, limit int) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
	if len(runes) <= limit {
		return strings.TrimSpace(string(runes))
	}
	return strings.TrimSpace(string(runes[:limit])) + "..."
}
func displayValueName(value string) string {
	if value == "" {
		return "(默认)"
	}
	return value
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Local().Format("2006-01-02 15:04:05")
}
func byteSize(value int) string {
	if value >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(value)/1024/1024)
	}
	if value >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(value)/1024)
	}
	return fmt.Sprintf("%d B", value)
}
func registryTypeName(value uint32) string {
	switch value {
	case 0:
		return "REG_NONE"
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 7:
		return "REG_MULTI_SZ"
	case 11:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("TYPE_%d", value)
	}
}
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
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
