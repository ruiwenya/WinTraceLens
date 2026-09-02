package evidencebundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/csvutil"
)

// Dataset preserves the collection scope and the complete JSON result.
type Dataset struct {
	Source      string          `json:"source"`
	Options     json.RawMessage `json:"options"`
	CollectedAt time.Time       `json:"collectedAt"`
	Data        json.RawMessage `json:"-"`
}

const evidencePackageLimit = 256 * 1024 * 1024

var evidenceSourceLabels = []struct{ ID, Label string }{
	{"processes", "进程信息"}, {"process-modules", "进程模块"},
	{"connections", "实时网络连接"}, {"host", "主机信息"},
	{"findings", "规则关注项"}, {"behavior", "行为关联"},
	{"registry", "注册表异常"}, {"registry-correlated", "注册表关联结果"},
	{"security-events", "事件日志"}, {"log-health", "日志健康"},
	{"network-history", "历史通信"}, {"file-traces", "文件痕迹"},
	{"memory", "内存异常"},
	{"drivers", "内核驱动风险"}, {"investigation", "案件调查"}, {"yara", "YARA 结果"},
}

type SourceStatus struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Datasets    int       `json:"datasets"`
	Rows        int       `json:"rows"`
	Warnings    int       `json:"warnings"`
	Failures    int       `json:"failures"`
	CollectedAt time.Time `json:"collectedAt,omitempty"`
	Selected    bool      `json:"selected"`
	Collectable bool      `json:"collectable"`
}

type Status struct {
	Sources      []SourceStatus `json:"sources"`
	DatasetCount int            `json:"datasetCount"`
	RawBytes     int            `json:"rawBytes"`
	Collecting   bool           `json:"collecting"`
}

// GroupSource makes sub-collectors part of their user-facing evidence category.
func GroupSource(source string) string {
	if source == "native-files" {
		return "file-traces"
	}
	return source
}

// NormalizeSelection treats an omitted selection as all sources for older clients.
// An explicit empty selection is an error, never an instruction to export all.
func NormalizeSelection(sources []string) ([]string, error) {
	if sources != nil && len(sources) == 0 {
		return nil, errors.New("请至少勾选一个证据来源")
	}
	wanted := make(map[string]bool)
	for _, source := range sources {
		known := false
		for _, label := range evidenceSourceLabels {
			if source == label.ID {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("未知证据来源：%s", source)
		}
		wanted[source] = true
	}
	var result []string
	for _, label := range evidenceSourceLabels {
		if sources == nil || wanted[label.ID] {
			result = append(result, label.ID)
		}
	}
	return result, nil
}

func Select(datasets []Dataset, sources []string) ([]Dataset, error) {
	selected, err := NormalizeSelection(sources)
	if err != nil {
		return nil, err
	}
	if sources == nil {
		return datasets, nil
	}
	wanted := make(map[string]bool)
	for _, source := range selected {
		wanted[source] = true
	}
	var out []Dataset
	for _, dataset := range datasets {
		if wanted[GroupSource(dataset.Source)] {
			out = append(out, dataset)
		}
	}
	return out, nil
}

type evidenceTable struct {
	Name string
	Rows []any
}

type evidenceDigest struct {
	Path   string `json:"path"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type evidenceManifestEntry struct {
	Dataset
	Files    []string `json:"files"`
	Warnings []string `json:"warnings,omitempty"`
}

// Describe reports coverage without invoking any collectors.
func Describe(datasets []Dataset) (Status, error) {
	status := Status{DatasetCount: len(datasets)}
	for _, source := range evidenceSourceLabels {
		entry := SourceStatus{ID: source.ID, Label: source.Label, Selected: true, Collectable: source.ID != "yara"}
		for _, dataset := range datasets {
			if GroupSource(dataset.Source) != source.ID {
				continue
			}
			entry.Datasets++
			var options struct {
				BatchFailure bool `json:"batchFailure"`
				Unavailable  bool `json:"unavailable"`
			}
			if json.Unmarshal(dataset.Options, &options) == nil && (options.BatchFailure || options.Unavailable) {
				entry.Failures++
			}
			status.RawBytes += len(dataset.Data)
			if dataset.CollectedAt.After(entry.CollectedAt) {
				entry.CollectedAt = dataset.CollectedAt
			}
			tables, warnings, err := evidenceTables(dataset.Data)
			if err != nil {
				return status, err
			}
			entry.Warnings += len(warnings)
			for _, table := range tables {
				entry.Rows += len(table.Rows)
			}
		}
		status.Sources = append(status.Sources, entry)
	}
	return status, nil
}

// JSON is authoritative. CSV contains all row fields, with nested structures
// encoded as JSON cells; summaries are never substituted for original records.
func evidenceTables(data []byte) ([]evidenceTable, []string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, err
	}
	var tables []evidenceTable
	var warnings []string
	switch value := value.(type) {
	case []any:
		tables = append(tables, evidenceTable{Name: "records", Rows: value})
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			rows, ok := value[key].([]any)
			if !ok {
				continue
			}
			if key == "collectionErrors" || key == "errors" || key == "ruleErrors" {
				for _, row := range rows {
					warnings = append(warnings, fmt.Sprint(row))
				}
				continue
			}
			tables = append(tables, evidenceTable{Name: key, Rows: rows})
		}
	}
	return tables, warnings, nil
}

func evidenceCSV(rows []any) ([]byte, error) {
	columns := make(map[string]bool)
	for _, row := range rows {
		if object, ok := row.(map[string]any); ok {
			for key := range object {
				columns[key] = true
			}
		} else {
			columns["value"] = true
		}
	}
	if len(columns) == 0 {
		columns["value"] = true
	}
	keys := make([]string, 0, len(columns))
	for key := range columns {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	buffer.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(&buffer)
	writer.UseCRLF = true
	if err := writer.Write(csvutil.SanitizeRow(keys)); err != nil {
		return nil, err
	}
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			object = map[string]any{"value": row}
		}
		cells := make([]string, len(keys))
		for i, key := range keys {
			value := object[key]
			switch typed := value.(type) {
			case nil:
			case string:
				cells[i] = typed
			case json.Number:
				cells[i] = typed.String()
			default:
				encoded, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}
				cells[i] = string(encoded)
			}
		}
		if err := writer.Write(csvutil.SanitizeRow(cells)); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

type evidenceArchiveBuffer struct {
	bytes.Buffer
	ctx context.Context
}

func (b *evidenceArchiveBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > evidencePackageLimit-b.Len() {
		return 0, errors.New("取证包超过 256 MB，请缩小采集范围或分模块导出")
	}
	return b.Buffer.Write(p)
}

// Build creates a bounded in-memory ZIP; it never reads source files or samples.
func Build(ctx context.Context, datasets []Dataset, version, hostname string, now time.Time) ([]byte, error) {
	return BuildSelected(ctx, datasets, version, hostname, now, nil)
}

func BuildSelected(ctx context.Context, datasets []Dataset, version, hostname string, now time.Time, sources []string) ([]byte, error) {
	selected, err := NormalizeSelection(sources)
	if err != nil {
		return nil, err
	}
	datasets, err = Select(datasets, sources)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rawSize int
	for _, dataset := range datasets {
		if len(dataset.Data) > evidencePackageLimit-rawSize {
			return nil, errors.New("采集数据超过 256 MB，请分模块导出")
		}
		rawSize += len(dataset.Data)
	}
	status, err := Describe(datasets)
	if err != nil {
		return nil, err
	}
	if status.RawBytes > evidencePackageLimit {
		return nil, errors.New("采集数据超过 256 MB，请分模块导出")
	}
	for i := range status.Sources {
		status.Sources[i].Selected = false
		for _, id := range selected {
			if id == status.Sources[i].ID {
				status.Sources[i].Selected = true
				break
			}
		}
	}
	buffer := &evidenceArchiveBuffer{ctx: ctx}
	archive := zip.NewWriter(buffer)
	var hashes []evidenceDigest
	var totalBytes int
	add := func(path string, data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(data) > evidencePackageLimit-totalBytes {
			return errors.New("取证包原始数据超过 256 MB，请分模块导出")
		}
		totalBytes += len(data)
		header := &zip.FileHeader{Name: path, Method: zip.Deflate}
		header.SetModTime(now)
		header.SetMode(0600)
		file, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err = io.Copy(file, bytes.NewReader(data)); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		hashes = append(hashes, evidenceDigest{Path: path, Size: len(data), SHA256: hex.EncodeToString(sum[:])})
		return nil
	}
	var entries []evidenceManifestEntry
	var warningRows []any
	for i, dataset := range datasets {
		tables, warnings, err := evidenceTables(dataset.Data)
		if err != nil {
			return nil, err
		}
		// Only generated numeric paths are used, never collected host paths.
		folder := fmt.Sprintf("data/%03d", i+1)
		for _, source := range evidenceSourceLabels {
			if dataset.Source == source.ID {
				folder += "-" + source.ID
				break
			}
		}
		entry := evidenceManifestEntry{Dataset: dataset, Warnings: warnings}
		path := folder + "/snapshot.json"
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, dataset.Data, "", "  "); err != nil {
			return nil, err
		}
		if err := add(path, pretty.Bytes()); err != nil {
			return nil, err
		}
		entry.Files = append(entry.Files, path)
		for j, table := range tables {
			name := table.Name
			if strings.IndexFunc(name, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
			}) >= 0 || name == "" {
				name = fmt.Sprintf("table-%03d", j+1)
			}
			path := folder + "/" + name + ".csv"
			csvData, err := evidenceCSV(table.Rows)
			if err != nil {
				return nil, err
			}
			if err := add(path, csvData); err != nil {
				return nil, err
			}
			entry.Files = append(entry.Files, path)
		}
		for _, warning := range warnings {
			warningRows = append(warningRows, map[string]any{"source": dataset.Source, "dataset": folder, "warning": warning})
		}
		entries = append(entries, entry)
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "WinTraceLens 取证包\r\n版本：%s\r\n主机：%s\r\n导出时间（UTC）：%s\r\n\r\n", version, hostname, now.Format(time.RFC3339))
	for _, source := range status.Sources {
		if !source.Selected {
			fmt.Fprintf(&summary, "%s：未勾选，不包含在本取证包中。\r\n", source.Label)
		} else if source.Datasets == 0 {
			fmt.Fprintf(&summary, "%s：未采集或尚未成功，不代表未发现异常。\r\n", source.Label)
		} else {
			fmt.Fprintf(&summary, "%s：%d 组，%d 条，最近采集 %s\r\n", source.Label, source.Datasets, source.Rows, source.CollectedAt.UTC().Format(time.RFC3339))
		}
	}
	summary.WriteString("\r\n范围与限制：\r\n仅保全本次运行中勾选来源的已完成采集结果；ZIP 生成本身不补扫，可事先使用一键获取证据。每种采集参数保留最近成功快照，跨时间范围分组导出。\r\n数据不受当前页面关键词、分页或可见列限制；模块包含手动查看或一键采集的 PID，一键采集受进程上限与权限限制。文件痕迹包含 Go 原生落地点。\r\n后台仍在采集时，只包含已完成结果；失败提示与旧快照同时保留，不同模块不是同一时刻的系统镜像。\r\nJSON 保存完整字段，CSV 嵌套字段为 JSON 文本，已防公式注入。\r\n不包含 API Key、AI 对话、原始内存转储、可执行样本、注册表二进制原值或原始 EVTX。\r\n主机数据可能含账户、路径、命令与内网地址，请按敏感证据保管。\r\nmanifest.json 记录每组来源、参数、采集时间与文件位置；hashes.csv 校验包内所有其他文件，自身不参与哈希。哈希保证完整性，不保证源主机未被篡改。\r\n")
	if err := add("summary.txt", []byte(summary.String())); err != nil {
		return nil, err
	}
	if len(warningRows) > 0 {
		data, err := evidenceCSV(warningRows)
		if err != nil {
			return nil, err
		}
		if err := add("collection-warnings.csv", data); err != nil {
			return nil, err
		}
	}
	manifest := struct {
		SchemaVersion int                     `json:"schemaVersion"`
		Version       string                  `json:"toolVersion"`
		Hostname      string                  `json:"hostname"`
		ExportedAt    time.Time               `json:"exportedAt"`
		Mode          string                  `json:"mode"`
		Coverage      Status                  `json:"coverage"`
		Datasets      []evidenceManifestEntry `json:"datasets"`
		Files         []evidenceDigest        `json:"files"`
	}{1, version, hostname, now, "completed-session-snapshots", status, entries, hashes}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := add("manifest.json", data); err != nil {
		return nil, err
	}
	var hashRows []any
	for _, hash := range hashes {
		hashRows = append(hashRows, map[string]any{"path": hash.Path, "size": hash.Size, "sha256": hash.SHA256})
	}
	data, err = evidenceCSV(hashRows)
	if err != nil {
		return nil, err
	}
	if err := add("hashes.csv", data); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
