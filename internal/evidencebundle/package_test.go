package evidencebundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func exportFixture() []Dataset {
	return []Dataset{
		{Source: "processes", Options: json.RawMessage(`{"skipHashes":false}`), CollectedAt: time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC), Data: json.RawMessage(`[{"pid":4,"name":"=HYPERLINK(\"bad\")","path":"C:\\中文 空格\\程序.exe","base":18446744073709551615,"more":{"cmd":"@something"}}]`)},
		{Source: "host", Options: json.RawMessage(`{}`), CollectedAt: time.Now().UTC(), Data: json.RawMessage(`{"services":[{"name":"+cmd","command":"原始\n多行"}],"users":[],"collectionErrors":["权限不足"],"generatedAt":"original-time"}`)},
	}
}

func readEvidenceZIP(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range reader.File {
		if strings.Contains(entry.Name, "..") || strings.HasPrefix(entry.Name, "/") || strings.ContainsAny(entry.Name, `\:`) {
			t.Fatalf("unsafe name %s", entry.Name)
		}
		if _, ok := files[entry.Name]; ok {
			t.Fatalf("duplicate name %s", entry.Name)
		}
		file, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name] = content
	}
	return files
}

func TestEvidencePackageCompleteJSONCSVHashesAndCoverage(t *testing.T) {
	data, err := Build(context.Background(), exportFixture(), "test", "host", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	files := readEvidenceZIP(t, data)
	for _, name := range []string{"manifest.json", "summary.txt", "collection-warnings.csv", "hashes.csv", "data/001-processes/snapshot.json", "data/001-processes/records.csv", "data/002-host/services.csv"} {
		if len(files[name]) == 0 {
			t.Fatalf("missing %s", name)
		}
	}
	if !strings.Contains(string(files["data/002-host/snapshot.json"]), `原始\n多行`) {
		t.Fatal("original evidence modified")
	}
	processCSV := string(files["data/001-processes/records.csv"])
	if !strings.Contains(processCSV, "'=HYPERLINK") || !strings.Contains(processCSV, "18446744073709551615") || !strings.Contains(processCSV, "中文 空格") {
		t.Fatalf("CSV lost fields or formula protection: %s", processCSV)
	}
	if !bytes.HasPrefix(files["data/001-processes/records.csv"], []byte{0xef, 0xbb, 0xbf}) {
		t.Fatal("CSV missing UTF-8 BOM")
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(files["hashes.csv"]), "\ufeff")))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(files) {
		t.Fatalf("hash inventory incomplete: %d rows %d files", len(rows), len(files))
	}
	for _, row := range rows[1:] {
		// Alphabetical keys: path, sha256, size.
		content, ok := files[row[0]]
		if !ok {
			t.Fatalf("unknown hash file %s", row[0])
		}
		sum := sha256.Sum256(content)
		if row[1] != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash mismatch %s", row[0])
		}
	}
	var manifest struct {
		Coverage Status
		Datasets []evidenceManifestEntry
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Coverage.DatasetCount != 2 || len(manifest.Datasets) != 2 {
		t.Fatal("manifest missing snapshots")
	}
	if !manifest.Datasets[0].CollectedAt.Equal(exportFixture()[0].CollectedAt) {
		t.Fatal("collection time replaced by export time")
	}
	for _, source := range manifest.Coverage.Sources {
		if source.ID == "memory" && source.Datasets != 0 {
			t.Fatal("missing collection reported as completed")
		}
		if source.ID == "host" && source.Warnings != 1 {
			t.Fatal("warning lost")
		}
	}
}

func TestEvidenceExportCancellationAndMalformedData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, exportFixture(), "test", "host", time.Now()); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := Build(context.Background(), []Dataset{{Source: "host", Data: json.RawMessage(`{broken`)}}, "test", "host", time.Now()); err == nil {
		t.Fatal("malformed JSON allowed")
	}
}

func TestEvidencePackageNeverUsesCollectedPaths(t *testing.T) {
	datasets := []Dataset{{Source: "../../escape", Options: json.RawMessage(`{}`), Data: json.RawMessage(`{"../../evil":[{"path":"C:\\Windows\\evil"}]}`)}}
	data, err := Build(context.Background(), datasets, "test", "host", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	files := readEvidenceZIP(t, data)
	if _, ok := files["data/001/table-001.csv"]; !ok {
		t.Fatal("unsafe table name not replaced")
	}
}

func TestFileTraceGroupIncludesNativeRecordsWithoutDuplicateStatus(t *testing.T) {
	data := []Dataset{
		{Source: "file-traces", Options: json.RawMessage(`{}`), Data: json.RawMessage(`{"records":[{"source":"native","name":"native embedded"}]}`)},
		{Source: "native-files", Options: json.RawMessage(`{}`), Data: json.RawMessage(`{"records":[{"name":"native separate"}]}`)},
		{Source: "host", Options: json.RawMessage(`{}`), Data: json.RawMessage(`{"services":[{"name":"not-selected-host"}]}`)},
	}
	status, err := Describe(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range status.Sources {
		if source.ID == "native-files" {
			t.Fatal("duplicate native-file source exposed")
		}
		if source.ID == "file-traces" && (source.Datasets != 2 || source.Rows != 2) {
			t.Fatalf("native coverage missing: %+v", source)
		}
	}
	archive, err := BuildSelected(context.Background(), data, "test", "host", time.Now(), []string{"file-traces"})
	if err != nil {
		t.Fatal(err)
	}
	files := readEvidenceZIP(t, archive)
	var manifest struct {
		Coverage Status
		Datasets []evidenceManifestEntry
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Datasets) != 2 {
		t.Fatal("group did not retain both collectors")
	}
	for _, content := range files {
		if strings.Contains(string(content), "not-selected-host") {
			t.Fatal("unselected host records exported")
		}
	}
	for _, source := range manifest.Coverage.Sources {
		if source.ID == "host" && source.Selected {
			t.Fatal("unselected source marked selected")
		}
	}
	if !strings.Contains(string(files["summary.txt"]), "未勾选") {
		t.Fatal("unselected source marked missing")
	}
	if _, err := Select(data, []string{}); err == nil {
		t.Fatal("empty selection exported all")
	}
	if _, err := Select(data, []string{"ai-session"}); err == nil {
		t.Fatal("unknown source accepted")
	}
}

func TestCoverageDistinguishesFailureRecords(t *testing.T) {
	status, err := Describe([]Dataset{
		{Source: "host", Options: json.RawMessage(`{"batchFailure":true}`), Data: json.RawMessage(`{"collectionErrors":["unavailable"]}`)},
		{Source: "process-modules", Options: json.RawMessage(`{"pid":4,"unavailable":true}`), Data: json.RawMessage(`{"items":[],"collectionErrors":["denied"]}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range status.Sources {
		if source.ID == "host" || source.ID == "process-modules" {
			if source.Failures != 1 || source.Rows != 0 || source.Warnings != 1 {
				t.Fatalf("failure counted as successful records: %+v", source)
			}
		}
	}
}
