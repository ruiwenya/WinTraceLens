package server

import (
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
)

func TestFileTraceSourceMatchesNativeLandingScan(t *testing.T) {
	native := filetrace.Record{Source: "Go \u539f\u751f\u843d\u5730\u70b9\u626b\u63cf", Name: "sample.exe"}
	prefetch := filetrace.Record{Source: "Prefetch", Name: "SAMPLE.EXE-12345678.pf"}

	if !fileTraceSourceMatches(native, "native") {
		t.Fatal("native landing scan record should match the native source filter")
	}
	if fileTraceSourceMatches(prefetch, "native") {
		t.Fatal("non-native record should not match the native source filter")
	}
}

func TestFilterFileTraceRecordsByNativeSource(t *testing.T) {
	items := []filetrace.Record{
		{Category: "\u53ef\u7591\u843d\u5730\u6587\u4ef6", Source: "Go \u539f\u751f\u843d\u5730\u70b9\u626b\u63cf", Name: "payload.bin"},
		{Category: "\u6267\u884c\u75d5\u8ff9", Source: "Prefetch", Name: "PAYLOAD.EXE-12345678.pf"},
	}

	got := filterFileTraceRecords(items, "all", "native", "")
	if len(got) != 1 || got[0].Name != "payload.bin" {
		t.Fatalf("native source filter returned %#v", got)
	}
}

func TestFileTraceStructureFilter(t *testing.T) {
	item := filetrace.Record{Category: "文件结构异常", Source: "敏感文件结构校验", Name: "desktop.ini"}
	if !fileTraceSourceMatches(item, "structure") {
		t.Fatal("sensitive structure record should match the structure source filter")
	}
	if !fileTraceCategoryMatches(item, "structure") || !fileTraceCategoryMatches(item, "artifacts") {
		t.Fatal("sensitive structure record should be visible in structure and artifact categories")
	}
}
