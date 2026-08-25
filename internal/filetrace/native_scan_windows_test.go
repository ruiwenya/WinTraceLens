//go:build windows

package filetrace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestServiceReferencesFromScript(t *testing.T) {
	items := serviceReferences("@echo off\r\nsc create BadSvc binPath= C:\\Temp\\x.exe\r\nsc start BadSvc")
	if len(items) != 1 || items[0] != "BadSvc" {
		t.Fatalf("unexpected service references: %#v", items)
	}
}

func TestHiddenPEIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update.tmp")
	data := make([]byte, 4096)
	copy(data, []byte("MZ"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := inspectLandingFile(path, info)
	if !ok {
		t.Fatal("expected disguised PE record")
	}
	if record.Magic != "PE" || record.Suspicion == "" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestDesktopINIStructuralWhitespacePayloadIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desktop.ini")
	text := "[.ShellClassInfo]\r\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21781\r\n" +
		strings.Repeat(" ", 80) + "\r\n" + strings.Repeat(" ", 90) + "\r\n" + strings.Repeat(" ", 100) + "\r\n"
	if err := os.WriteFile(path, encodeUTF16LEForTest(text), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := inspectDesktopINI(path, info)
	if !ok {
		t.Fatal("expected desktop.ini structural anomaly")
	}
	if record.Source != "敏感文件结构校验" || record.Suspicion == "" || !strings.Contains(record.Reason, "纯空白") {
		t.Fatalf("unexpected desktop.ini record: %+v", record)
	}
}

func TestNormalDesktopINIIsNotReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desktop.ini")
	content := "[.ShellClassInfo]\r\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21781\r\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if record, ok := inspectDesktopINI(path, info); ok {
		t.Fatalf("normal desktop.ini was unexpectedly reported: %+v", record)
	}
}

func encodeUTF16LEForTest(value string) []byte {
	data := []byte{0xff, 0xfe}
	for _, item := range utf16.Encode([]rune(value)) {
		data = append(data, byte(item), byte(item>>8))
	}
	return data
}
