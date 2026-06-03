package yaraengine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestMain(m *testing.M) {
	if os.Getenv("YARAENGINE_HELPER") == "1" {
		fakeYARA()
		return
	}
	os.Exit(m.Run())
}

func TestParseMatchedRules(t *testing.T) {
	output := "SuspiciousA C:\\temp\\a.exe\r\nwarning: something\r\nns:SuspiciousB 1234\nerror 19440\nerror scanning process 19440: access denied\nC:\\rules\\bad.yar(1): error: invalid\nSuspiciousA C:\\temp\\a.exe\n"
	got := parseMatchedRules(output)
	want := []string{"SuspiciousA", "ns:SuspiciousB"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMatchedRules() = %#v, want %#v", got, want)
	}
}

func TestNormalizeLimits(t *testing.T) {
	if normalizeTimeout(0) != 15 || normalizeTimeout(999) != 300 {
		t.Fatalf("unexpected timeout normalization")
	}
	if normalizeConcurrency(0) != 2 || normalizeConcurrency(99) != 6 {
		t.Fatalf("unexpected concurrency normalization")
	}
}

func TestValidateAndScanWithExternalEngine(t *testing.T) {
	t.Setenv("YARAENGINE_HELPER", "1")
	t.Setenv("YARAENGINE_MATCH_EXIT_1", "1")

	targetFile, err := os.CreateTemp(t.TempDir(), "target-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	targetPath := targetFile.Name()
	if _, err := targetFile.WriteString("test"); err != nil {
		t.Fatal(err)
	}
	if err := targetFile.Close(); err != nil {
		t.Fatal(err)
	}

	rules := "rule MATCH_ALWAYS { condition: true }"
	validate := Validate(context.Background(), ValidateRequest{
		EnginePath:     os.Args[0],
		Rules:          rules,
		TimeoutSeconds: 5,
	})
	if !validate.Valid {
		t.Fatalf("Validate() valid = false, errors = %#v", validate.Errors)
	}

	scan := Scan(context.Background(), ScanRequest{
		EnginePath:     os.Args[0],
		Rules:          rules,
		Paths:          []string{targetPath},
		TimeoutSeconds: 5,
		Concurrency:    1,
	}, []process.Info{{
		PID:  1234,
		Name: "demo.exe",
		Path: targetPath,
	}})
	if !scan.Valid {
		t.Fatalf("Scan() valid = false, rule errors = %#v", scan.RuleErrors)
	}
	if len(scan.Results) != 1 {
		t.Fatalf("Scan() results = %d, want 1", len(scan.Results))
	}
	result := scan.Results[0]
	if !result.Matched || !reflect.DeepEqual(result.Rules, []string{"MATCH_ALWAYS"}) {
		t.Fatalf("unexpected scan result: %#v", result)
	}
	if result.PID != 1234 || result.ProcessName != "demo.exe" {
		t.Fatalf("process association missing: %#v", result)
	}
	if scan.FinishedAt == "" {
		t.Fatalf("Scan() did not set FinishedAt")
	}
}

func TestScanProcessErrorIsNotMatch(t *testing.T) {
	t.Setenv("YARAENGINE_HELPER", "1")
	t.Setenv("YARAENGINE_PROCESS_ERROR", "1")

	scan := Scan(context.Background(), ScanRequest{
		EnginePath:           os.Args[0],
		Rules:                "rule MATCH_ALWAYS { condition: true }",
		PIDs:                 []uint32{19440},
		IncludeProcessMemory: true,
		TimeoutSeconds:       5,
		Concurrency:          1,
	}, nil)
	if !scan.Valid {
		t.Fatalf("Scan() valid = false, rule errors = %#v", scan.RuleErrors)
	}
	if len(scan.Results) != 1 {
		t.Fatalf("Scan() results = %d, want 1", len(scan.Results))
	}
	result := scan.Results[0]
	if result.Matched || len(result.Rules) != 0 {
		t.Fatalf("process error was treated as a match: %#v", result)
	}
	if result.Error == "" || !strings.Contains(result.Error, "error scanning process") {
		t.Fatalf("process error missing: %#v", result)
	}
}

func TestRuleDirectoryAndFolderScan(t *testing.T) {
	t.Setenv("YARAENGINE_HELPER", "1")

	base := t.TempDir()
	ruleDir := base + string(os.PathSeparator) + "rules"
	targetDir := base + string(os.PathSeparator) + "targets"
	if err := os.Mkdir(ruleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	validRule := ruleDir + string(os.PathSeparator) + "valid.yar"
	validRule2 := ruleDir + string(os.PathSeparator) + "valid2.yar"
	invalidRule := ruleDir + string(os.PathSeparator) + "invalid.yar"
	if err := os.WriteFile(validRule, []byte("rule MATCH_ALWAYS { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(validRule2, []byte("rule MATCH_OTHER { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidRule, []byte("syntax_error"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetPath := targetDir + string(os.PathSeparator) + "a.bin"
	if err := os.WriteFile(targetPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	rules := ValidateRules(context.Background(), RulesRequest{
		EnginePath:     os.Args[0],
		RuleDir:        ruleDir,
		TimeoutSeconds: 5,
	})
	if rules.ValidFiles != 2 || rules.InvalidFiles != 1 {
		t.Fatalf("unexpected rules response: %#v", rules)
	}

	scan := Scan(context.Background(), ScanRequest{
		EnginePath:     os.Args[0],
		RuleDir:        ruleDir,
		FolderPaths:    []string{targetDir},
		Recursive:      true,
		TimeoutSeconds: 5,
		Concurrency:    1,
	}, []process.Info{{
		PID:  4321,
		Name: "folder-demo.exe",
		Path: targetPath,
	}})
	if !scan.Valid {
		t.Fatalf("Scan() valid = false, rule errors = %#v", scan.RuleErrors)
	}
	if len(scan.RuleFiles) != 3 {
		t.Fatalf("Scan() rule files = %d, want 3", len(scan.RuleFiles))
	}
	if len(scan.Results) != 1 {
		t.Fatalf("Scan() results = %d, want 1", len(scan.Results))
	}
	result := scan.Results[0]
	if result.RuleFile != "规则集合(2)" || !result.Matched || result.PID != 4321 {
		t.Fatalf("unexpected directory scan result: %#v", result)
	}
	if !reflect.DeepEqual(result.Rules, []string{"MATCH_ALWAYS", "MATCH_OTHER"}) {
		t.Fatalf("unexpected matched rules: %#v", result.Rules)
	}
}

func fakeYARA() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("fake-yara 0.0")
		os.Exit(0)
	}
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "error: missing arguments")
		os.Exit(2)
	}
	rules, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ruleText := expandFakeIncludes(string(rules))
	if strings.Contains(ruleText, "syntax_error") {
		fmt.Fprintln(os.Stderr, "error: invalid rule")
		os.Exit(1)
	}
	if os.Getenv("YARAENGINE_PROCESS_ERROR") == "1" && isDigits(os.Args[2]) {
		fmt.Fprintf(os.Stderr, "error scanning process %s: access denied\n", os.Args[2])
		os.Exit(1)
	}
	matched := false
	if strings.Contains(ruleText, "MATCH_ALWAYS") {
		fmt.Printf("MATCH_ALWAYS %s\n", os.Args[2])
		matched = true
	}
	if strings.Contains(ruleText, "MATCH_OTHER") {
		fmt.Printf("MATCH_OTHER %s\n", os.Args[2])
		matched = true
	}
	if matched && os.Getenv("YARAENGINE_MATCH_EXIT_1") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func expandFakeIncludes(ruleText string) string {
	var out strings.Builder
	for _, line := range strings.Split(ruleText, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "include ") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(line, "include "))
		path = strings.Trim(path, `"`)
		path = filepath.FromSlash(path)
		data, err := os.ReadFile(path)
		if err == nil {
			out.Write(data)
			out.WriteString("\n")
		}
	}
	return out.String()
}
