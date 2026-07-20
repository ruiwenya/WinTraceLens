package server

import "testing"

func TestSanitizeCSVRowPreventsFormulaInjection(t *testing.T) {
	input := []string{"=cmd()", "+SUM(1,2)", "-2+3", "@IMPORT", " normal", "safe"}
	got := sanitizeCSVRow(input)
	want := []string{"'=cmd()", "'+SUM(1,2)", "'-2+3", "'@IMPORT", "normal", "safe"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("column %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMatchesCSVQuerySupportsRegularExpressions(t *testing.T) {
	values := []string{"svchost.exe", "10.20.30.40:445", `C:\Windows\System32\svchost.exe`}
	for _, query := range []string{`/10\.20\.\d+\.40:445/`, `re:SVCHOST\.EXE`} {
		if !matchesCSVQuery(query, values) {
			t.Fatalf("query %q should match", query)
		}
	}
	if matchesCSVQuery(`/10\.20\.\d+\.41/`, values) {
		t.Fatal("non-matching regular expression returned true")
	}
	if matchesCSVQuery(`/[invalid/`, values) {
		t.Fatal("invalid regular expression returned true")
	}
}
