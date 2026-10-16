//go:build windows

package securitylog

import (
	"strings"
	"testing"
)

func TestPersistenceXPathLiteralDoesNotInterpretNames(t *testing.T) {
	for _, value := range []string{"Test Service", `测试服务`, "A'B", `A"B`} {
		literal, ok := eventXPathLiteral(value)
		if !ok || len(literal) < len(value)+2 {
			t.Fatalf("literal unavailable: %q", value)
		}
	}
	if _, ok := eventXPathLiteral(`A'"B`); ok {
		t.Fatal("unsupported XPath quote combination accepted")
	}
}

func TestReadOnlyPersistenceEventQueryAcceptsGeneratedFilter(t *testing.T) {
	_, warnings := CollectPersistenceMatches([]string{"WinTraceLensNonexistentReadOnlyFixture"})
	for _, warning := range warnings {
		lower := strings.ToLower(warning)
		if strings.Contains(lower, "syntax") || strings.Contains(lower, "invalid query") || strings.Contains(lower, "parameter set") || strings.Contains(lower, "解析失败") || strings.Contains(lower, "语法") {
			t.Fatalf("generated event query invalid: %s", warning)
		}
	}
}
