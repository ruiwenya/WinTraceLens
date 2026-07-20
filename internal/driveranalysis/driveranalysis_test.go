package driveranalysis

import (
	"path/filepath"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestBuildSourceChecksReportsIndependentSourceDifferences(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing-driver.sys")
	modulePath := filepath.Join(t.TempDir(), "hidden-clue.sys")
	modules := []process.ModuleInfo{
		{Name: "hidden-clue.sys", Path: modulePath},
		{Name: "normal-kernel-component.dll", Path: filepath.Join(t.TempDir(), "normal-kernel-component.dll")},
	}
	ctx := analysisContext{
		services: []serviceEntry{{Name: "orphan-service", ExpandedImage: missingPath}},
		files:    []diskEntry{{Name: "disk-only.sys", Path: filepath.Join(t.TempDir(), "disk-only.sys")}},
		events:   []eventEntry{{Source: "System", EventID: "7045", ServiceName: "orphan-service"}},
	}

	checks := buildSourceChecks(modules, ctx, []string{"Security 日志不可读"})
	byID := make(map[string]SourceCheck, len(checks))
	for _, check := range checks {
		byID[check.ID] = check
	}

	assertCheckCount(t, byID, "kernel-registry", 1)
	assertCheckCount(t, byID, "kernel-disk", 1)
	assertCheckCount(t, byID, "registry-disk", 1)
	assertCheckCount(t, byID, "registry-kernel", 1)
	assertCheckCount(t, byID, "disk-orphan", 1)
	assertCheckCount(t, byID, "load-events", 1)
	assertCheckCount(t, byID, "coverage", 1)
	if byID["coverage"].Status != "采集不完整" {
		t.Fatalf("coverage status = %q, want 采集不完整", byID["coverage"].Status)
	}
}

func TestNewSourceCheckUsesNeutralStatusWithoutDifferences(t *testing.T) {
	check := newSourceCheck("test", "test", nil, "detail", "action", "高", "高关注")
	if check.Count != 0 || check.Level != "信息" || check.Status != "未见差异" {
		t.Fatalf("unexpected neutral check: %+v", check)
	}
}

func assertCheckCount(t *testing.T, checks map[string]SourceCheck, id string, want int) {
	t.Helper()
	check, ok := checks[id]
	if !ok {
		t.Fatalf("missing check %q", id)
	}
	if check.Count != want {
		t.Fatalf("check %q count = %d, want %d", id, check.Count, want)
	}
}
