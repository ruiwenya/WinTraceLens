package threatanalysis

import (
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestExpectedBrowserDoesNotSuppressHardMemorySignal(t *testing.T) {
	item := process.Info{
		PID: 4120, Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		Signature: "已签名", ConnectionCount: 1,
	}
	memory := map[uint32][]memoryscan.Record{
		item.PID: {{
			Level: "高", Category: "线程入口", Base: "0x100000", HasPE: true,
			HardSignals: []string{"线程入口位于 MEM_PRIVATE 可执行内存"},
		}},
	}
	result, ok := analyzeProcess(item, persistenceIndex{}, traceIndex{byPath: map[string][]filetrace.Record{}}, memory, false)
	if !ok {
		t.Fatal("hard memory signal in trusted browser was suppressed")
	}
	if !strings.Contains(result.Related, "内存异常") || strings.Contains(result.Related, "常见软件内存线索") {
		t.Fatalf("unexpected related signals: %s", result.Related)
	}
}

func TestExpectedBrowserOrdinaryJITIsSuppressed(t *testing.T) {
	item := process.Info{
		PID: 4120, Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		Signature: "已签名",
	}
	memory := map[uint32][]memoryscan.Record{
		item.PID: {{Level: "低", Category: "可执行内存", Base: "0x100000", Reason: "小型动态代码区域"}},
	}
	if _, ok := analyzeProcess(item, persistenceIndex{}, traceIndex{byPath: map[string][]filetrace.Record{}}, memory, false); ok {
		t.Fatal("ordinary browser JIT record should be suppressed without another suspicious signal")
	}
}

func TestProcessTimesDetectsParentPIDReuse(t *testing.T) {
	child, parent, ok := processTimes("2026-08-03 10:00:00", "2026-08-03 10:05:00")
	if !ok || !parent.After(child) {
		t.Fatalf("process time parsing failed: child=%v parent=%v ok=%v", child, parent, ok)
	}
}
