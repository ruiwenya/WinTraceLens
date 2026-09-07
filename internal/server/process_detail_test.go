package server

import (
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

func TestRelatedHistoryRecordsRequiresExactPIDAndLifetime(t *testing.T) {
	proc := process.Info{PID: 120, Name: "agent.exe", Path: `C:\Program Files\Agent\agent.exe`, CreatedAt: "2026-09-05 10:00:00"}
	items := []history.Record{
		{Time: "2026-09-05 10:01:00", PID: "120", Process: proc.Path},
		{Time: "2026-09-05 10:01:00", PID: "1200", Process: proc.Path},
		{Time: "2026-09-05 09:59:00", PID: "120", Process: proc.Path},
		{Time: "2026-09-05 10:02:00", Process: `C:\Other\agent.exe`},
	}
	got := relatedHistoryRecords(items, proc)
	if len(got) != 1 || got[0].PID != "120" {
		t.Fatalf("unexpected history correlation: %#v", got)
	}
}

func TestRelatedSecurityEventsDoesNotUsePIDSubstring(t *testing.T) {
	proc := process.Info{PID: 120, Name: "agent.exe", Path: `C:\Program Files\Agent\agent.exe`, CreatedAt: "2026-09-05 10:00:00"}
	items := []securitylog.Event{
		{Time: "2026-09-05 10:01:00", Process: "ProcessID=120"},
		{Time: "2026-09-05 10:01:00", Process: "ProcessID=1200"},
		{Time: "2026-09-05 10:01:00", Process: `C:\Other\agent.exe`},
		{Time: "2026-09-05 10:01:00", Command: `"C:\Program Files\Agent\agent.exe" --run`},
	}
	got := relatedSecurityEvents(items, proc)
	if len(got) != 2 {
		t.Fatalf("unexpected security correlation: %#v", got)
	}
}

func TestSelectProcessFamilyRejectsReusedParentPID(t *testing.T) {
	items := []process.Info{
		{PID: 10, ParentPID: 20, CreatedAt: "2026-09-05 10:00:00", ParentCreatedAt: "2026-09-05 09:00:00"},
		{PID: 20, CreatedAt: "2026-09-05 11:00:00"},
		{PID: 30, ParentPID: 10, CreatedAt: "2026-09-05 10:05:00", ParentCreatedAt: "2026-09-05 10:00:00"},
		{PID: 31, ParentPID: 10, CreatedAt: "2026-09-05 09:00:00", ParentCreatedAt: "2026-09-05 08:00:00"},
	}
	_, parent, children, ok := selectProcessFamily(items, 10)
	if !ok || parent != nil {
		t.Fatalf("reused parent PID accepted: %#v", parent)
	}
	if len(children) != 1 || children[0].PID != 30 {
		t.Fatalf("unexpected children: %#v", children)
	}
}
