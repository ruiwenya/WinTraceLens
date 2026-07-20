package investigation

import (
	"testing"
	"time"
)

func TestAddTimelineFiltersHistoricalEventsButKeepsCurrentSnapshot(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.Local)
	end := time.Date(2026, 7, 7, 23, 59, 59, 0, time.Local)
	var snapshot Snapshot
	opts := Options{StartTime: start, EndTime: end}

	snapshot.addTimeline(opts, TimelineEvent{Time: "2026-06-30 23:59:59", Source: "old"})
	snapshot.addTimeline(opts, TimelineEvent{Time: "2026-07-03 10:20:30", Source: "inside"})
	snapshot.addTimeline(opts, TimelineEvent{Time: "2026-07-13 10:20:30", Source: "current", Current: true})

	if len(snapshot.Timeline) != 2 {
		t.Fatalf("timeline count = %d, want 2", len(snapshot.Timeline))
	}
	if snapshot.Timeline[0].Source != "inside" || snapshot.Timeline[1].Source != "current" {
		t.Fatalf("unexpected timeline: %+v", snapshot.Timeline)
	}
}

func TestParseTimeSupportsWindowsAndRFC3339Values(t *testing.T) {
	for _, value := range []string{
		"2026-07-13 10:20:30",
		"2026-07-13T10:20:30.1234567+08:00",
		"2026-07-13T02:20:30Z",
	} {
		if parseTime(value).IsZero() {
			t.Fatalf("parseTime(%q) returned zero", value)
		}
	}
}

func TestApplyScenarioHighlightsSMBEvidenceWithoutMutatingInput(t *testing.T) {
	input := Snapshot{Entities: []Entity{
		{Group: "实时网络连接", Kind: "网络连接", Name: "System", PID: "4", Remote: "10.20.30.40:445"},
		{Group: "实时网络连接", Kind: "网络连接", Name: "chrome.exe", PID: "100", Remote: "1.1.1.1:443"},
	}}

	result := ApplyScenario(input, "smb")
	if result.Scenario != "smb" || result.FocusCount != 1 {
		t.Fatalf("scenario=%q focus=%d, want smb/1", result.Scenario, result.FocusCount)
	}
	if !result.Entities[0].Focus || result.Entities[0].ScenarioScore < 5 {
		t.Fatalf("SMB evidence was not highlighted: %+v", result.Entities[0])
	}
	if result.Entities[1].Focus {
		t.Fatalf("unrelated HTTPS connection was highlighted: %+v", result.Entities[1])
	}
	if input.Entities[0].Focus || input.Entities[0].ScenarioScore != 0 {
		t.Fatalf("ApplyScenario mutated cached input: %+v", input.Entities[0])
	}
}
