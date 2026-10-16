package history

import "testing"

func TestDNSAndCurrentSnapshotCannotEstablishHistoricalCoverage(t *testing.T) {
	c := historyCoverage(Snapshot{Records: []Record{{Source: "DNS 缓存", Query: "example.invalid"}, {Source: "netstat 快照", Time: "2026-10-14 12:00:00", PID: "42"}}}, 500)
	if c.Status != "Insufficient telemetry" {
		t.Fatalf("snapshot was treated as historical telemetry: %+v", c)
	}
	c = historyCoverage(Snapshot{Records: []Record{{Source: "Sysmon", Time: "2026-10-13 10:00:00"}}}, 1)
	if c.Status != "Observed" || !c.LimitReached || !c.PossiblyTruncated {
		t.Fatalf("audit coverage incorrect: %+v", c)
	}
}
