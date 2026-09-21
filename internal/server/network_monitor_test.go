package server

import (
	"testing"
	"time"
)

func TestConnectionMonitorRetainsIntermittentConnection(t *testing.T) {
	monitor := newConnectionMonitor()
	firstSeen := time.Date(2026, 9, 16, 10, 30, 0, 0, time.Local)
	connection := liveConnectionItem{
		PID:        3996,
		Process:    "sample.exe",
		Path:       `C:\ProgramData\sample.exe`,
		Protocol:   "TCPv4",
		Local:      "192.168.1.20:51000",
		Remote:     "203.0.113.8:445",
		RemoteIP:   "203.0.113.8",
		RemotePort: 445,
		RemoteKind: "公网/外部",
		State:      "SYN-SENT",
	}

	monitor.observe([]liveConnectionItem{connection}, firstSeen)
	monitor.observe(nil, firstSeen.Add(time.Second))
	connection.State = "ESTABLISHED"
	monitor.observe([]liveConnectionItem{connection}, firstSeen.Add(2*time.Second))

	snapshot := monitor.snapshot()
	if snapshot.Count != 1 {
		t.Fatalf("expected one retained connection, got %d", snapshot.Count)
	}
	item := snapshot.Items[0]
	if item.Occurrences != 2 {
		t.Fatalf("expected two appearances, got %d", item.Occurrences)
	}
	if item.Samples != 2 {
		t.Fatalf("expected two matching samples, got %d", item.Samples)
	}
	if !item.CurrentlyActive {
		t.Fatal("expected reappearing connection to be active")
	}
	if item.FirstSeen != "2026-09-16 10:30:00" || item.LastSeen != "2026-09-16 10:30:02" {
		t.Fatalf("unexpected observation window: %s - %s", item.FirstSeen, item.LastSeen)
	}
	if item.State != "ESTABLISHED" {
		t.Fatalf("expected latest state, got %q", item.State)
	}
}

func TestConnectionMonitorIgnoresListenerRows(t *testing.T) {
	monitor := newConnectionMonitor()
	monitor.observe([]liveConnectionItem{{
		PID:        4,
		Protocol:   "TCPv4",
		Local:      "0.0.0.0:445",
		Remote:     "0.0.0.0:0",
		RemoteIP:   "0.0.0.0",
		RemotePort: 0,
		State:      "LISTENING",
	}}, time.Now())
	if snapshot := monitor.snapshot(); snapshot.Count != 0 {
		t.Fatalf("expected listener without a remote target to be ignored, got %d records", snapshot.Count)
	}
}
