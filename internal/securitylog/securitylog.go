package securitylog

import (
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

type Options struct {
	MaxRecords int
	StartTime  time.Time
	EndTime    time.Time
}

type Snapshot struct {
	Events           []Event  `json:"events"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
}

type Event struct {
	Time          string `json:"time"`
	Category      string `json:"category"`
	Source        string `json:"source"`
	EventID       string `json:"eventId"`
	Action        string `json:"action"`
	Account       string `json:"account"`
	Domain        string `json:"domain"`
	Subject       string `json:"subject"`
	LogonType     string `json:"logonType"`
	LogonTypeName string `json:"logonTypeName"`
	SourceIP      string `json:"sourceIp"`
	SourcePort    string `json:"sourcePort"`
	Workstation   string `json:"workstation"`
	Process       string `json:"process"`
	ServiceName   string `json:"serviceName"`
	Command       string `json:"command"`
	AuthPackage   string `json:"authPackage"`
	Status        string `json:"status"`
	FailureReason string `json:"failureReason"`
	TargetSID     string `json:"targetSid"`
	Provider      string `json:"provider"`
	Level         string `json:"level"`
	Message       string `json:"message"`
	Details       string `json:"details"`
}

func IsWinTraceLensCollectorEvent(event Event) bool {
	if event.Category != "PowerShell日志" && !strings.Contains(strings.ToLower(event.Source), "powershell") {
		return false
	}
	content := strings.ToLower(strings.Join([]string{event.Command, event.Message, event.Details}, " "))
	if strings.Contains(content, strings.ToLower(winexec.PowerShellCollectorMarker)) || strings.Contains(content, "wtlcollectormarker") {
		return true
	}
	legacyPairs := [][2]string{
		{"function new-eventfilter", "convert-securityaction"},
		{"$customrootsjson", "function add-artifactrecord"},
		{"function suspicion-forfile", "function add-filelist"},
		{"function data-summary", "function join-endpoint"},
		{"function get-wmicompat", "win32_service"},
		{"function walk-folder", "schedule.service"},
		{"function add-driverevent", "system/7045"},
		{"function test-eventsource", "windows filtering platform"},
		{"win32_perfformatteddata_perfproc_process", "parentprocessid,commandline,workingsetsize"},
		{"get-ciminstance win32_process", "processid,parentprocessid | convertto-json"},
	}
	for _, pair := range legacyPairs {
		if strings.Contains(content, pair[0]) && strings.Contains(content, pair[1]) {
			return true
		}
	}
	return false
}

func FilterCollectorEvents(events []Event) []Event {
	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		if !IsWinTraceLensCollectorEvent(event) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func IsLowValuePowerShellEvent(event Event) bool {
	if !IsPowerShellEvent(event) {
		return false
	}
	switch event.EventID {
	case "400", "403", "600", "4105", "4106":
		return true
	case "4103":
		return !IsSuspiciousPowerShellEvent(event)
	case "4104":
		return !IsSuspiciousPowerShellEvent(event) && isGeneratedPowerShellModule(contentForPowerShell(event))
	default:
		return false
	}
}

func IsSuspiciousPowerShellEvent(event Event) bool {
	if !IsPowerShellEvent(event) {
		return false
	}
	content := contentForPowerShell(event)
	markers := []string{
		"encodedcommand", "frombase64string", "downloadstring", "downloadfile",
		"invoke-webrequest", "invoke-restmethod", "invoke-expression", "reflection.assembly",
		"executionpolicy bypass", "windowstyle hidden", "http://", "https://",
	}
	for _, marker := range markers {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

func IsPowerShellEvent(event Event) bool {
	if event.Category == "PowerShell日志" {
		return true
	}
	source := strings.ToLower(event.Source + " " + event.Provider)
	return strings.Contains(source, "powershell")
}

// FilterPowerShellNoise removes lifecycle and generated module noise while
// retaining suspicious commands and one copy of each remaining benign event.
func FilterPowerShellNoise(events []Event) []Event {
	filtered := make([]Event, 0, len(events))
	seen := make(map[string]struct{})
	for _, event := range events {
		if IsWinTraceLensCollectorEvent(event) || IsLowValuePowerShellEvent(event) {
			continue
		}
		if IsPowerShellEvent(event) && !IsSuspiciousPowerShellEvent(event) {
			key := event.EventID + "\x00" + normalizePowerShellContent(contentForPowerShell(event))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func contentForPowerShell(event Event) string {
	return strings.ToLower(strings.Join([]string{event.Command, event.Message, event.Details}, " "))
}

func isGeneratedPowerShellModule(content string) bool {
	markers := []string{
		"__cmdletization_",
		"microsoft.powershell.cmdletization.",
		"$script:mymodule = $myinvocation.mycommand.scriptblock.module",
		"microsoft.powershell.core\\set-strictmode -off",
		".cdxml-help.xml",
		"export-modulemember -function",
	}
	for _, marker := range markers {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

func normalizePowerShellContent(content string) string {
	return strings.Join(strings.Fields(content), " ")
}
