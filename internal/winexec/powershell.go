package winexec

import (
	"context"
	"os/exec"
	"strings"
)

const PowerShellCollectorMarker = "WTL-COLLECTOR"

const powerShellCollectorHeader = "# WTL-COLLECTOR WinTraceLens evidence collector\n$global:WTLCollectorMarker = 'WTL-COLLECTOR'\n"

func PowerShell(script string) *exec.Cmd {
	return Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", MarkPowerShellScript(script))
}

func PowerShellContext(ctx context.Context, script string) *exec.Cmd {
	return CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", MarkPowerShellScript(script))
}

func MarkPowerShellScript(script string) string {
	if strings.Contains(script, PowerShellCollectorMarker) {
		return script
	}
	return powerShellCollectorHeader + script
}
