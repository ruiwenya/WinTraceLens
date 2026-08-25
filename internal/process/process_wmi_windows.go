//go:build windows

package process

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

type wmiProcessJSON struct {
	PID          string `json:"pid"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	ParentPID    string `json:"parentPid"`
	CommandLine  string `json:"commandLine"`
	ThreadCount  string `json:"threadCount"`
	HandleCount  string `json:"handleCount"`
	WorkingSet   string `json:"workingSet"`
	PrivateBytes string `json:"privateBytes"`
}

func snapshotProcessesWMI() (map[uint32]processContext, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	script := `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$items = Get-WmiObject -Class Win32_Process -ErrorAction Stop | ForEach-Object {
  New-Object PSObject -Property @{
    pid = [string]$_.ProcessId
    name = [string]$_.Name
    path = [string]$_.ExecutablePath
    parentPid = [string]$_.ParentProcessId
    commandLine = [string]$_.CommandLine
    threadCount = [string]$_.ThreadCount
    handleCount = [string]$_.HandleCount
    workingSet = [string]$_.WorkingSetSize
    privateBytes = [string]$_.PrivatePageCount
  }
}
@($items) | ConvertTo-Json -Compress -Depth 3`
	out, err := winexec.PowerShellContext(ctx, script).CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(bytes.TrimPrefix(out, []byte{0xEF, 0xBB, 0xBF})))
		if detail != "" {
			return nil, fmt.Errorf("WMI 进程视图采集失败: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("WMI 进程视图采集失败: %w", err)
	}
	out = bytes.TrimPrefix(out, []byte{0xEF, 0xBB, 0xBF})
	data := bytes.TrimSpace(out)
	var raw []wmiProcessJSON
	if len(data) > 0 && data[0] == '{' {
		var one wmiProcessJSON
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("WMI 进程视图解析失败: %w", err)
		}
		raw = []wmiProcessJSON{one}
	} else if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("WMI 进程视图解析失败: %w", err)
	}
	result := make(map[uint32]processContext, len(raw))
	for _, item := range raw {
		pid := parseUint32(item.PID)
		if pid == 0 && strings.TrimSpace(item.PID) != "0" {
			continue
		}
		result[pid] = processContext{
			Name:               strings.TrimSpace(item.Name),
			Path:               strings.TrimSpace(item.Path),
			ParentPID:          parseUint32(item.ParentPID),
			CommandLine:        strings.TrimSpace(item.CommandLine),
			ThreadCount:        parseUint32(item.ThreadCount),
			HandleCount:        parseUint32(item.HandleCount),
			WorkingSetBytes:    parseUint64(item.WorkingSet),
			PrivateMemoryBytes: parseUint64(item.PrivateBytes),
		}
		if strings.Contains(strings.ToUpper(result[pid].CommandLine), winexec.PowerShellCollectorMarker) {
			delete(result, pid)
		}
	}
	return result, nil
}

func parseUint32(value string) uint32 {
	parsed, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	return uint32(parsed)
}

func parseUint64(value string) uint64 {
	parsed, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	return parsed
}
