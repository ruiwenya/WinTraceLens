//go:build windows

package driveranalysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
	"golang.org/x/sys/windows/registry"
)

func collectDriverFiles() ([]diskEntry, error) {
	systemRoot := os.Getenv("SystemRoot")
	if strings.TrimSpace(systemRoot) == "" {
		systemRoot = `C:\Windows`
	}
	root := filepath.Join(systemRoot, "System32", "drivers")
	items := make([]diskEntry, 0, 512)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".sys") {
			return nil
		}
		items = append(items, diskEntry{Name: entry.Name(), Path: filepath.Clean(path)})
		return nil
	})
	return items, err
}

func collectDriverServices() ([]serviceEntry, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	items := make([]serviceEntry, 0, len(names))
	for _, name := range names {
		key, err := registry.OpenKey(root, name, registry.READ)
		if err != nil {
			continue
		}
		item := serviceEntry{
			Name:         name,
			RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\` + name,
		}
		item.Type, _, _ = key.GetIntegerValue("Type")
		if item.Type&0x3 == 0 {
			key.Close()
			continue
		}
		item.Start, _, _ = key.GetIntegerValue("Start")
		item.ErrorControl, _, _ = key.GetIntegerValue("ErrorControl")
		item.DisplayName = readRegistryString(key, "DisplayName")
		item.ImagePath = readRegistryString(key, "ImagePath")
		item.Group = readRegistryString(key, "Group")
		item.TypeText = driverTypeText(item.Type)
		item.StartText = driverStartText(item.Start)
		item.ExpandedImage = normalizeDriverImagePath(expandRegistryString(item.ImagePath))
		if item.ExpandedImage == "" && item.ImagePath == "" {
			item.ExpandedImage = normalizeDriverImagePath(`System32\Drivers\` + item.Name + `.sys`)
		}
		items = append(items, item)
		key.Close()
	}
	return items, nil
}

func readRegistryString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func expandRegistryString(value string) string {
	if value == "" {
		return ""
	}
	expanded, err := registry.ExpandString(value)
	if err != nil {
		return value
	}
	return expanded
}

func driverTypeText(value uint64) string {
	parts := make([]string, 0, 2)
	if value&0x1 != 0 {
		parts = append(parts, "Kernel Driver")
	}
	if value&0x2 != 0 {
		parts = append(parts, "File System Driver")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%X", value)
	}
	return strings.Join(parts, "+")
}

func driverStartText(value uint64) string {
	switch value {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Auto"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return fmt.Sprintf("%d", value)
	}
}

type driverEventSnapshot struct {
	Events           []eventEntry `json:"events"`
	CollectionErrors []string     `json:"collectionErrors"`
}

func collectDriverEvents(max int) ([]eventEntry, []string) {
	if max <= 0 {
		max = 800
	}
	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$events = New-Object 'System.Collections.Generic.List[object]'
$errors = New-Object 'System.Collections.Generic.List[string]'

function Clean-Value($value) {
  if ($null -eq $value) { return '' }
  return ([string]$value).Trim()
}

function Has-Text($value) {
  if ($null -eq $value) { return $false }
  return (([string]$value).Trim().Length -gt 0)
}

function Add-Error($source, $message) {
  $errors.Add(([string]$source + ': ' + [string]$message)) | Out-Null
}

function Get-EventDataMap($event) {
  $map = @{}
  try {
    [xml]$xml = $event.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
      if ($item.Name) { $map[$item.Name] = [string]$item.'#text' }
    }
    foreach ($container in @($xml.Event.UserData.ChildNodes)) {
      foreach ($node in @($container.ChildNodes)) {
        if ($node.NodeType -eq 'Element') { $map[$node.Name] = [string]$node.InnerText }
      }
    }
  } catch {}
  return $map
}

function First-Value($data, $names) {
  foreach ($name in @($names)) {
    if ($data.ContainsKey($name)) {
      $value = [string]$data[$name]
      if (Has-Text $value) { return $value }
    }
  }
  return ''
}

function Data-Summary($data) {
  $parts = @()
  foreach ($key in @($data.Keys | Sort-Object)) {
    $value = [string]$data[$key]
    if (Has-Text $value) { $parts += ([string]$key + '=' + $value) }
  }
  return ($parts -join '; ')
}

function Add-DriverEvent($source, $event, $data, $serviceName, $imagePath, $account, $details) {
  $events.Add([pscustomobject]@{
    Time=$event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Source=[string]$source
    EventID=[string]$event.Id
    ServiceName=(Clean-Value $serviceName)
    ImagePath=(Clean-Value $imagePath)
    Account=(Clean-Value $account)
    Details=(Clean-Value $details)
  }) | Out-Null
}

try {
  Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045 } -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $serviceName = First-Value $data @('ServiceName','param1','Param1')
    $imagePath = First-Value $data @('ImagePath','ServiceFileName','param2','Param2')
    $account = First-Value $data @('AccountName','ServiceAccount','param5','Param5')
    $serviceType = First-Value $data @('ServiceType','param3','Param3')
    $startType = First-Value $data @('StartType','ServiceStartType','param4','Param4')
    $details = ('ServiceType=' + $serviceType + '; StartType=' + $startType + '; ' + (Data-Summary $data))
    Add-DriverEvent 'System/Service Control Manager' $_ $data $serviceName $imagePath $account $details
  }
} catch {
  Add-Error 'System 7045' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4697 } -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $serviceName = First-Value $data @('ServiceName','param1','Param1')
    $imagePath = First-Value $data @('ServiceFileName','ImagePath','param2','Param2')
    $account = First-Value $data @('ServiceAccount','AccountName','param5','Param5')
    $details = Data-Summary $data
    Add-DriverEvent 'Security' $_ $data $serviceName $imagePath $account $details
  }
} catch {
  Add-Error 'Security 4697' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=6 } -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $imagePath = First-Value $data @('ImageLoaded','Image','TargetFilename','param1','Param1')
    $details = Data-Summary $data
    Add-DriverEvent 'Sysmon DriverLoad' $_ $data '' $imagePath (First-Value $data @('User','UserName')) $details
  }
} catch {
  Add-Error 'Sysmon 6' $_.Exception.Message
}

[pscustomobject]@{
  Events=@($events | Sort-Object Time -Descending | Select-Object -First $max)
  CollectionErrors=@($errors)
} | ConvertTo-Json -Compress -Depth 5
`, max)

	cmd := winexec.PowerShell(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, []string{"驱动事件日志: " + msg}
	}
	data := bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xEF, 0xBB, 0xBF})
	if len(data) == 0 {
		return nil, []string{"驱动事件日志: 输出为空"}
	}
	var snapshot driverEventSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, []string{"驱动事件日志 JSON 解析失败: " + err.Error()}
	}
	return snapshot.Events, localizeDriverEventErrors(snapshot.CollectionErrors)
}

func localizeDriverEventErrors(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		lower := strings.ToLower(value)
		switch {
		case strings.Contains(lower, "no events were found") || strings.Contains(value, "找不到任何与指定的选择条件匹配的事件"):
			continue
		case strings.Contains(lower, "there is not an event log") || (strings.Contains(value, "没有与") && strings.Contains(value, "匹配的事件日志")):
			continue
		case strings.Contains(lower, "access is denied"):
			out = append(out, strings.SplitN(value, ":", 2)[0]+": 当前权限不足，建议使用管理员权限运行后重试。")
		default:
			out = append(out, value)
		}
	}
	return out
}
