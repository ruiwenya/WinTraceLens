//go:build windows

package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

func Collect(opts Options) (Snapshot, error) {
	maxRecords := opts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 500
	}
	if maxRecords > 5000 {
		maxRecords = 5000
	}

	startRaw := psDateLiteral(opts.StartTime)
	endRaw := psDateLiteral(opts.EndTime)

	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$startTimeRaw = %q
$endTimeRaw = %q
$startTime = if ([string]::IsNullOrWhiteSpace($startTimeRaw)) { $null } else { [datetime]::ParseExact($startTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$endTime = if ([string]::IsNullOrWhiteSpace($endTimeRaw)) { $null } else { [datetime]::ParseExact($endTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$records = New-Object 'System.Collections.Generic.List[object]'
$errors = New-Object 'System.Collections.Generic.List[string]'

function Add-Record($time, $source, $eventId, $process, $procId, $proto, $local, $remote, $query, $action, $user, $details) {
  $records.Add([pscustomobject]@{
    Time=[string]$time
    Source=[string]$source
    EventID=[string]$eventId
    Process=[string]$process
    PID=[string]$procId
    Proto=[string]$proto
    Local=[string]$local
    Remote=[string]$remote
    Query=[string]$query
    Action=[string]$action
    User=[string]$user
    Details=[string]$details
  }) | Out-Null
}

function Add-Error($source, $message) {
  $errors.Add(([string]$source + ': ' + [string]$message)) | Out-Null
}

function Get-EventDataMap($event) {
  $map = @{}
  try {
    [xml]$xml = $event.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
      if ($item.Name) {
        $map[$item.Name] = [string]$item.'#text'
      }
    }
    foreach ($container in @($xml.Event.UserData.ChildNodes)) {
      foreach ($node in @($container.ChildNodes)) {
        if ($node.NodeType -eq 'Element') {
          $map[$node.Name] = [string]$node.InnerText
        }
      }
    }
  } catch {}
  return $map
}

function First-Value($data, $names) {
  foreach ($name in @($names)) {
    if ($data.ContainsKey($name)) {
      $value = [string]$data[$name]
      if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
  }
  return ''
}

function Data-Summary($data) {
  $parts = @()
  foreach ($key in @($data.Keys | Sort-Object)) {
    $value = [string]$data[$key]
    if (-not [string]::IsNullOrWhiteSpace($value)) {
      $parts += ([string]$key + '=' + $value)
    }
  }
  return ($parts -join '; ')
}

function Join-Endpoint($address, $port) {
  if ([string]::IsNullOrWhiteSpace([string]$address)) { return '' }
  if ([string]::IsNullOrWhiteSpace([string]$port) -or [string]$port -eq '0') { return [string]$address }
  return ([string]$address + ':' + [string]$port)
}

function Convert-Protocol($proto) {
  switch ([string]$proto) {
    '6' { return 'TCP' }
    '17' { return 'UDP' }
    default { return [string]$proto }
  }
}

function New-EventFilter($logName, $ids) {
  $filter = @{ LogName = $logName }
  if ($null -ne $ids) { $filter.Id = $ids }
  if ($null -ne $startTime) { $filter.StartTime = $startTime }
  if ($null -ne $endTime) { $filter.EndTime = $endTime }
  return $filter
}

function In-TimeRange($value) {
  if ([string]::IsNullOrWhiteSpace([string]$value)) { return $true }
  try {
    $time = [datetime]::Parse([string]$value, [Globalization.CultureInfo]::InvariantCulture)
    if ($null -ne $startTime -and $time -lt $startTime) { return $false }
    if ($null -ne $endTime -and $time -gt $endTime) { return $false }
    return $true
  } catch {
    return $true
  }
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-Sysmon/Operational' @(3,22)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    if ($_.Id -eq 3) {
      Add-Record $time 'Sysmon' $_.Id $data['Image'] $data['ProcessId'] $data['Protocol'] (Join-Endpoint $data['SourceIp'] $data['SourcePort']) (Join-Endpoint $data['DestinationIp'] $data['DestinationPort']) '' $data['Initiated'] $data['User'] $data['DestinationHostname']
    } elseif ($_.Id -eq 22) {
      Add-Record $time 'Sysmon DNS' $_.Id $data['Image'] $data['ProcessId'] '' '' '' $data['QueryName'] '' $data['User'] $data['QueryResults']
    }
  }
} catch {
  Add-Error 'Sysmon' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-DNS-Client/Operational' $null) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    $query = First-Value $data @('QueryName','QName','Name','HostName','Hostname','Query')
    $result = First-Value $data @('QueryResults','Results','Response','Answers','Address','IpAddress')
    $procId = First-Value $data @('ClientProcessId','ProcessId','ProcessID','PID')
    $process = First-Value $data @('Image','ProcessName','Application','AppName')
    $details = Data-Summary $data
    if ([string]::IsNullOrWhiteSpace($query)) { $query = $_.ProviderName }
    if (-not [string]::IsNullOrWhiteSpace($result)) {
      if ([string]::IsNullOrWhiteSpace($details)) { $details = $result } else { $details = ('结果=' + $result + '; ' + $details) }
    }
    Add-Record $time 'DNS Client 日志' $_.Id $process $procId '' '' '' $query '' '' $details
  }
} catch {
  Add-Error 'DNS Client 日志' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Security' @(5156,5157)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    $action = if ($_.Id -eq 5156) { '允许' } else { '阻止' }
    Add-Record $time '安全日志 WFP' $_.Id $data['Application'] $data['ProcessID'] (Convert-Protocol $data['Protocol']) (Join-Endpoint $data['SourceAddress'] $data['SourcePort']) (Join-Endpoint $data['DestAddress'] $data['DestPort']) '' $action '' $data['LayerName']
  }
} catch {
  Add-Error '安全日志 WFP' $_.Exception.Message
}

try {
  Get-DnsClientCache -ErrorAction Stop | Select-Object -First $max | ForEach-Object {
    $data = @($_.Data | Where-Object { $_ }) -join '; '
    Add-Record '' 'DNS 缓存' '' '' '' '' '' '' $_.Entry '' '' $data
  }
} catch {
  try {
    $names = @()
    ipconfig.exe /displaydns | ForEach-Object {
      $line = [string]$_
      if ($line -match '^\s*(Record Name|记录名称|記錄名稱)\s*\.?\s*:?\s*(.+)$') {
        $names += $Matches[2].Trim()
      }
    }
    foreach ($name in @($names | Where-Object { $_ } | Select-Object -Unique -First $max)) {
      Add-Record '' 'DNS 缓存' '' '' '' '' '' '' $name '' '' 'ipconfig /displaydns'
    }
  } catch {
    Add-Error 'DNS 缓存' $_.Exception.Message
  }
}

try {
  $fw = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
  if (Test-Path $fw) {
    $allLines = Get-Content -Path $fw -ErrorAction Stop
    $fieldLine = @($allLines | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1)
    if ($fieldLine.Count -gt 0) {
      $fields = ($fieldLine[0] -replace '^#Fields:\s*','') -split '\s+'
      $dataLines = @($allLines | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -Last $max)
      foreach ($line in $dataLines) {
        $parts = $line -split '\s+'
        $row = @{}
        for ($i = 0; $i -lt $fields.Length -and $i -lt $parts.Length; $i++) {
          $row[$fields[$i]] = $parts[$i]
        }
        $time = (($row['date'], $row['time']) | Where-Object { $_ }) -join ' '
        if (-not (In-TimeRange $time)) { continue }
        Add-Record $time '防火墙日志' '' $row['path'] '' $row['protocol'] (Join-Endpoint $row['src-ip'] $row['src-port']) (Join-Endpoint $row['dst-ip'] $row['dst-port']) '' $row['action'] '' $row['info']
      }
    }
  } else {
    Add-Error '防火墙日志' ('not found: ' + $fw)
  }
} catch {
  Add-Error '防火墙日志' $_.Exception.Message
}

$ordered = @($records | Sort-Object @{Expression={ if ($_.Time) { $_.Time } else { '0000' } }; Descending=$true} | Select-Object -First $max)
[pscustomobject]@{
  Records=$ordered
  CollectionErrors=@($errors)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`, maxRecords, startRaw, endRaw)

	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Snapshot{}, errors.New(msg)
	}

	data := bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xEF, 0xBB, 0xBF})
	if len(data) == 0 {
		return Snapshot{}, errors.New("empty history collection output")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	snapshot.CollectionErrors = localizeHistoryErrors(snapshot.CollectionErrors)
	return snapshot, nil
}

func psDateLiteral(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

func localizeHistoryErrors(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		lower := strings.ToLower(item)
		switch {
		case strings.HasPrefix(item, "Sysmon:") && (strings.Contains(lower, "there is not an event log") || strings.Contains(item, "没有与")):
			out = append(out, "Sysmon: 未发现 Sysmon 事件日志（Microsoft-Windows-Sysmon/Operational），可能未安装或未启用 Sysmon。")
		case strings.HasPrefix(item, "DNS Client 日志:") && (strings.Contains(lower, "there is not an event log") || strings.Contains(item, "没有与")):
			out = append(out, "DNS Client 日志: 未发现 Microsoft-Windows-DNS-Client/Operational，当前系统可能不支持该日志。")
		case strings.HasPrefix(item, "DNS Client 日志:") && strings.Contains(lower, "disabled"):
			out = append(out, "DNS Client 日志: Microsoft-Windows-DNS-Client/Operational 当前未启用，DNS 缓存无法提供历史时间和发起进程。")
		case strings.HasPrefix(item, "DNS Client 日志:") && (strings.Contains(lower, "no events were found") || strings.Contains(item, "找不到任何与指定的选择条件匹配的事件")):
			out = append(out, "DNS Client 日志: 未找到 DNS Client 事件，可能日志未启用、已轮转或近期没有记录。")
		case strings.HasPrefix(item, "安全日志 WFP:") && (strings.Contains(lower, "no events were found") || strings.Contains(item, "找不到任何与指定的选择条件匹配的事件")):
			out = append(out, "安全日志 WFP: 未找到 5156/5157 网络连接审计事件，可能未启用 Windows Filtering Platform 连接审计。")
		case strings.HasPrefix(item, "防火墙日志:") && strings.Contains(lower, "pfirewall.log"):
			out = append(out, "防火墙日志: 未找到 pfirewall.log，可能未启用 Windows 防火墙日志。")
		case strings.Contains(lower, "access is denied") || strings.Contains(item, "拒绝访问"):
			out = append(out, strings.SplitN(item, ":", 2)[0]+": 当前权限不足，建议用管理员权限运行本工具后重试。")
		default:
			out = append(out, item)
		}
	}
	return out
}
