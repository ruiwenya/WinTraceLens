//go:build windows

package loghealth

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

func Collect() (Snapshot, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$items = @()

function Clean-Value($value) {
  if ($null -eq $value) { return '' }
  $text = [string]$value
  if ([string]::IsNullOrWhiteSpace($text)) { return '' }
  return $text
}

function Add-Source($category, $name, $logName, $status, $eventIds, $lastEventTime, $recordCount, $details, $recommendation) {
  $script:items += [pscustomobject]@{
    Category=Clean-Value $category
    Name=Clean-Value $name
    LogName=Clean-Value $logName
    Status=Clean-Value $status
    EventIDs=Clean-Value $eventIds
    LastEventTime=Clean-Value $lastEventTime
    RecordCount=[int64]$recordCount
    Details=Clean-Value $details
    Recommendation=Clean-Value $recommendation
  }
}

function Id-Label($ids) {
  if ($null -eq $ids -or @($ids).Count -eq 0) { return '' }
  return (@($ids) | ForEach-Object { [string]$_ }) -join ','
}

function Is-NoEvents($message) {
  $lower = ([string]$message).ToLowerInvariant()
  return $lower.Contains('no events were found') -or ([string]$message).Contains('找不到任何与指定的选择条件匹配的事件')
}

function Is-AccessDenied($message) {
  $lower = ([string]$message).ToLowerInvariant()
  return $lower.Contains('access is denied') -or $lower.Contains('unauthorized') -or $lower.Contains('required privilege') -or ([string]$message).Contains('拒绝访问') -or ([string]$message).Contains('未经授权') -or ([string]$message).Contains('权限')
}

function Is-MissingLog($message) {
  $lower = ([string]$message).ToLowerInvariant()
  return $lower.Contains('there is not an event log') -or $lower.Contains('cannot find') -or ([string]$message).Contains('没有与') -or ([string]$message).Contains('找不到')
}

function Test-EventSource($category, $name, $logName, $ids, $recommendation) {
  $eventIds = Id-Label $ids
  $recordCount = 0
  try {
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    try { $recordCount = [int64]$log.RecordCount } catch { $recordCount = 0 }
    if ($log.IsEnabled -eq $false) {
      Add-Source $category $name $logName '未启用' $eventIds '' $recordCount '事件日志存在，但当前未启用。' $recommendation
      return
    }
  } catch {
    $msg = $_.Exception.Message
    if (Is-AccessDenied $msg) {
      Add-Source $category $name $logName '权限不足' $eventIds '' 0 $msg '请使用管理员权限运行本工具后重试。'
    } elseif (Is-MissingLog $msg) {
      Add-Source $category $name $logName '未安装' $eventIds '' 0 $msg $recommendation
    } else {
      Add-Source $category $name $logName '不可用' $eventIds '' 0 $msg $recommendation
    }
    return
  }

  $filter = @{ LogName = $logName }
  if ($null -ne $ids -and @($ids).Count -gt 0) { $filter.Id = $ids }
  try {
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction Stop)
    if ($events.Count -gt 0) {
      Add-Source $category $name $logName '可用' $eventIds $events[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') $recordCount '可以读取到匹配事件。' ''
    } else {
      Add-Source $category $name $logName '无事件' $eventIds '' $recordCount '日志可读取，但没有匹配事件。' $recommendation
    }
  } catch {
    $msg = $_.Exception.Message
    if (Is-NoEvents $msg) {
      Add-Source $category $name $logName '无事件' $eventIds '' $recordCount '日志可读取，但没有匹配事件。' $recommendation
    } elseif (Is-AccessDenied $msg) {
      Add-Source $category $name $logName '权限不足' $eventIds '' $recordCount $msg '请使用管理员权限运行本工具后重试。'
    } else {
      Add-Source $category $name $logName '不可用' $eventIds '' $recordCount $msg $recommendation
    }
  }
}

Test-EventSource '安全日志' '登录/账户/特权事件' 'Security' @(4624,4625,4634,4647,4672,4720,4722,4725,4726,4778,4779) '如果没有事件，请检查安全审计策略和日志保留时间。'
Test-EventSource '历史通信' 'WFP 网络连接审计' 'Security' @(5156,5157) '需要启用 Windows Filtering Platform 连接审计后才会产生 5156/5157 事件。'
Test-EventSource '历史通信' 'Sysmon 网络与 DNS' 'Microsoft-Windows-Sysmon/Operational' @(3,22) '需要安装并启用 Sysmon，且配置包含 NetworkConnect/DnsQuery 事件。'
Test-EventSource '历史通信' 'DNS Client Operational' 'Microsoft-Windows-DNS-Client/Operational' $null 'DNS Client 日志可补充 DNS 查询时间，但通常不能稳定提供发起进程；如需进程名建议启用 Sysmon DNS 事件 22。'
Test-EventSource 'RDP' 'RDP 认证' 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149) '如果没有事件，可能近期没有 RDP 认证或日志已轮转。'
Test-EventSource 'RDP' 'RDP 会话' 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25,39,40) '如果没有事件，可能近期没有 RDP 会话变化或日志已轮转。'
Test-EventSource 'PowerShell' 'PowerShell Operational' 'Microsoft-Windows-PowerShell/Operational' @(4103,4104,4105,4106) '建议开启 PowerShell 模块日志和脚本块日志。'
Test-EventSource 'PowerShell' 'Windows PowerShell' 'Windows PowerShell' @(400,403,600,800) '传统 Windows PowerShell 日志可用于补充引擎启动和管道执行记录。'
Test-EventSource '服务' '服务创建事件' 'System' @(7045) '如果没有事件，可能近期没有新服务安装或 System 日志已轮转。'

try {
  $cache = @(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 1)
  if ($cache.Count -gt 0) {
    Add-Source '历史通信' 'DNS 客户端缓存' 'Get-DnsClientCache' '可用' '' '' 1 '可以读取当前 DNS 客户端缓存。' ''
  } else {
    Add-Source '历史通信' 'DNS 客户端缓存' 'Get-DnsClientCache' '无事件' '' '' 0 'DNS 客户端缓存当前为空。' 'DNS 缓存不是完整历史日志，重启或刷新缓存后会丢失。'
  }
} catch {
  try {
    $dnsText = ipconfig.exe /displaydns 2>$null | Out-String
    if (-not [string]::IsNullOrWhiteSpace($dnsText)) {
      Add-Source '历史通信' 'DNS 客户端缓存' 'ipconfig /displaydns' '可用' '' '' 1 'Get-DnsClientCache 不可用，已回退到 ipconfig /displaydns。' ''
    } else {
      Add-Source '历史通信' 'DNS 客户端缓存' 'ipconfig /displaydns' '无事件' '' '' 0 'DNS 缓存当前为空。' 'DNS 缓存不是完整历史日志，重启或刷新缓存后会丢失。'
    }
  } catch {
    Add-Source '历史通信' 'DNS 客户端缓存' 'DNS Client Cache' '不可用' '' '' 0 $_.Exception.Message '当前系统可能不支持 Get-DnsClientCache，请尝试管理员权限或使用 ipconfig /displaydns。'
  }
}

try {
  $fw = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
  if (Test-Path $fw) {
    $file = Get-Item -LiteralPath $fw -ErrorAction Stop
    if ($file.Length -gt 0) {
      Add-Source '历史通信' 'Windows 防火墙日志' $fw '可用' '' $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') $file.Length '发现 pfirewall.log，文件中可能包含历史连接记录。' ''
    } else {
      Add-Source '历史通信' 'Windows 防火墙日志' $fw '无事件' '' $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') 0 'pfirewall.log 存在但为空。' '请确认防火墙日志已启用并记录允许/丢弃连接。'
    }
  } else {
    Add-Source '历史通信' 'Windows 防火墙日志' $fw '未启用' '' '' 0 '未找到 pfirewall.log。' '可在 Windows 防火墙高级安全设置中启用日志。'
  }
} catch {
  $msg = $_.Exception.Message
  if (Is-AccessDenied $msg) {
    Add-Source '历史通信' 'Windows 防火墙日志' 'pfirewall.log' '权限不足' '' '' 0 $msg '请使用管理员权限运行本工具后重试。'
  } else {
    Add-Source '历史通信' 'Windows 防火墙日志' 'pfirewall.log' '不可用' '' '' 0 $msg '请检查防火墙日志配置。'
  }
}

$sqlServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(MSSQLSERVER|MSSQL\$|SQLSERVERAGENT|SQLAgent\$)' -or $_.DisplayName -match 'SQL Server' })
if ($sqlServices.Count -eq 0) {
  Add-Source 'SQL Server' 'SQL Server 服务' 'Service Control Manager' '未安装' '' '' 0 '未发现 SQL Server 服务。' '该系统未安装 SQL Server 时不会有 SQL Server 日志。'
} else {
  $serviceNames = (@($sqlServices | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', ')
  Add-Source 'SQL Server' 'SQL Server 服务' 'Service Control Manager' '可用' '' '' $sqlServices.Count ('发现 SQL Server 相关服务: ' + $serviceNames) ''
  try {
    $sqlEvents = @(Get-WinEvent -FilterHashtable @{LogName='Application'} -MaxEvents 300 -ErrorAction Stop | Where-Object { $_.ProviderName -match 'MSSQL|SQLSERVERAGENT|SQLAgent|SQL Server' } | Select-Object -First 1)
    if ($sqlEvents.Count -gt 0) {
      Add-Source 'SQL Server' 'SQL Server 应用日志' 'Application' '可用' '' $sqlEvents[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') 1 'Application 日志中发现 SQL Server 事件。' ''
    } else {
      Add-Source 'SQL Server' 'SQL Server 应用日志' 'Application' '无事件' '' '' 0 '已发现 SQL Server 服务，但 Application 日志中未找到 SQL Server 事件。' '请确认 SQL Server 运行状态和 Application 日志保留时间。'
    }
  } catch {
    $msg = $_.Exception.Message
    if (Is-AccessDenied $msg) {
      Add-Source 'SQL Server' 'SQL Server 应用日志' 'Application' '权限不足' '' '' 0 $msg '请使用管理员权限运行本工具后重试。'
    } else {
      Add-Source 'SQL Server' 'SQL Server 应用日志' 'Application' '不可用' '' '' 0 $msg '请确认 Application 日志可读取。'
    }
  }
}

[pscustomobject]@{
  Sources=@($items)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`
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
		return Snapshot{}, errors.New("empty log health output")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	snapshot.Summary = summarize(snapshot.Sources)
	return snapshot, nil
}

func summarize(items []SourceHealth) Summary {
	summary := Summary{Total: len(items)}
	for _, item := range items {
		switch item.Status {
		case "可用":
			summary.Available++
		case "无事件":
			summary.NoEvents++
		case "权限不足":
			summary.PermissionIssue++
			summary.Unavailable++
		default:
			summary.Unavailable++
		}
	}
	return summary
}
