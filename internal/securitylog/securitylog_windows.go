//go:build windows

package securitylog

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
$psRawMax = $max
$psLaunchMax = [Math]::Min(1000, [Math]::Max(200, ($max * 2)))
$startTimeRaw = %q
$endTimeRaw = %q
$startTime = if ([string]::IsNullOrWhiteSpace($startTimeRaw)) { $null } else { [datetime]::ParseExact($startTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$endTime = if ([string]::IsNullOrWhiteSpace($endTimeRaw)) { $null } else { [datetime]::ParseExact($endTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$events = @()
$errors = @()

function New-EventFilter($logName, $ids) {
  $filter = @{ LogName = $logName }
  if ($null -ne $ids) { $filter.Id = $ids }
  if ($null -ne $startTime) { $filter.StartTime = $startTime }
  if ($null -ne $endTime) { $filter.EndTime = $endTime }
  return $filter
}

function Add-Error($source, $message) {
  $script:errors += ([string]$source + ': ' + [string]$message)
}

function Clean-Value($value) {
  if ($null -eq $value) { return '' }
  $text = [string]$value
  if ([string]::IsNullOrWhiteSpace($text) -or $text -eq '-') { return '' }
  return $text
}

function Get-EventMessage($event) {
  try {
    return (([string]$event.FormatDescription()) -replace '\r?\n', ' ')
  } catch {
    return ''
  }
}

function Get-EventDataMap($event) {
  $map = @{}
  try {
    [xml]$xml = $event.ToXml()
    $idx = 1
    foreach ($item in @($xml.Event.EventData.Data)) {
      $name = Clean-Value $item.Name
      if ($name -eq '') { $name = 'Param' + $idx }
      $map[$name] = Clean-Value $item.'#text'
      $idx++
    }
    foreach ($container in @($xml.Event.UserData.ChildNodes)) {
      foreach ($node in @($container.ChildNodes)) {
        if ($node.NodeType -eq 'Element') {
          $map[$node.Name] = Clean-Value $node.InnerText
        }
      }
    }
  } catch {}
  return $map
}

function First-Value($data, $names) {
  foreach ($name in @($names)) {
    if ($data.ContainsKey($name)) {
      $value = Clean-Value $data[$name]
      if ($value -ne '') { return $value }
    }
  }
  return ''
}

function Test-WinTraceLensCollectorText($value) {
  $text = ([string]$value).ToLowerInvariant()
  if ($text -eq '') { return $false }
  if ($text.Contains('wtl-collector') -or $text.Contains('wtlcollectormarker')) { return $true }

  $legacyPairs = @(
    @('function new-eventfilter', 'convert-securityaction'),
    @('$customrootsjson', 'function add-artifactrecord'),
    @('function suspicion-forfile', 'function add-filelist'),
    @('function data-summary', 'function join-endpoint'),
    @('function get-wmicompat', 'win32_service'),
    @('function walk-folder', 'schedule.service'),
    @('function add-driverevent', 'system/7045'),
    @('function test-eventsource', 'windows filtering platform'),
    @('win32_perfformatteddata_perfproc_process', 'parentprocessid,commandline,workingsetsize'),
    @('get-ciminstance win32_process', 'processid,parentprocessid | convertto-json')
  )
  foreach ($pair in $legacyPairs) {
    if ($text.Contains([string]$pair[0]) -and $text.Contains([string]$pair[1])) { return $true }
  }
  return $false
}

function Convert-LogonTypeName($value) {
  switch ([string]$value) {
    '2' { return '交互式登录' }
    '3' { return '网络登录' }
    '4' { return '批处理登录' }
    '5' { return '服务登录' }
    '7' { return '解锁' }
    '8' { return '网络明文登录' }
    '9' { return '新凭据登录' }
    '10' { return '远程交互式登录/RDP' }
    '11' { return '缓存交互式登录' }
    default { if ([string]::IsNullOrWhiteSpace([string]$value)) { return '' }; return ('LogonType ' + [string]$value) }
  }
}

function Convert-SecurityAction($eventId, $logonType) {
  switch ([int]$eventId) {
    4624 { if ([string]$logonType -eq '10') { return 'RDP 登录成功' }; return '登录成功' }
    4625 { if ([string]$logonType -eq '10') { return 'RDP 登录失败' }; return '登录失败' }
    4634 { return '注销' }
    4647 { return '用户主动注销' }
    4672 { return '特权登录' }
    4720 { return '用户创建' }
    4722 { return '用户启用' }
    4723 { return '尝试修改密码' }
    4724 { return '密码重置' }
    4725 { return '用户禁用' }
    4726 { return '用户删除' }
    4738 { return '用户属性变更' }
    4728 { return '添加到全局组' }
    4729 { return '从全局组移除' }
    4732 { return '添加到本地组' }
    4733 { return '从本地组移除' }
    4756 { return '添加到通用组' }
    4757 { return '从通用组移除' }
    4778 { return 'RDP 会话重新连接' }
    4779 { return 'RDP 会话断开' }
    4800 { return '工作站锁定' }
    4801 { return '工作站解锁' }
    default { return ('安全事件 ' + [string]$eventId) }
  }
}

function Convert-SecurityCategory($eventId, $logonType) {
  switch ([int]$eventId) {
    4624 { if ([string]$logonType -eq '10') { return 'RDP登录' }; return '登录' }
    4625 { if ([string]$logonType -eq '10') { return 'RDP登录' }; return '登录失败' }
    4634 { return '注销' }
    4647 { return '注销' }
    4672 { return '特权登录' }
    4778 { return 'RDP连接' }
    4779 { return 'RDP连接' }
    4800 { return '工作站锁定' }
    4801 { return '工作站解锁' }
    default { return '用户账户' }
  }
}

function Convert-RDPAction($eventId) {
  switch ([int]$eventId) {
    21 { return 'RDP 会话登录' }
    22 { return 'RDP Shell 启动' }
    23 { return 'RDP 会话注销' }
    24 { return 'RDP 会话断开' }
    25 { return 'RDP 会话重新连接' }
    39 { return 'RDP 会话断开' }
    40 { return 'RDP 会话状态变更' }
    1149 { return 'RDP 认证成功' }
    default { return ('RDP 事件 ' + [string]$eventId) }
  }
}

function Convert-PowerShellAction($eventId) {
  switch ([int]$eventId) {
    400 { return 'PowerShell 引擎启动' }
    403 { return 'PowerShell 引擎停止' }
    600 { return 'PowerShell Provider 加载' }
    800 { return 'PowerShell 管道执行' }
    4103 { return 'PowerShell 模块日志' }
    4104 { return 'PowerShell 脚本块日志' }
    4105 { return 'PowerShell 脚本块开始' }
    4106 { return 'PowerShell 脚本块结束' }
    default { return ('PowerShell 事件 ' + [string]$eventId) }
  }
}

function Add-Event($category, $source, $event, $data, $action, $account, $domain, $subject, $logonType, $sourceIp, $sourcePort, $workstation, $process, $serviceName, $command, $authPackage, $status, $failureReason, $targetSid, $details) {
  $message = Get-EventMessage $event
  $script:events += [pscustomobject]@{
    Time=$event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Category=Clean-Value $category
    Source=Clean-Value $source
    EventID=[string]$event.Id
    Action=Clean-Value $action
    Account=Clean-Value $account
    Domain=Clean-Value $domain
    Subject=Clean-Value $subject
    LogonType=Clean-Value $logonType
    LogonTypeName=(Convert-LogonTypeName $logonType)
    SourceIP=Clean-Value $sourceIp
    SourcePort=Clean-Value $sourcePort
    Workstation=Clean-Value $workstation
    Process=Clean-Value $process
    ServiceName=Clean-Value $serviceName
    Command=Clean-Value $command
    AuthPackage=Clean-Value $authPackage
    Status=Clean-Value $status
    FailureReason=Clean-Value $failureReason
    TargetSID=Clean-Value $targetSid
    Provider=Clean-Value $event.ProviderName
    Level=Clean-Value $event.LevelDisplayName
    Message=Clean-Value $message
    Details=Clean-Value $details
  }
}

$canReadSecurity = $true
try {
  $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
} catch {
  Add-Error '安全日志' ('无法读取 Security 日志: ' + $_.Exception.Message)
  $canReadSecurity = $false
}

if ($canReadSecurity) {
  try {
    Get-WinEvent -FilterHashtable (New-EventFilter 'Security' @(4624,4625,4634,4647,4672,4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4756,4757,4778,4779,4800,4801)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
      $data = Get-EventDataMap $_
      $logonType = First-Value $data @('LogonType')
      $account = First-Value $data @('TargetUserName','AccountName')
      $domain = First-Value $data @('TargetDomainName','AccountDomain')
      $subject = (First-Value $data @('SubjectDomainName')) + '\' + (First-Value $data @('SubjectUserName'))
      if ($subject -eq '\') { $subject = '' }
      $sourceIp = First-Value $data @('IpAddress','ClientAddress','SourceNetworkAddress')
      $sourcePort = First-Value $data @('IpPort','ClientPort','SourcePort')
      $workstation = First-Value $data @('WorkstationName','ClientName','Workstation')
      $process = First-Value $data @('ProcessName','ProcessId')
      $authPackage = First-Value $data @('AuthenticationPackageName','PackageName')
      $status = First-Value $data @('Status','SubStatus')
      $failureReason = First-Value $data @('FailureReason')
      $sid = First-Value $data @('TargetUserSid','SubjectUserSid')
      $details = @()
      $memberName = First-Value $data @('MemberName')
      $groupName = First-Value $data @('TargetSid','GroupName')
      if ($memberName -ne '') { $details += ('成员=' + $memberName) }
      if ($groupName -ne '') { $details += ('组/SID=' + $groupName) }
      if ($data.ContainsKey('ElevatedToken')) { $details += ('ElevatedToken=' + $data['ElevatedToken']) }
      Add-Event (Convert-SecurityCategory $_.Id $logonType) 'Security' $_ $data (Convert-SecurityAction $_.Id $logonType) $account $domain $subject $logonType $sourceIp $sourcePort $workstation $process '' '' $authPackage $status $failureReason $sid ($details -join '; ')
    }
  } catch {
    Add-Error '安全日志' $_.Exception.Message
  }
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $account = First-Value $data @('Param1','User','UserName')
    $domain = First-Value $data @('Param2','Domain')
    $sourceIp = First-Value $data @('Param3','Address','SourceNetworkAddress')
    Add-Event 'RDP连接' 'TerminalServices RemoteConnectionManager' $_ $data (Convert-RDPAction $_.Id) $account $domain '' '10' $sourceIp '' '' '' '' '' '' '' '' '' ''
  }
} catch {
  Add-Error 'RDP连接' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25,39,40)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $account = First-Value $data @('User','Param1','TargetUser')
    $sourceIp = First-Value $data @('Address','Param3','SourceNetworkAddress')
    $details = @()
    $sessionId = First-Value $data @('SessionID','SessionId','Param2')
    if ($sessionId -ne '') { $details += ('SessionID=' + $sessionId) }
    Add-Event 'RDP连接' 'TerminalServices LocalSessionManager' $_ $data (Convert-RDPAction $_.Id) $account '' '' '10' $sourceIp '' '' '' '' '' '' '' '' '' ($details -join '; ')
  }
} catch {
  Add-Error 'RDP会话' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'System' @(7045)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $serviceName = First-Value $data @('ServiceName','param1','Param1')
    $imagePath = First-Value $data @('ImagePath','ServiceFileName','param2','Param2')
    $account = First-Value $data @('AccountName','ServiceAccount','param5','Param5')
    $details = @()
    $serviceType = First-Value $data @('ServiceType','param3','Param3')
    $startType = First-Value $data @('StartType','ServiceStartType','param4','Param4')
    if ($serviceType -ne '') { $details += ('服务类型=' + $serviceType) }
    if ($startType -ne '') { $details += ('启动类型=' + $startType) }
    Add-Event '服务创建' 'System/Service Control Manager' $_ $data '服务创建' $account '' '' '' '' '' '' '' $serviceName $imagePath '' '' '' '' ($details -join '; ')
  }
} catch {
  Add-Error '服务创建' $_.Exception.Message
}

$collectorProcessWindows = @()
try {
  $launchEvents = @(Get-WinEvent -FilterHashtable (New-EventFilter 'Windows PowerShell' @(400)) -MaxEvents $psLaunchMax -ErrorAction Stop)
  foreach ($launchEvent in $launchEvents) {
    $launchData = Get-EventDataMap $launchEvent
    $launchCommand = First-Value $launchData @('HostApplication','CommandLine','Payload','ContextInfo','Param1')
    $launchContent = (Get-EventMessage $launchEvent) + ' ' + $launchCommand
    if (Test-WinTraceLensCollectorText $launchContent) {
      $launchProcessId = Clean-Value $launchEvent.ProcessId
      if ($launchProcessId -ne '' -and $launchProcessId -ne '0' -and $null -ne $launchEvent.TimeCreated) {
        $collectorProcessWindows += [pscustomobject]@{ ProcessId=$launchProcessId; Start=$launchEvent.TimeCreated.AddMinutes(-2); End=$launchEvent.TimeCreated.AddMinutes(30) }
      }
    }
  }
} catch {}

foreach ($psLog in @('Microsoft-Windows-PowerShell/Operational','Windows PowerShell')) {
  try {
    $psEvents = @(Get-WinEvent -FilterHashtable (New-EventFilter $psLog @(400,403,600,800,4103,4104,4105,4106)) -MaxEvents $psRawMax -ErrorAction Stop)
    $collectorScriptBlocks = @{}
    $collectorRunspaces = @{}
    $collectorActivities = @{}

    foreach ($psEvent in $psEvents) {
      $data = Get-EventDataMap $psEvent
      $command = First-Value $data @('ScriptBlockText','CommandLine','Payload','ContextInfo','HostApplication','Path','Param1')
      $content = (Get-EventMessage $psEvent) + ' ' + $command
      if (Test-WinTraceLensCollectorText $content) {
        $scriptBlockId = First-Value $data @('ScriptBlockId','ScriptBlockID')
        $runspaceId = First-Value $data @('RunspaceId','RunspaceID')
        $activityId = Clean-Value $psEvent.ActivityId
        $processId = Clean-Value $psEvent.ProcessId
        if ($scriptBlockId -ne '') { $collectorScriptBlocks[$scriptBlockId] = $true }
        if ($runspaceId -ne '') { $collectorRunspaces[$runspaceId] = $true }
        if ($activityId -ne '' -and $activityId -ne '00000000-0000-0000-0000-000000000000') { $collectorActivities[$activityId] = $true }
        if ($processId -ne '' -and $processId -ne '0' -and $null -ne $psEvent.TimeCreated) {
          $collectorProcessWindows += [pscustomobject]@{ ProcessId=$processId; Start=$psEvent.TimeCreated.AddMinutes(-2); End=$psEvent.TimeCreated.AddMinutes(30) }
        }
      }
    }

    $kept = 0
    foreach ($psEvent in $psEvents) {
      if ($kept -ge $max) { break }
      $data = Get-EventDataMap $psEvent
      $command = First-Value $data @('ScriptBlockText','CommandLine','Payload','ContextInfo','HostApplication','Path','Param1')
      $content = (Get-EventMessage $psEvent) + ' ' + $command
      $scriptBlockId = First-Value $data @('ScriptBlockId','ScriptBlockID')
      $runspaceId = First-Value $data @('RunspaceId','RunspaceID')
      $activityId = Clean-Value $psEvent.ActivityId
      $processId = Clean-Value $psEvent.ProcessId
      $isCollector = Test-WinTraceLensCollectorText $content
      if (-not $isCollector -and $scriptBlockId -ne '' -and $collectorScriptBlocks.ContainsKey($scriptBlockId)) { $isCollector = $true }
      if (-not $isCollector -and $runspaceId -ne '' -and $collectorRunspaces.ContainsKey($runspaceId)) { $isCollector = $true }
      if (-not $isCollector -and $activityId -ne '' -and $activityId -ne '00000000-0000-0000-0000-000000000000' -and $collectorActivities.ContainsKey($activityId)) { $isCollector = $true }
      if (-not $isCollector -and $processId -ne '' -and $processId -ne '0' -and $null -ne $psEvent.TimeCreated) {
        foreach ($window in $collectorProcessWindows) {
          if ($window.ProcessId -eq $processId -and $psEvent.TimeCreated -ge $window.Start -and $psEvent.TimeCreated -le $window.End) {
            $isCollector = $true
            break
          }
        }
      }
      if (-not $isCollector) {
        $account = First-Value $data @('UserId','User')
        Add-Event 'PowerShell日志' $psLog $psEvent $data (Convert-PowerShellAction $psEvent.Id) $account '' '' '' '' '' '' 'powershell.exe' '' $command '' '' '' '' ''
        $kept++
      }
    }
  } catch {
    Add-Error 'PowerShell日志' ($psLog + ': ' + $_.Exception.Message)
  }
}

$sqlServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(MSSQLSERVER|MSSQL\$|SQLSERVERAGENT|SQLAgent\$)' -or $_.DisplayName -match 'SQL Server' })
if ($sqlServices.Count -eq 0) {
  Add-Error 'SQL Server' '该系统未安装 SQL Server 或未发现 SQL Server 服务，因此没有 SQL Server 日志可分析。'
} else {
  try {
    $sqlEvents = @(Get-WinEvent -FilterHashtable (New-EventFilter 'Application' $null) -MaxEvents ($max * 5) -ErrorAction Stop | Where-Object { $_.ProviderName -match 'MSSQL|SQLSERVERAGENT|SQLAgent|SQL Server' } | Select-Object -First $max)
    if ($sqlEvents.Count -eq 0) {
      Add-Error 'SQL Server' '已发现 SQL Server 服务，但 Application 日志中未找到 SQL Server 事件。'
    }
    foreach ($event in $sqlEvents) {
      $data = Get-EventDataMap $event
      $instance = First-Value $data @('InstanceName','ServerName','Param1')
      Add-Event 'SQL Server日志' 'Application/SQL Server' $event $data 'SQL Server 事件' $instance '' '' '' '' '' '' '' '' '' '' '' '' '' ''
    }
  } catch {
    Add-Error 'SQL Server' $_.Exception.Message
  }
}

$ordered = @($events | Sort-Object @{Expression={ if ($_.Time) { $_.Time } else { '0000' } }; Descending=$true})
[pscustomobject]@{
  Events=@($ordered)
  CollectionErrors=@($errors)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`, maxRecords, startRaw, endRaw)

	cmd := winexec.PowerShell(script)
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
		return Snapshot{}, errors.New("empty event log collection output")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	snapshot.Events = FilterCollectorEvents(snapshot.Events)
	snapshot.CollectionErrors = localizeErrors(snapshot.CollectionErrors)
	return snapshot, nil
}

func psDateLiteral(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

func localizeErrors(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		lower := strings.ToLower(item)
		msg := item
		switch {
		case strings.Contains(lower, "requested registry access is not allowed") || strings.Contains(lower, "unauthorized operation") || strings.Contains(lower, "access is denied") || strings.Contains(lower, "required privilege") || strings.Contains(item, "未经授权") || strings.Contains(item, "拒绝访问") || strings.Contains(item, "权限"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 当前权限不足，无法读取对应事件日志。请用管理员权限运行本工具。"
		case strings.Contains(lower, "no events were found") || strings.Contains(item, "找不到任何与指定的选择条件匹配的事件"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 未找到匹配事件，可能日志已轮转、审计策略未启用，或该功能近期没有产生日志。"
		case strings.Contains(lower, "there is not an event log") || strings.Contains(item, "没有与"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 未发现对应事件日志，可能系统组件未安装或该日志未启用。"
		}
		if !seen[msg] {
			out = append(out, msg)
			seen[msg] = true
		}
	}
	return out
}
