//go:build windows

package filetrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
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
	hours := opts.Hours
	if hours <= 0 {
		hours = 72
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	modifiedRoots := cleanModifiedRoots(opts.ModifiedRoots)
	modifiedRootsJSON, err := json.Marshal(modifiedRoots)
	if err != nil {
		return Snapshot{}, err
	}

	artifactsOnly := "$false"
	if opts.ArtifactsOnly {
		artifactsOnly = "$true"
	}

	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$hours = %d
$artifactsOnly = %s
$customRootsJson = @'
%s
'@
$since = (Get-Date).AddHours(-1 * $hours)
$records = @()
$errors = @()
$seen = @{}

function Clean-Value($value) {
  if ($null -eq $value) { return '' }
  $text = [string]$value
  if ([string]::IsNullOrWhiteSpace($text)) { return '' }
  return $text
}

function Add-Error($source, $message) {
  $script:errors += ([string]$source + ': ' + [string]$message)
}

function Add-Record($category, $source, $file, $path, $lastRun, $runCount, $suspicion, $reason, $details) {
  $actualPath = Clean-Value $path
  if ($null -ne $file) {
    try {
      if ($actualPath -eq '') { $actualPath = $file.FullName }
      $name = $file.Name
      $dir = $file.DirectoryName
      $ext = $file.Extension
      $size = [int64]$file.Length
      $created = if ($file.CreationTime) { $file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
      $modified = if ($file.LastWriteTime) { $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
      $accessed = if ($file.LastAccessTime) { $file.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    } catch {
      $name = Split-Path -Leaf $actualPath
      $dir = Split-Path -Parent $actualPath
      $ext = [IO.Path]::GetExtension($actualPath)
      $size = 0
      $created = ''
      $modified = ''
      $accessed = ''
    }
  } else {
    $name = Split-Path -Leaf $actualPath
    $dir = Split-Path -Parent $actualPath
    $ext = [IO.Path]::GetExtension($actualPath)
    $size = 0
    $created = ''
    $modified = ''
    $accessed = ''
  }
  $key = ([string]$category + '|' + [string]$source + '|' + [string]$actualPath + '|' + [string]$lastRun)
  if ($script:seen.ContainsKey($key)) { return }
  $script:seen[$key] = $true
  $script:records += [pscustomobject]@{
    Category=Clean-Value $category
    Source=Clean-Value $source
    Name=Clean-Value $name
    Path=Clean-Value $actualPath
    Directory=Clean-Value $dir
    Extension=Clean-Value $ext
    Size=[int64]$size
    Created=Clean-Value $created
    Modified=Clean-Value $modified
    Accessed=Clean-Value $accessed
    LastRun=Clean-Value $lastRun
    RunCount=Clean-Value $runCount
    Suspicion=Clean-Value $suspicion
    Reason=Clean-Value $reason
    Details=Clean-Value $details
  }
}

function Add-ArtifactRecord($category, $source, $name, $path, $created, $modified, $lastRun, $runCount, $details) {
  $actualName = Clean-Value $name
  $actualPath = Clean-Value $path
  $actualLastRun = Clean-Value $lastRun
  if ($actualName -eq '') { $actualName = Split-Path -Leaf $actualPath }
  $key = ([string]$category + '|' + [string]$source + '|' + [string]$actualPath + '|' + [string]$actualName + '|' + [string]$actualLastRun)
  if ($script:seen.ContainsKey($key)) { return }
  $script:seen[$key] = $true
  $dir = ''
  $ext = ''
  try {
    $dir = Split-Path -Parent $actualPath
    $ext = [IO.Path]::GetExtension($actualPath)
  } catch {}
  $script:records += [pscustomobject]@{
    Category=Clean-Value $category
    Source=Clean-Value $source
    Name=$actualName
    Path=$actualPath
    Directory=Clean-Value $dir
    Extension=Clean-Value $ext
    Size=[int64]0
    Created=Clean-Value $created
    Modified=Clean-Value $modified
    Accessed=''
    LastRun=$actualLastRun
    RunCount=Clean-Value $runCount
    Suspicion=''
    Reason=''
    Details=Clean-Value $details
  }
}

function Convert-ROT13($value) {
  $chars = ([string]$value).ToCharArray()
  for ($i = 0; $i -lt $chars.Length; $i++) {
    $code = [int][char]$chars[$i]
    if ($code -ge 65 -and $code -le 90) { $chars[$i] = [char](65 + (($code - 65 + 13) %% 26)) }
    elseif ($code -ge 97 -and $code -le 122) { $chars[$i] = [char](97 + (($code - 97 + 13) %% 26)) }
  }
  return -join $chars
}

function FileTime-FromBytes($bytes, $offset) {
  try {
    if ($null -eq $bytes -or $bytes.Length -lt ($offset + 8)) { return '' }
    $value = [BitConverter]::ToInt64($bytes, $offset)
    if ($value -le 0) { return '' }
    $date = [DateTime]::FromFileTimeUtc($value).ToLocalTime()
    if ($date.Year -lt 2000 -or $date.Year -gt 2100) { return '' }
    return $date.ToString('yyyy-MM-dd HH:mm:ss')
  } catch { return '' }
}

function Suspicion-ForFile($file, $source) {
  $reasons = @()
  $level = ''
  $name = [string]$file.Name
  $base = [IO.Path]::GetFileNameWithoutExtension($name)
  $ext = ([string]$file.Extension).ToLowerInvariant()
  $execExts = @('.exe','.dll','.scr','.com','.bat','.cmd','.ps1','.vbs','.js','.jse','.wsf','.hta','.msi','.jar','.lnk')
  if ($execExts -contains $ext) {
    $reasons += '可执行/脚本扩展'
    if ($source -match 'Temp') { $level = '高' } elseif ($level -eq '') { $level = '中' }
  }
  if ($base -match '^[a-fA-F0-9]{8,}$') {
    $reasons += '疑似随机十六进制文件名'
    if ($level -eq '') { $level = '中' }
  } elseif ($base -match '^[A-Za-z0-9]{12,}$') {
    $reasons += '疑似随机字母数字文件名'
    if ($level -eq '') { $level = '中' }
  }
  if ($name -match '[\x00-\x1f\ufffd]') {
    $reasons += '文件名包含不可见或替换字符'
    $level = '高'
  }
  if ($base.Length -ge 16) {
    $digits = ([regex]::Matches($base, '\d')).Count
    if ($digits -ge [Math]::Ceiling($base.Length * 0.45)) {
      $reasons += '文件名数字占比较高'
      if ($level -eq '') { $level = '中' }
    }
  }
  if ($file.Length -gt 0 -and $file.Length -lt 4096 -and ($execExts -contains $ext)) {
    $reasons += '小体积可执行/脚本文件'
    if ($level -eq '') { $level = '中' }
  }
  if ($reasons.Count -eq 0) { return @('', '') }
  return @($level, ($reasons -join '；'))
}

function Add-FileList($category, $source, $root, $recursive, $extensionOnly, $limit, $maxDepth) {
  if ([string]::IsNullOrWhiteSpace([string]$root) -or -not (Test-Path -LiteralPath $root)) { return }
  try {
    $items = Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if ($recursive) {
      if ($maxDepth -ge 0) {
        $boundedItems = New-Object 'System.Collections.ArrayList'
        $queue = New-Object 'System.Collections.Queue'
        $queue.Enqueue([pscustomobject]@{Path=[string]$root;Depth=0})
        while ($queue.Count -gt 0) {
          $entry = $queue.Dequeue()
          foreach ($child in @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction SilentlyContinue)) {
            if ($child.PSIsContainer) {
              if ($entry.Depth -lt $maxDepth) {
                $queue.Enqueue([pscustomobject]@{Path=$child.FullName;Depth=($entry.Depth + 1)})
              }
            } else {
              [void]$boundedItems.Add($child)
            }
          }
        }
        $items = @($boundedItems)
      } else {
        $items = Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue
      }
    }
    $execExts = @('.exe','.dll','.scr','.com','.bat','.cmd','.ps1','.vbs','.js','.jse','.wsf','.hta','.msi','.jar','.lnk')
    $items = @($items | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $since })
    if ($extensionOnly) {
      $items = @($items | Where-Object { $execExts -contains ([string]$_.Extension).ToLowerInvariant() })
    }
    foreach ($file in @($items | Sort-Object LastWriteTime -Descending | Select-Object -First $limit)) {
      $risk = Suspicion-ForFile $file $source
      Add-Record $category $source $file $file.FullName '' '' $risk[0] $risk[1] ''
    }
  } catch {
    Add-Error $source $_.Exception.Message
  }
}

$customRoots = New-Object 'System.Collections.Generic.List[string]'
try {
  if (-not [string]::IsNullOrWhiteSpace($customRootsJson)) {
    $parsedRoots = ConvertFrom-Json -InputObject $customRootsJson -ErrorAction Stop
    foreach ($root in @($parsedRoots)) {
      $rootText = Clean-Value $root
      if ($rootText -ne '' -and (Test-Path -LiteralPath $rootText) -and -not $customRoots.Contains($rootText)) {
        $customRoots.Add($rootText) | Out-Null
      }
    }
  }
} catch {
  Add-Error '自定义最近修改目录' $_.Exception.Message
}

$perRoot = [Math]::Max(30, [int]($max / 8))
if (-not $artifactsOnly) {
$tempRoots = New-Object 'System.Collections.Generic.List[string]'
foreach ($path in @($env:TEMP, $env:TMP, (Join-Path $env:SystemRoot 'Temp'))) {
  if (-not [string]::IsNullOrWhiteSpace([string]$path) -and -not $tempRoots.Contains([string]$path)) { $tempRoots.Add([string]$path) | Out-Null }
}
try {
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $candidate = Join-Path $_.FullName 'AppData\Local\Temp'
    if (Test-Path -LiteralPath $candidate) {
      if (-not $tempRoots.Contains([string]$candidate)) { $tempRoots.Add([string]$candidate) | Out-Null }
    }
  }
} catch {
  Add-Error 'Temp 目录枚举' $_.Exception.Message
}

foreach ($root in @($tempRoots)) {
  Add-FileList 'Temp 临时文件' 'Temp 目录' $root $true $false $perRoot 4
}

$scanRoots = New-Object 'System.Collections.Generic.List[string]'
$modifiedSource = '常见落地点'
if ($customRoots.Count -gt 0) {
  $modifiedSource = '自定义目录'
  foreach ($root in @($customRoots)) {
    if (-not $scanRoots.Contains([string]$root)) { $scanRoots.Add([string]$root) | Out-Null }
  }
} else {
  foreach ($path in @(
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:ProgramData ''),
    (Join-Path $env:PUBLIC 'Downloads'),
    (Join-Path $env:PUBLIC 'Desktop')
  )) {
    if (-not [string]::IsNullOrWhiteSpace([string]$path) -and (Test-Path -LiteralPath $path) -and -not $scanRoots.Contains([string]$path)) { $scanRoots.Add([string]$path) | Out-Null }
  }
  try {
    Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
      foreach ($leaf in @('Downloads','Desktop','AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) {
        $candidate = Join-Path $_.FullName $leaf
        if (Test-Path -LiteralPath $candidate) {
          if (-not $scanRoots.Contains([string]$candidate)) { $scanRoots.Add([string]$candidate) | Out-Null }
        }
      }
    }
  } catch {
    Add-Error '最近修改目录枚举' $_.Exception.Message
  }
}

if ($scanRoots.Count -gt 0) {
  $perRoot = [Math]::Max(30, [int]($max / [Math]::Max(1, $scanRoots.Count)))
}
foreach ($root in @($scanRoots)) {
  $scanDepth = if ($customRoots.Count -gt 0) { -1 } else { 3 }
  Add-FileList '最近修改文件' $modifiedSource $root $true $true $perRoot $scanDepth
}
}

try {
  $pfRoot = Join-Path $env:SystemRoot 'Prefetch'
  if (Test-Path -LiteralPath $pfRoot) {
    $allPrefetch = @(Get-ChildItem -LiteralPath $pfRoot -Force -ErrorAction Stop | Where-Object { -not $_.PSIsContainer -and $_.Extension -ieq '.pf' })
    $recentPrefetch = @($allPrefetch | Where-Object { $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $max)
    $recentPrefetch | ForEach-Object {
      $base = [IO.Path]::GetFileNameWithoutExtension($_.Name)
      $exe = ($base -replace '-[A-Fa-f0-9]{8}$','')
      Add-Record '最近运行文件' 'Prefetch' $_ $_.FullName $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('可执行名=' + $exe + '；当前显示 Prefetch 文件最后写入时间作为最近活动近似值，不等同于完整运行时间解析')
    }
    $newestPrefetch = ''
    if ($allPrefetch.Count -gt 0) {
      $newestItem = $allPrefetch | Sort-Object LastWriteTime -Descending | Select-Object -First 1
      $newestPrefetch = $newestItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    $prefetchDetails = 'PF 文件总数=' + $allPrefetch.Count + '；所选时间范围内=' + $recentPrefetch.Count
    if ($newestPrefetch) { $prefetchDetails += '；最新写入=' + $newestPrefetch }
    if ($allPrefetch.Count -eq 0) { $prefetchDetails += '；目录为空，可能未启用 Prefetch 或记录已被清理' }
    elseif ($recentPrefetch.Count -eq 0) { $prefetchDetails += '；当前时间范围内没有新记录，可扩大时间范围复核' }
    Add-ArtifactRecord '取证源状态' 'Prefetch 状态' 'Prefetch 采集状态' $pfRoot '' '' '' '' $prefetchDetails
  } else {
    Add-Error '最近运行文件' ('Prefetch 目录不存在或未启用，无法读取最近运行记录，不影响最近修改文件和 Temp 目录扫描: ' + $pfRoot)
    Add-ArtifactRecord '取证源状态' 'Prefetch 状态' 'Prefetch 目录不存在' $pfRoot '' '' '' '' '该系统可能禁用了 Prefetch，或者系统版本未使用此取证源'
  }
} catch {
  Add-Error 'Prefetch' ('读取失败: ' + $_.Exception.Message + '；请确认以管理员身份运行')
  Add-ArtifactRecord '取证源状态' 'Prefetch 状态' 'Prefetch 读取失败' $pfRoot '' '' '' '' ('错误=' + $_.Exception.Message + '；请确认以管理员身份运行')
}

try {
  $shell = New-Object -ComObject WScript.Shell
  $recentRoots = @()
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $candidate = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    if (Test-Path -LiteralPath $candidate) { $recentRoots += $candidate }
  }
  foreach ($root in @($recentRoots | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -ieq '.lnk' -and $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $perRoot | ForEach-Object {
      $target = ''
      $arguments = ''
      $workingDirectory = ''
      $iconLocation = ''
      try {
        $shortcut = $shell.CreateShortcut($_.FullName)
        $target = [string]$shortcut.TargetPath
        $arguments = Clean-Value $shortcut.Arguments
        $workingDirectory = Clean-Value $shortcut.WorkingDirectory
        $iconLocation = Clean-Value $shortcut.IconLocation
      } catch {}
      Add-Record '最近运行文件' 'Recent 快捷方式' $_ $target $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('lnk=' + $_.FullName + '；参数=' + $arguments + '；工作目录=' + $workingDirectory + '；图标=' + $iconLocation)
    }
  }
} catch {
  Add-Error 'Recent 快捷方式' $_.Exception.Message
}

try {
  $jumpRoots = @()
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    foreach ($leaf in @(
      'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations',
      'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'
    )) {
      $candidate = Join-Path $_.FullName $leaf
      if (Test-Path -LiteralPath $candidate) { $jumpRoots += $candidate }
    }
  }
  foreach ($root in @($jumpRoots | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $perRoot | ForEach-Object {
      Add-Record '执行痕迹' 'JumpList' $_ $_.FullName $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' 'JumpList 容器文件；目标明细需专用解析器进一步解析'
    }
  }
} catch {
  Add-Error 'JumpList' $_.Exception.Message
}

try {
  $amcacheRoots = @(
    'Registry::HKEY_LOCAL_MACHINE\Amcache\Root\InventoryApplicationFile',
    'Registry::HKEY_LOCAL_MACHINE\Amcache\Root\File'
  )
  foreach ($root in $amcacheRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue | Select-Object -First ([Math]::Max(100, [int]($max / 2))) | ForEach-Object {
      try {
        $item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
        $candidate = ''
        foreach ($propertyName in @('LowerCaseLongPath','LongPathHash','Name','FileName','FullPath')) {
          $value = Clean-Value $item.$propertyName
          if ($value -ne '') { $candidate = $value; break }
        }
        if ($candidate -ne '') {
          $displayName = Split-Path -Leaf $candidate
          if ($displayName -eq '') { $displayName = $candidate }
          $details = '注册表=' + $_.Name + '；Amcache 条目可证明系统记录过该文件，不单独证明文件已执行'
          foreach ($propertyName in @('ProgramId','FileId','Publisher','LinkDate','ProductName','Version')) {
            $value = Clean-Value $item.$propertyName
            if ($value -ne '') { $details += '；' + $propertyName + '=' + $value }
          }
          Add-ArtifactRecord '执行痕迹' 'Amcache' $displayName $candidate '' '' '' '' $details
        }
      } catch {}
    }
  }
} catch {
  Add-Error 'Amcache' $_.Exception.Message
}

try {
  $shimcachePath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
  if (Test-Path -LiteralPath $shimcachePath) {
    $shimcache = Get-ItemProperty -LiteralPath $shimcachePath -Name AppCompatCache -ErrorAction Stop
    $bytes = $shimcache.AppCompatCache
    $found = 0
    if ($bytes -is [byte[]]) {
      $decoded = [Text.Encoding]::Unicode.GetString($bytes)
      $pathPattern = '(?i)[A-Z]:\\(?:[^<>:"|?*\x00-\x1F\\]+\\)*[^<>:"|?*\x00-\x1F\\]+\.(?:exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|hta)'
      foreach ($match in @([regex]::Matches($decoded, $pathPattern) | Select-Object -First $perRoot)) {
        $candidate = Clean-Value $match.Value
        if ($candidate -eq '') { continue }
        Add-ArtifactRecord '执行痕迹' 'Shimcache 路径提取' (Split-Path -Leaf $candidate) $candidate '' '' '' '' ('注册表=' + $shimcachePath + '；从版本化二进制中启发式提取路径；条目本身不单独证明执行，时间与标志位尚未解析')
        $found++
      }
    }
    if ($found -eq 0) {
      Add-ArtifactRecord '取证源状态' 'Shimcache 证据定位' 'AppCompatCache' $shimcachePath '' '' '' '' ('已定位 Shimcache 二进制数据；字节数=' + @($bytes).Count + '；当前版本未可靠解析此系统版本的条目结构')
    }
  }
} catch {
  Add-Error 'Shimcache' $_.Exception.Message
}

try {
  $srumPath = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
  if (Test-Path -LiteralPath $srumPath) {
    $srumFile = Get-Item -LiteralPath $srumPath -Force -ErrorAction Stop
    Add-Record '网络与应用痕迹' 'SRUM 证据定位' $srumFile $srumPath '' '' '' '' '已定位 SRUM ESE 数据库；在线模式仅展示文件元数据，尚未解析应用流量和资源使用明细，建议取证副本后使用专用 SRUM/ESE 解析器'
  } else {
    Add-Error 'SRUM' ('未找到 SRUM 数据库: ' + $srumPath)
  }
} catch {
  Add-Error 'SRUM' $_.Exception.Message
}

try {
  Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
    $sid = $_.PSChildName
    $storePath = 'Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
    if (Test-Path -LiteralPath $storePath) {
      try {
        $store = Get-ItemProperty -LiteralPath $storePath -ErrorAction Stop
        foreach ($property in @($store.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -First $perRoot)) {
          $path = Clean-Value $property.Name
          if ($path -eq '') { continue }
          $lastRun = ''
          if ($property.Value -is [byte[]]) { $lastRun = FileTime-FromBytes $property.Value 0 }
          Add-ArtifactRecord '执行痕迹' 'PCA 执行记录' (Split-Path -Leaf $path) $path '' '' $lastRun '' ('SID=' + $sid + '；注册表=' + $storePath)
        }
      } catch {}
    }
  }
} catch {
  Add-Error 'PCA 执行记录' $_.Exception.Message
}

try {
  Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
    $sid = $_.PSChildName
    $userAssistRoot = 'Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (Test-Path -LiteralPath $userAssistRoot) {
      Get-ChildItem -LiteralPath $userAssistRoot -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'Count' } | ForEach-Object {
        $keyPath = $_.PSPath
        try {
          $values = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
          foreach ($property in @($values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -First $perRoot)) {
            $decoded = Convert-ROT13 $property.Name
            $runCount = ''
            $lastRun = ''
            if ($property.Value -is [byte[]]) {
              if ($property.Value.Length -ge 8) { $runCount = [BitConverter]::ToInt32($property.Value, 4).ToString() }
              $lastRun = FileTime-FromBytes $property.Value 60
            }
            Add-ArtifactRecord '执行痕迹' 'UserAssist' $decoded $decoded '' '' $lastRun $runCount ('SID=' + $sid + '；注册表=' + $keyPath)
          }
        } catch {}
      }
    }
  }
} catch {
  Add-Error 'UserAssist' $_.Exception.Message
}

try {
  $historyFiles = @()
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    foreach ($historyLeaf in @(
      'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine',
      'AppData\Roaming\Microsoft\PowerShell\PSReadLine'
    )) {
      $historyRoot = Join-Path $_.FullName $historyLeaf
      if (-not (Test-Path -LiteralPath $historyRoot)) { continue }
      try {
        $historyFiles += @(Get-ChildItem -LiteralPath $historyRoot -Force -ErrorAction Stop | Where-Object { -not $_.PSIsContainer -and $_.Name -like '*_history.txt' })
      } catch {
        Add-Error 'PowerShell PSReadLine' ($historyRoot + ': ' + $_.Exception.Message)
      }
    }
  }
  $historyFileCount = 0
  $historyCommandCount = 0
  foreach ($historyFile in @($historyFiles | Sort-Object FullName -Unique)) {
      try {
        $historyPath = $historyFile.FullName
        $commands = @(Get-Content -LiteralPath $historyPath -ErrorAction Stop | Select-Object -Last ([Math]::Min(100, $perRoot)))
        $lineNumber = 0
        foreach ($command in $commands) {
          $lineNumber++
          $commandText = Clean-Value $command
          if ($commandText -eq '') { continue }
          $display = $commandText
          if ($display.Length -gt 180) { $display = $display.Substring(0, 180) + '...' }
          Add-ArtifactRecord '命令历史' 'PowerShell PSReadLine' $display $historyPath '' $historyFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' ('历史文件中的相对行号=' + $lineNumber + '；单条命令没有可靠执行时间')
          $historyCommandCount++
        }
        $historyFileCount++
      } catch {
        Add-Error 'PowerShell PSReadLine' ($historyFile.FullName + ': ' + $_.Exception.Message)
      }
  }
  $historyDetails = '历史文件=' + $historyFileCount + '；读取命令=' + $historyCommandCount + '；同时检查 Windows PowerShell 与 PowerShell 7 的 PSReadLine 目录'
  if ($historyFileCount -eq 0) { $historyDetails += '；未发现历史文件，可能从未使用 PSReadLine、历史保存被禁用或记录已清理' }
  Add-ArtifactRecord '取证源状态' 'PowerShell PSReadLine 状态' 'PowerShell 历史采集状态' (Join-Path $env:SystemDrive 'Users') '' '' '' '' $historyDetails
} catch {
  Add-Error 'PowerShell PSReadLine' $_.Exception.Message
}

$sortedRecords = @($records | Sort-Object @{Expression={ if ($_.LastRun) { $_.LastRun } elseif ($_.Modified) { $_.Modified } else { $_.Created } }; Descending=$true})
$quota = [Math]::Max(20, [int]($max / 5))
$sourceQuota = [Math]::Max(10, [int]($max / 20))
$selected = @()
foreach ($sourceName in @('Prefetch', 'PowerShell PSReadLine')) {
  $sourceItems = @($sortedRecords | Where-Object { $_.Source -eq ($sourceName + ' 状态') }) + @($sortedRecords | Where-Object { $_.Source -eq $sourceName })
  $sourceItems = @($sourceItems | Select-Object -First $sourceQuota)
  foreach ($item in $sourceItems) {
    if ($selected.Count -ge $max) { break }
    if ($selected -notcontains $item) { $selected += $item }
  }
}
foreach ($group in @($sortedRecords | Group-Object Category)) {
  $taken = 0
  foreach ($item in @($group.Group)) {
    if ($selected.Count -ge $max -or $taken -ge $quota) { break }
    if ($selected -notcontains $item) {
      $selected += $item
      $taken++
    }
  }
}
if ($selected.Count -lt $max) {
  foreach ($item in $sortedRecords) {
    if ($selected.Count -ge $max) { break }
    if ($selected -notcontains $item) { $selected += $item }
  }
}
$ordered = @($selected | Sort-Object @{Expression={ if ($_.LastRun) { $_.LastRun } elseif ($_.Modified) { $_.Modified } else { $_.Created } }; Descending=$true})
[pscustomobject]@{
  Records=@($ordered)
  CollectionErrors=@($errors | Select-Object -Unique)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`, maxRecords, hours, artifactsOnly, string(modifiedRootsJSON))

	cmd := winexec.PowerShell(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var snapshot Snapshot
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "PowerShell 文件痕迹采集: "+msg)
		snapshot.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	} else {
		data := bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xEF, 0xBB, 0xBF})
		if len(data) == 0 {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "PowerShell 文件痕迹采集返回空结果")
			snapshot.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
		} else if decodeErr := json.Unmarshal(data, &snapshot); decodeErr != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "PowerShell 文件痕迹解析: "+decodeErr.Error())
			snapshot.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
		}
	}
	amcacheRecords, amcacheWarnings, amcacheNotices, nativeAmcache := collectNativeAmcache(opts, maxRecords)
	if nativeAmcache || strings.TrimSpace(opts.AmcachePath) != "" {
		filtered := snapshot.Records[:0]
		for _, item := range snapshot.Records {
			if !strings.EqualFold(strings.TrimSpace(item.Source), "Amcache") {
				filtered = append(filtered, item)
			}
		}
		snapshot.Records = filtered
	}
	ntfsLimit := maxRecords / 3
	if ntfsLimit < 100 {
		ntfsLimit = 100
	}
	if ntfsLimit > 1000 {
		ntfsLimit = 1000
	}
	ntfsRecords, ntfsWarnings := collectNTFSArtifacts(modifiedRoots, ntfsLimit)
	nativeLimit := maxRecords / 2
	if nativeLimit < 150 {
		nativeLimit = 150
	}
	nativeRecords, nativeWarnings := collectNativeLandingFiles(opts, nativeLimit)
	extraRecords := append(nativeRecords, ntfsRecords...)
	extraRecords = append(extraRecords, amcacheRecords...)
	snapshot.Records = mergeTraceRecords(snapshot.Records, extraRecords, maxRecords)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, nativeWarnings...)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, ntfsWarnings...)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, amcacheWarnings...)
	snapshot.Notices = append(snapshot.Notices, amcacheNotices...)
	return snapshot, nil
}

func mergeTraceRecords(existing, extra []Record, limit int) []Record {
	if limit <= 0 {
		return append(existing, extra...)
	}
	all := append(append([]Record(nil), existing...), extra...)
	sort.SliceStable(all, func(i, j int) bool {
		return recordTimestamp(all[i]).After(recordTimestamp(all[j]))
	})
	selected := make([]Record, 0, minInt(limit, len(all)))
	seen := make(map[string]bool, len(all))
	add := func(item Record) {
		key := item.Category + "|" + item.Source + "|" + item.Path + "|" + item.Name + "|" + item.Modified
		if len(selected) >= limit || seen[key] {
			return
		}
		seen[key] = true
		selected = append(selected, item)
	}
	for _, item := range extra {
		if item.Source == "MFT 证据定位" {
			add(item)
		}
	}
	// Structural anomalies are low-volume, high-signal records and must not be
	// displaced by large Amcache/USN result sets.
	for _, item := range extra {
		if item.Source == "敏感文件结构校验" {
			add(item)
		}
	}
	// Preserve low-volume evidence sources before NTFS and Amcache quotas fill
	// the result set. Their status rows are needed to distinguish "no data"
	// from collection failure.
	sourceQuota := limit / 20
	if sourceQuota < 10 {
		sourceQuota = 10
	}
	for _, source := range []string{"Prefetch", "PowerShell PSReadLine"} {
		remaining := sourceQuota
		for _, item := range existing {
			if remaining <= 0 {
				break
			}
			if item.Source == source+" 状态" {
				add(item)
				remaining--
			}
		}
		for _, item := range existing {
			if remaining <= 0 {
				break
			}
			if item.Source == source {
				add(item)
				remaining--
			}
		}
	}
	usnQuota := limit / 5
	if usnQuota < 20 {
		usnQuota = 20
	}
	for _, item := range extra {
		if item.Source == "USN Journal" && usnQuota > 0 {
			add(item)
			usnQuota--
		}
	}
	amcacheQuota := limit / 3
	if amcacheQuota < 50 {
		amcacheQuota = 50
	}
	for _, item := range extra {
		if item.Source == "Amcache Hive" && amcacheQuota > 0 {
			add(item)
			amcacheQuota--
		}
	}
	for _, item := range all {
		add(item)
	}
	return selected
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func cleanModifiedRoots(values []string) []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, value)
		if len(roots) >= 8 {
			break
		}
	}
	return roots
}
