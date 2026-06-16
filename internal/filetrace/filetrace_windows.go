//go:build windows

package filetrace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$hours = %d
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

function Add-FileList($category, $source, $root, $recursive, $extensionOnly, $limit) {
  if ([string]::IsNullOrWhiteSpace([string]$root) -or -not (Test-Path -LiteralPath $root)) { return }
  try {
    $items = Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if ($recursive) {
      $items = Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue
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

$perRoot = [Math]::Max(30, [int]($max / 8))
foreach ($root in @($tempRoots)) {
  Add-FileList 'Temp 临时文件' 'Temp 目录' $root $true $false $perRoot
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
      foreach ($leaf in @('Downloads','Desktop','AppData\Roaming','AppData\Local')) {
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
  Add-FileList '最近修改文件' $modifiedSource $root $true $true $perRoot
}

try {
  $pfRoot = Join-Path $env:SystemRoot 'Prefetch'
  if (Test-Path -LiteralPath $pfRoot) {
    Get-ChildItem -LiteralPath $pfRoot -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -ieq '.pf' -and $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $max | ForEach-Object {
      $base = [IO.Path]::GetFileNameWithoutExtension($_.Name)
      $exe = ($base -replace '-[A-Fa-f0-9]{8}$','')
      Add-Record '最近运行文件' 'Prefetch' $_ $_.FullName $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('可执行名=' + $exe)
    }
  } else {
    Add-Error '最近运行文件' ('Prefetch 目录不存在或未启用，无法读取最近运行记录，不影响最近修改文件和 Temp 目录扫描: ' + $pfRoot)
  }
} catch {
  Add-Error 'Prefetch' $_.Exception.Message
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
      try {
        $shortcut = $shell.CreateShortcut($_.FullName)
        $target = [string]$shortcut.TargetPath
      } catch {}
      Add-Record '最近运行文件' 'Recent 快捷方式' $_ $target $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('lnk=' + $_.FullName)
    }
  }
} catch {
  Add-Error 'Recent 快捷方式' $_.Exception.Message
}

$ordered = @($records | Sort-Object @{Expression={ if ($_.LastRun) { $_.LastRun } elseif ($_.Modified) { $_.Modified } else { $_.Created } }; Descending=$true} | Select-Object -First $max)
[pscustomobject]@{
  Records=@($ordered)
  CollectionErrors=@($errors | Select-Object -Unique)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`, maxRecords, hours, string(modifiedRootsJSON))

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
		return Snapshot{}, errors.New("empty file trace output")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
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
