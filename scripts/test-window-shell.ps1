param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$exePath = (Resolve-Path -LiteralPath $Executable).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path -Parent $exePath) "window-shell-validation.json"
}

if (-not ("WtlWindowProbe" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WtlWindowProbe {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")] public static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int index);
  [DllImport("user32.dll", EntryPoint="GetWindowLongW")] public static extern IntPtr GetWindowLong32(IntPtr hWnd, int index);
  public static IntPtr GetWindowLongPtr(IntPtr hWnd, int index) { return IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, index) : GetWindowLong32(hWnd, index); }
}
'@
}

function Start-WtlProbeProcess {
    param(
        [string]$Arguments = "",
        [string]$AppData = ""
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $exePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($AppData) {
        $startInfo.EnvironmentVariables["APPDATA"] = $AppData
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process | Add-Member -NotePropertyName WtlStdOutTask -NotePropertyValue $process.StandardOutput.ReadToEndAsync()
    $process | Add-Member -NotePropertyName WtlStdErrTask -NotePropertyValue $process.StandardError.ReadToEndAsync()
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
        $process.Refresh()
        if ($process.HasExited) { throw "WinTraceLens exited during window-shell validation" }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) { return $process }
    }
    if (-not $process.HasExited) { $process.Kill() }
    throw "Timed out waiting for the WinTraceLens window"
}

function Stop-WtlProbeProcess([System.Diagnostics.Process]$Process) {
    if ($Process -and -not $Process.HasExited) {
        [void]$Process.CloseMainWindow()
        if (-not $Process.WaitForExit(10000)) {
            $Process.Kill()
            $Process.WaitForExit(5000) | Out-Null
        }
    }
    if ($Process) {
        [void]$Process.WtlStdOutTask.GetAwaiter().GetResult()
        [void]$Process.WtlStdErrTask.GetAwaiter().GetResult()
    }
    Start-Sleep -Milliseconds 750
}

function Get-WtlStyle([IntPtr]$Hwnd) {
    return [WtlWindowProbe]::GetWindowLongPtr($Hwnd, -16).ToInt64()
}

function Find-MaxButtonHits([IntPtr]$Hwnd) {
    $rect = New-Object WtlWindowProbe+RECT
    if (-not [WtlWindowProbe]::GetClientRect($Hwnd, [ref]$rect)) { throw "GetClientRect failed" }
    $origin = New-Object WtlWindowProbe+POINT
    if (-not [WtlWindowProbe]::ClientToScreen($Hwnd, [ref]$origin)) { throw "ClientToScreen failed" }
    $count = 0
    for ($clientY = 5; $clientY -le 70; $clientY += 5) {
        $startX = [Math]::Max(0, ($rect.Right - $rect.Left) - 420)
        for ($clientX = $startX; $clientX -lt ($rect.Right - $rect.Left); $clientX += 5) {
            $screenX = $origin.X + $clientX
            $screenY = $origin.Y + $clientY
            $packed = (($screenY -band 0xffff) -shl 16) -bor ($screenX -band 0xffff)
            $hit = [WtlWindowProbe]::SendMessage($Hwnd, 0x0084, [IntPtr]::Zero, [IntPtr]::new([int64]$packed)).ToInt64()
            if ($hit -eq 9) { $count++ }
        }
    }
    return $count
}

function Get-WtlFrameResult {
    param(
        [string]$Name,
        [string]$Arguments = "",
        [string]$AppData = "",
        [bool]$ExpectedCaption = $true,
        [bool]$ProbeMaxButton = $false
    )
    $process = Start-WtlProbeProcess -Arguments $Arguments -AppData $AppData
    try {
        $process.Refresh()
        $style = Get-WtlStyle $process.MainWindowHandle
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (((($style -band 0x00c00000) -ne 0) -ne $ExpectedCaption) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
            $process.Refresh()
            if ($process.HasExited) { throw "WinTraceLens exited before applying its window frame" }
            $style = Get-WtlStyle $process.MainWindowHandle
        }
        $hitCount = 0
        if ($ProbeMaxButton) { $hitCount = Find-MaxButtonHits $process.MainWindowHandle }
        return [PSCustomObject]@{
            name = $Name
            responding = $process.Responding
            hasCaption = (($style -band 0x00c00000) -ne 0)
            hasThickFrame = (($style -band 0x00040000) -ne 0)
            maxButtonHitSamples = $hitCount
            title = $process.MainWindowTitle
        }
    } finally {
        Stop-WtlProbeProcess $process
    }
}

$profileRoot = Join-Path (Split-Path -Parent $OutputPath) ("window-shell-profile-{0}" -f $PID)
$defaultProfileRoot = Join-Path $profileRoot "default"
$configDirectory = Join-Path $profileRoot "WinTraceLens"
New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $defaultProfileRoot -Force | Out-Null
$configPath = Join-Path $configDirectory "ui-preferences.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

try {
    $results = @()
    $results += Get-WtlFrameResult -Name "integrated-default" -AppData $defaultProfileRoot -ExpectedCaption $false -ProbeMaxButton $true
    $results += Get-WtlFrameResult -Name "system-argument" -Arguments "-system-frame" -ExpectedCaption $true

    [IO.File]::WriteAllText($configPath, '{"windowFrame":"system"}', $utf8NoBom)
    $results += Get-WtlFrameResult -Name "system-saved" -AppData $profileRoot -ExpectedCaption $true

    $integrated = @($results | Where-Object { $_.name -like "integrated-*" })
    $system = @($results | Where-Object { $_.name -like "system-*" })
    $report = [PSCustomObject]@{
        generatedAt = [DateTime]::UtcNow.ToString("o")
        executable = $exePath
        results = $results
    }
    $reportJson = $report | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($OutputPath, $reportJson, $utf8NoBom)
    $reportJson
    if ($integrated | Where-Object { -not $_.responding -or $_.hasCaption -or -not $_.hasThickFrame -or $_.maxButtonHitSamples -le 0 }) {
        throw "Integrated window-shell validation failed"
    }
    if ($system | Where-Object { -not $_.responding -or -not $_.hasCaption -or -not $_.hasThickFrame }) {
        throw "System window-shell validation failed"
    }
} finally {
    if ([IO.Directory]::Exists($profileRoot)) {
        [IO.Directory]::Delete($profileRoot, $true)
    }
}
