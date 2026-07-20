//go:build windows

package amcache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	regProcessAppKey = 1
	regLatestFormat  = 2
)

var (
	advapi32              = windows.NewLazySystemDLL("advapi32.dll")
	adjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	regLoadAppKeyW        = advapi32.NewProc("RegLoadAppKeyW")
	regSaveKeyExW         = advapi32.NewProc("RegSaveKeyExW")
)

// openHiveSource first retries with FILE_SHARE_DELETE, which os.Open does not
// request on Windows. A mounted live Amcache hive may still reject file reads;
// in that case only the default local hive is replaced with a RegSaveKeyEx
// snapshot of HKLM\Amcache. Offline files never fall back to local evidence.
func openHiveSource(path string) (*os.File, string, string, func(), error) {
	if sameHivePath(path, DefaultPath()) {
		cleanupPendingVSSSnapshots()
	}
	hive, directErr := openHiveShared(path)
	if directErr == nil {
		return hive, path, "direct", func() {}, nil
	}
	if !sameHivePath(path, DefaultPath()) {
		return nil, "", "", nil, directErr
	}
	if !errors.Is(directErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(directErr, windows.ERROR_LOCK_VIOLATION) {
		return nil, "", "", nil, directErr
	}

	snapshotPath, readMode, cleanup, snapshotErr := saveLiveAmcache(path)
	if snapshotErr != nil {
		return nil, "", "", nil, fmt.Errorf("实时文件直接读取失败: %v；自动创建 Amcache 快照失败: %w", directErr, snapshotErr)
	}
	hive, err := os.Open(snapshotPath)
	if err != nil {
		cleanup()
		return nil, "", "", nil, fmt.Errorf("打开临时 Amcache 快照失败: %w", err)
	}
	return hive, snapshotPath, readMode, cleanup, nil
}

func openHiveShared(path string) (*os.File, error) {
	hive, directErr := os.Open(path)
	if directErr == nil {
		return hive, nil
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, sharedErr := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if sharedErr != nil {
		return nil, fmt.Errorf("%v；使用完整共享标志重试仍失败: %w", directErr, sharedErr)
	}
	return os.NewFile(uintptr(handle), path), nil
}

func saveLiveAmcache(sourcePath string) (string, string, func(), error) {
	tempDir, err := os.MkdirTemp("", "WinTraceLens-amcache-")
	if err != nil {
		return "", "", nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}
	destination := filepath.Join(tempDir, "Amcache-snapshot.hve")

	registryErr := withBackupPrivilege(func() error {
		appHiveErr := saveApplicationHive(sourcePath, destination)
		if appHiveErr == nil {
			return nil
		}
		_ = os.Remove(destination)
		mountedErr := saveMountedHive(destination)
		if mountedErr == nil {
			return nil
		}
		return fmt.Errorf("RegLoadAppKey 路径失败: %v；HKLM\\Amcache 路径失败: %w", appHiveErr, mountedErr)
	})
	if registryErr != nil {
		_ = os.Remove(destination)
		if !windows.GetCurrentProcessToken().IsElevated() {
			cleanup()
			return "", "", nil, fmt.Errorf("注册表快照失败: %v；VSS 读取被占用文件需要以管理员身份运行 WinTraceLens", registryErr)
		}
		vssErr := saveViaVSS(sourcePath, destination)
		if vssErr == nil {
			return destination, "vss", cleanup, nil
		}
		cleanup()
		return "", "", nil, fmt.Errorf("注册表快照失败: %v；VSS 快照失败: %w", registryErr, vssErr)
	}
	return destination, "registry-snapshot", cleanup, nil
}

func saveViaVSS(sourcePath, destination string) error {
	volume := filepath.VolumeName(sourcePath)
	if volume == "" {
		return fmt.Errorf("无法确定 Amcache 所在卷: %s", sourcePath)
	}
	volumeRoot := volume + `\`
	relative, err := filepath.Rel(volumeRoot, sourcePath)
	if err != nil || relative == "." || strings.HasPrefix(relative, `..\`) || relative == ".." {
		return fmt.Errorf("无法计算 Amcache 卷内路径: %s", sourcePath)
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$shadowId = ''
$shadow = $null
$stateRegistryPath = ''
$cleanupSucceeded = $false
try {
  $class = [WMIClass]'root\cimv2:Win32_ShadowCopy'
  $result = $class.Create('%s', 'ClientAccessible')
  if ([int]$result.ReturnValue -ne 0) { throw ('VSS_CREATE_FAILED:' + [string]$result.ReturnValue) }
  $shadowId = [string]$result.ShadowID
  $stateName = $shadowId.Trim('{}')
  $stateRegistryPath = 'SOFTWARE\WinTraceLens\VSSPending\' + $stateName
  $stateKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($stateRegistryPath)
  $ownerStart = [string](Get-Process -Id $PID).StartTime.ToFileTimeUtc()
  $stateKey.SetValue('ShadowID', $shadowId, [Microsoft.Win32.RegistryValueKind]::String)
  $stateKey.SetValue('OwnerPID', [int]$PID, [Microsoft.Win32.RegistryValueKind]::DWord)
  $stateKey.SetValue('OwnerStart', $ownerStart, [Microsoft.Win32.RegistryValueKind]::String)
  $stateKey.Close()
  $filter = "ID='" + $shadowId.Replace("'", "''") + "'"
  $shadow = Get-WmiObject -Class Win32_ShadowCopy -Filter $filter -ErrorAction Stop
  if ($null -eq $shadow) { throw 'VSS_SHADOW_NOT_FOUND' }
  $source = ([string]$shadow.DeviceObject).TrimEnd('\') + '\%s'
  $destination = '%s'
  [System.IO.File]::Copy($source, $destination, $true)
  foreach ($suffix in @('.LOG1', '.LOG2')) {
    $logSource = $source + $suffix
    if ([System.IO.File]::Exists($logSource)) {
      [System.IO.File]::Copy($logSource, ($destination + $suffix), $true)
    }
  }
} finally {
  try {
    if ($null -ne $shadow) {
      $shadow | Remove-WmiObject -ErrorAction Stop
    } elseif ($shadowId) {
      $filter = "ID='" + $shadowId.Replace("'", "''") + "'"
      $pendingShadow = Get-WmiObject -Class Win32_ShadowCopy -Filter $filter -ErrorAction SilentlyContinue
      if ($null -ne $pendingShadow) { $pendingShadow | Remove-WmiObject -ErrorAction Stop }
    }
    $cleanupSucceeded = $true
  } catch {
    Write-Error ('VSS_CLEANUP_FAILED:' + $_.Exception.Message)
  }
  if ($cleanupSucceeded -and $stateRegistryPath) {
    try {
      [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($stateRegistryPath)
      $pendingKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\WinTraceLens\VSSPending')
      $pendingEmpty = ($null -ne $pendingKey -and $pendingKey.SubKeyCount -eq 0)
      if ($null -ne $pendingKey) { $pendingKey.Close() }
      if ($pendingEmpty) { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey('SOFTWARE\WinTraceLens\VSSPending') }
    } catch {}
  }
}
`, quotePowerShell(volumeRoot), quotePowerShell(relative), quotePowerShell(destination))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, commandErr := winexec.PowerShellContext(ctx, script).CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("创建 VSS 快照超时: %w", ctx.Err())
	}
	if commandErr != nil {
		message := strings.TrimSpace(strings.ReplaceAll(string(output), "\x00", ""))
		if len(message) > 2000 {
			message = message[len(message)-2000:]
		}
		if message != "" {
			return fmt.Errorf("%w: %s", commandErr, message)
		}
		return commandErr
	}
	info, err := os.Stat(destination)
	if err != nil {
		return fmt.Errorf("VSS 快照未生成 Amcache 副本: %w", err)
	}
	if info.Size() <= 0 {
		return fmt.Errorf("VSS 生成的 Amcache 副本为空")
	}
	return nil
}

func cleanupPendingVSSSnapshots() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\WinTraceLens\VSSPending`, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	names, err := key.ReadSubKeyNames(1)
	_ = key.Close()
	if err != nil || len(names) == 0 {
		return
	}

	const script = `
$ErrorActionPreference = 'Stop'
$stateRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinTraceLens\VSSPending'
if (Test-Path -LiteralPath $stateRoot) {
  Get-ChildItem -LiteralPath $stateRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $state = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    $ownerAlive = $false
    if ($null -ne $state -and [int]$state.OwnerPID -gt 0) {
      $owner = Get-Process -Id ([int]$state.OwnerPID) -ErrorAction SilentlyContinue
      if ($null -ne $owner) {
        try { $ownerAlive = ([string]$owner.StartTime.ToFileTimeUtc() -eq [string]$state.OwnerStart) } catch { $ownerAlive = $true }
      }
    }
    if (-not $ownerAlive) {
      $removed = $true
      $shadowId = [string]$state.ShadowID
      if ($shadowId) {
        try {
          $filter = "ID='" + $shadowId.Replace("'", "''") + "'"
          $shadow = Get-WmiObject -Class Win32_ShadowCopy -Filter $filter -ErrorAction SilentlyContinue
          if ($null -ne $shadow) { $shadow | Remove-WmiObject -ErrorAction Stop }
        } catch { $removed = $false }
      }
      if ($removed) { Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
  if (@(Get-ChildItem -LiteralPath $stateRoot -ErrorAction SilentlyContinue).Count -eq 0) {
    Remove-Item -LiteralPath $stateRoot -Force -ErrorAction SilentlyContinue
  }
}
`
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_ = winexec.PowerShellContext(ctx, script).Run()
}

func saveApplicationHive(sourcePath, destination string) error {
	sourcePtr, err := windows.UTF16PtrFromString(sourcePath)
	if err != nil {
		return err
	}
	var key registry.Key
	status, _, _ := regLoadAppKeyW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(&key)),
		uintptr(registry.READ),
		regProcessAppKey,
		0,
	)
	if status != 0 {
		return fmt.Errorf("RegLoadAppKeyW: %w", syscall.Errno(status))
	}
	defer key.Close()
	return saveRegistryKey(key, destination)
}

func saveMountedHive(destination string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `Amcache`, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("打开 HKLM\\Amcache 失败: %w", err)
	}
	defer key.Close()
	return saveRegistryKey(key, destination)
}

func saveRegistryKey(key registry.Key, destination string) error {
	destinationPtr, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	status, _, _ := regSaveKeyExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(destinationPtr)),
		0,
		regLatestFormat,
	)
	if status != 0 {
		return fmt.Errorf("RegSaveKeyExW: %w", syscall.Errno(status))
	}
	return nil
}

func withBackupPrivilege(action func() error) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("打开当前进程令牌失败: %w", err)
	}
	defer token.Close()

	name, err := windows.UTF16PtrFromString("SeBackupPrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return fmt.Errorf("查询 SeBackupPrivilege 失败: %w", err)
	}
	state := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	var previous windows.Tokenprivileges
	var returned uint32
	bufferSize := uint32(unsafe.Sizeof(previous))
	success, _, privilegeErr := adjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&state)),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if success == 0 {
		return fmt.Errorf("启用 SeBackupPrivilege 失败: %w", privilegeErr)
	}
	if privilegeErr == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("当前进程令牌没有 SeBackupPrivilege")
	}
	defer func() {
		_, _, _ = adjustTokenPrivileges.Call(
			uintptr(token),
			0,
			uintptr(unsafe.Pointer(&previous)),
			0,
			0,
			0,
		)
	}()
	return action()
}

func quotePowerShell(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func sameHivePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(strings.Trim(left, `"`)))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(strings.Trim(right, `"`)))
	if leftErr != nil || rightErr != nil {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return strings.EqualFold(leftAbs, rightAbs)
}
