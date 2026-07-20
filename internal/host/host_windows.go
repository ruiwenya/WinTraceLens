//go:build windows

package host

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

type psSnapshot struct {
	Services        []psService     `json:"Services"`
	ScheduledTasks  []psTask        `json:"ScheduledTasks"`
	Users           []UserInfo      `json:"Users"`
	StartupRegistry []psStartupItem `json:"StartupRegistry"`
	StartupFolders  []psStartupItem `json:"StartupFolders"`
	ImageHijacks    []psImageHijack `json:"ImageHijacks"`
}

type psService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	State       string `json:"State"`
	StartMode   string `json:"StartMode"`
	Account     string `json:"StartName"`
	Command     string `json:"PathName"`
}

type psStartupItem struct {
	Source   string `json:"Source"`
	Name     string `json:"Name"`
	Command  string `json:"Command"`
	Location string `json:"Location"`
}

type psTask struct {
	Name    string `json:"Name"`
	Path    string `json:"Path"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Author  string `json:"Author"`
	Command string `json:"Command"`
}

type psImageHijack struct {
	Image        string `json:"Image"`
	Debugger     string `json:"Debugger"`
	RegistryPath string `json:"RegistryPath"`
}

type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func Collect(opts Options) (Snapshot, error) {
	var snapshot Snapshot

	psData, err := collectPowerShellSnapshot()
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "PowerShell: "+err.Error())
	} else {
		snapshot.Services = servicesFromPS(psData.Services, opts)
		snapshot.ScheduledTasks = tasksFromPS(psData.ScheduledTasks, opts)
		snapshot.Users = psData.Users
		snapshot.StartupItems = append(snapshot.StartupItems, startupFromPS(psData.StartupRegistry, opts)...)
		snapshot.StartupItems = append(snapshot.StartupItems, startupFromPS(psData.StartupFolders, opts)...)
		snapshot.ImageHijacks = hijacksFromPS(psData.ImageHijacks, opts)
	}

	if len(snapshot.ScheduledTasks) == 0 {
		tasks, err := collectScheduledTasks(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Scheduled tasks: "+err.Error())
		} else {
			snapshot.ScheduledTasks = tasks
		}
	}

	sort.Slice(snapshot.Services, func(i, j int) bool {
		return strings.ToLower(snapshot.Services[i].Name) < strings.ToLower(snapshot.Services[j].Name)
	})
	sort.Slice(snapshot.ScheduledTasks, func(i, j int) bool {
		return strings.ToLower(snapshot.ScheduledTasks[i].Path) < strings.ToLower(snapshot.ScheduledTasks[j].Path)
	})
	sort.Slice(snapshot.StartupItems, func(i, j int) bool {
		if snapshot.StartupItems[i].Source == snapshot.StartupItems[j].Source {
			return strings.ToLower(snapshot.StartupItems[i].Name) < strings.ToLower(snapshot.StartupItems[j].Name)
		}
		return snapshot.StartupItems[i].Source < snapshot.StartupItems[j].Source
	})
	sort.Slice(snapshot.Users, func(i, j int) bool {
		return strings.ToLower(snapshot.Users[i].Name) < strings.ToLower(snapshot.Users[j].Name)
	})
	sort.Slice(snapshot.ImageHijacks, func(i, j int) bool {
		return strings.ToLower(snapshot.ImageHijacks[i].Image) < strings.ToLower(snapshot.ImageHijacks[j].Image)
	})

	return snapshot, nil
}

func collectPowerShellSnapshot() (psSnapshot, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$ErrorActionPreference = 'SilentlyContinue'
function Get-WmiCompat($class, $filter) {
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    if ($filter) { return Get-CimInstance -ClassName $class -Filter $filter }
    return Get-CimInstance -ClassName $class
  }
  if ($filter) { return Get-WmiObject -Class $class -Filter $filter }
  return Get-WmiObject -Class $class
}
$services = Get-WmiCompat 'Win32_Service' '' | Select-Object Name,DisplayName,State,StartMode,StartName,PathName
$scheduledTasks = @()
try {
  $scheduledTasks = schtasks.exe /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.TaskName -and $_.TaskName -ne 'TaskName' } | ForEach-Object {
    [pscustomobject]@{
      Name=($_.TaskName -replace '^.*\\','')
      Path=$_.TaskName
      State=$_.'Scheduled Task State'
      Status=$_.Status
      Author=$_.Author
      Command=$_.'Task To Run'
    }
  }
} catch {}
$users = Get-WmiCompat 'Win32_UserAccount' "LocalAccount=True" | Select-Object Name,SID,Disabled,Lockout,PasswordRequired,LocalAccount
$startupRegistry = @()
$runKeys = @(
  @{Source='HKLM Run'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKLM RunOnce'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'},
  @{Source='HKCU Run'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKCU RunOnce'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'},
  @{Source='HKLM Wow6432 Run'; Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKLM Wow6432 RunOnce'; Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'}
)
foreach ($key in $runKeys) {
  $props = Get-ItemProperty -Path $key.Path
  if ($props) {
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -notmatch '^PS') {
        $startupRegistry += [pscustomobject]@{Source=$key.Source; Name=$prop.Name; Command=[string]$prop.Value; Location=$key.Path}
      }
    }
  }
}
$startupFolders = @()
$folders = @(
  @{Source='User Startup'; Path=[Environment]::GetFolderPath('Startup')},
  @{Source='Common Startup'; Path=[Environment]::GetFolderPath('CommonStartup')}
)
foreach ($folder in $folders) {
  if ($folder.Path -and (Test-Path $folder.Path)) {
    Get-ChildItem -LiteralPath $folder.Path | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
      $startupFolders += [pscustomobject]@{Source=$folder.Source; Name=$_.Name; Command=$_.FullName; Location=$folder.Path}
    }
  }
}
$imageHijacks = @()
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeoRoot) {
  Get-ChildItem -LiteralPath $ifeoRoot | ForEach-Object {
    $debugger = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger).Debugger
    if ($debugger) {
      $imageHijacks += [pscustomobject]@{Image=$_.PSChildName; Debugger=[string]$debugger; RegistryPath=$_.Name}
    }
  }
}
[pscustomobject]@{
  Services=@($services)
  ScheduledTasks=@($scheduledTasks)
  Users=@($users)
  StartupRegistry=@($startupRegistry)
  StartupFolders=@($startupFolders)
  ImageHijacks=@($imageHijacks)
} | ConvertTo-Json -Compress -Depth 5
`

	cmd := winexec.PowerShell(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return psSnapshot{}, errors.New(msg)
	}

	var snapshot psSnapshot
	if err := json.Unmarshal([]byte(decodeCommandOutput(out)), &snapshot); err != nil {
		return psSnapshot{}, err
	}
	return snapshot, nil
}

func servicesFromPS(items []psService, opts Options) []ServiceInfo {
	out := make([]ServiceInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ServiceInfo{
			Name:         item.Name,
			DisplayName:  item.DisplayName,
			State:        item.State,
			StartMode:    item.StartMode,
			Account:      item.Account,
			Command:      item.Command,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func startupFromPS(items []psStartupItem, opts Options) []StartupItem {
	out := make([]StartupItem, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, StartupItem{
			Source:       item.Source,
			Name:         item.Name,
			Command:      item.Command,
			Location:     item.Location,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func tasksFromPS(items []psTask, opts Options) []ScheduledTaskInfo {
	out := make([]ScheduledTaskInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ScheduledTaskInfo{
			Name:         item.Name,
			Path:         item.Path,
			State:        item.State,
			Status:       item.Status,
			Author:       item.Author,
			Command:      item.Command,
			Executable:   path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func hijacksFromPS(items []psImageHijack, opts Options) []ImageHijackInfo {
	out := make([]ImageHijackInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Debugger)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ImageHijackInfo{
			Image:        item.Image,
			Debugger:     item.Debugger,
			RegistryPath: item.RegistryPath,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func collectScheduledTasks(opts Options) ([]ScheduledTaskInfo, error) {
	if tasks, err := collectScheduledTasksCOM(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}
	if tasks, err := collectSchtasksPowerShell(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}
	if tasks, err := collectSchtasksCSV(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}

	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("cannot resolve scheduled task root")
	}

	var tasks []ScheduledTaskInfo
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}

		item, err := parseScheduledTask(root, path, opts)
		if err == nil && item.Command != "" {
			tasks = append(tasks, item)
		}
		return nil
	})
	return tasks, err
}

func collectScheduledTasksCOM(opts Options) ([]ScheduledTaskInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function Convert-TaskState($state) {
  switch ($state) { 0 {'Unknown'} 1 {'Disabled'} 2 {'Queued'} 3 {'Ready'} 4 {'Running'} default {[string]$state} }
}
function Walk-Folder($folder) {
  foreach ($task in @($folder.GetTasks(0))) {
    foreach ($action in @($task.Definition.Actions)) {
      if ($action.Type -eq 0) {
        [pscustomobject]@{
          Name=$task.Name
          Path=$task.Path
          State=($(if ($task.Enabled) {'Enabled'} else {'Disabled'}))
          Status=(Convert-TaskState $task.State)
          Author=$task.Definition.RegistrationInfo.Author
          Command=(($action.Path + ' ' + $action.Arguments).Trim())
        }
      }
    }
  }
  foreach ($child in @($folder.GetFolders(0))) { Walk-Folder $child }
}
$schedule = New-Object -ComObject Schedule.Service
$schedule.Connect()
@((Walk-Folder ($schedule.GetFolder('\')))) | ConvertTo-Json -Compress -Depth 4
`
	cmd := winexec.PowerShell(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var tasks []psTask
	if err := unmarshalPSTaskList(out, &tasks); err != nil {
		return nil, err
	}
	return tasksFromPS(tasks, opts), nil
}

func collectSchtasksPowerShell(opts Options) ([]ScheduledTaskInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$tasks = schtasks.exe /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.TaskName -and $_.TaskName -ne 'TaskName' } | ForEach-Object {
  [pscustomobject]@{
    Name=($_.TaskName -replace '^.*\\','')
    Path=$_.TaskName
    State=$_.'Scheduled Task State'
    Status=$_.Status
    Author=$_.Author
    Command=$_.'Task To Run'
  }
}
@($tasks) | ConvertTo-Json -Compress -Depth 4
`
	cmd := winexec.PowerShell(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var tasks []psTask
	if err := unmarshalPSTaskList(out, &tasks); err != nil {
		return nil, err
	}
	return tasksFromPS(tasks, opts), nil
}

func unmarshalPSTaskList(raw []byte, out *[]psTask) error {
	data := bytes.TrimSpace([]byte(decodeCommandOutput(raw)))
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '[' {
		return json.Unmarshal(data, out)
	}
	var one psTask
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*out = []psTask{one}
	return nil
}

func collectSchtasksCSV(opts Options) ([]ScheduledTaskInfo, error) {
	cmd := winexec.Command("schtasks.exe", "/query", "/fo", "csv", "/v")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(decodeCommandOutput(out)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	header := records[0]
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[name] = i
	}

	get := func(record []string, name string) string {
		i, ok := index[name]
		if !ok || i < 0 || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	tasks := make([]ScheduledTaskInfo, 0, len(records)-1)
	for _, record := range records[1:] {
		taskPath := get(record, "TaskName")
		if taskPath == "" || taskPath == "TaskName" {
			continue
		}

		command := get(record, "Task To Run")
		executable := executablePathFromCommand(command)
		md5, hashErr, sig := enrichExecutable(executable, opts)
		tasks = append(tasks, ScheduledTaskInfo{
			Name:         taskNameFromPath(taskPath),
			Path:         taskPath,
			State:        get(record, "Scheduled Task State"),
			Status:       get(record, "Status"),
			Author:       get(record, "Author"),
			Command:      command,
			Executable:   executable,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}

	return tasks, nil
}

func taskNameFromPath(path string) string {
	path = strings.TrimRight(path, `\`)
	if path == "" {
		return ""
	}
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func parseScheduledTask(root, path string, opts Options) (ScheduledTaskInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ScheduledTaskInfo{}, err
	}

	text := decodeTaskXML(raw)
	var task taskXML
	if err := xml.Unmarshal([]byte(text), &task); err != nil {
		return ScheduledTaskInfo{}, err
	}
	if len(task.Actions.Exec) == 0 {
		return ScheduledTaskInfo{}, nil
	}

	rel, _ := filepath.Rel(root, path)
	taskPath := `\` + strings.ReplaceAll(rel, string(os.PathSeparator), `\`)
	execAction := task.Actions.Exec[0]
	executable := executablePathFromCommand(execAction.Command)
	if executable == "" {
		executable = executablePathFromCommand(execAction.Command + " " + execAction.Arguments)
	}
	md5, hashErr, sig := enrichExecutable(executable, opts)

	return ScheduledTaskInfo{
		Name:         filepath.Base(path),
		Path:         taskPath,
		State:        "",
		Status:       "",
		Author:       task.RegistrationInfo.Author,
		Command:      execAction.Command,
		Arguments:    execAction.Arguments,
		Executable:   executable,
		MD5:          md5,
		Signature:    sig.Status,
		SignatureMsg: sig.Message,
		HashError:    hashErr,
	}, nil
}

func decodeTaskXML(raw []byte) string {
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
			}
			return string(utf16.Decode(u16))
		}
		if raw[0] == 0xfe && raw[1] == 0xff {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			}
			return string(utf16.Decode(u16))
		}
	}
	return string(raw)
}

func decodeCommandOutput(raw []byte) string {
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			return decodeUTF16LE(raw[2:])
		}
		if raw[0] == 0xfe && raw[1] == 0xff {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			}
			return string(utf16.Decode(u16))
		}
	}
	if looksUTF16LE(raw) {
		return decodeUTF16LE(raw)
	}
	return string(raw)
}

func looksUTF16LE(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	checked := 0
	zeros := 0
	for i := 1; i < len(raw) && checked < 200; i += 2 {
		checked++
		if raw[i] == 0 {
			zeros++
		}
	}
	return checked > 0 && zeros*100/checked > 60
}

func decodeUTF16LE(raw []byte) string {
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}

func enrichExecutable(path string, opts Options) (string, string, process.SignatureResult) {
	if path == "" {
		return "", "", process.SignatureResult{}
	}

	md5, hashErr := process.HashFileMD5(path, opts.HashLimitBytes)
	return md5, hashErr, process.CheckSignature(path)
}

func executablePathFromCommand(command string) string {
	command = strings.TrimSpace(expandWindowsEnv(command))
	if command == "" {
		return ""
	}

	command = strings.TrimPrefix(command, `\??\`)
	command = strings.TrimPrefix(command, `\\?\`)
	if isNonExecutableCommand(command) {
		return ""
	}

	if strings.HasPrefix(command, `"`) || strings.HasPrefix(command, `'`) {
		quote := command[0]
		if end := strings.IndexByte(command[1:], quote); end >= 0 {
			return normalizeExecutablePath(command[1:end+1], true)
		}
	}

	first := strings.Fields(command)
	if len(first) > 0 {
		if path := normalizeExecutablePath(first[0], false); path != "" {
			return path
		}
	}

	lower := strings.ToLower(command)
	for i := 0; i < len(lower); i++ {
		for _, ext := range executableExtensions {
			if strings.HasPrefix(lower[i:], ext) && isExecutableExtensionBoundary(command, i+len(ext)) {
				return normalizeExecutablePath(strings.TrimSpace(command[:i+len(ext)]), true)
			}
		}
	}

	return ""
}

var executableExtensions = []string{".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}

func isNonExecutableCommand(command string) bool {
	switch strings.ToLower(strings.Trim(command, `" '	`)) {
	case "com handler", "custom handler", "multiple actions", "n/a", "not available", "none", "null":
		return true
	default:
		return false
	}
}

func isExecutableExtensionBoundary(command string, end int) bool {
	if end >= len(command) {
		return true
	}
	switch command[end] {
	case ' ', '\t', '\r', '\n', '"', '\'', ',', ';':
		return true
	default:
		return false
	}
}

var percentEnvPattern = regexp.MustCompile(`%([^%]+)%`)

func expandWindowsEnv(value string) string {
	return percentEnvPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := strings.Trim(match, "%")
		if expanded := os.Getenv(name); expanded != "" {
			return expanded
		}
		return match
	})
}

func normalizeExecutablePath(path string, keepMissingAbsolute bool) string {
	path = strings.Trim(path, `" '	`)
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, `\??\`)
	path = strings.TrimPrefix(path, `\\?\`)
	if strings.HasPrefix(strings.ToLower(path), "system32\\") {
		path = filepath.Join(os.Getenv("SystemRoot"), path)
	}
	if strings.HasPrefix(strings.ToLower(path), "syswow64\\") {
		path = filepath.Join(os.Getenv("SystemRoot"), path)
	}

	if filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if info, err := os.Stat(clean); err == nil {
			if info.IsDir() {
				return ""
			}
			return clean
		}
		if keepMissingAbsolute {
			return clean
		}
		return ""
	}

	if candidate, err := exec.LookPath(path); err == nil {
		if clean, err := filepath.Abs(candidate); err == nil {
			return clean
		}
		return candidate
	}
	return ""
}

func (s Snapshot) Summary() string {
	return fmt.Sprintf("services=%d tasks=%d startup=%d users=%d ifeo=%d", len(s.Services), len(s.ScheduledTasks), len(s.StartupItems), len(s.Users), len(s.ImageHijacks))
}
