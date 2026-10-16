//go:build windows

package host

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"golang.org/x/sys/windows"
)

func resolvePersistencePath(value, workingDirectory string) string {
	value = strings.TrimSpace(expandPersistenceEnv(value))
	value = strings.TrimPrefix(strings.TrimPrefix(value, `\??\`), `\\?\`)
	if value == "" || strings.ContainsAny(value, "%$!\x00\r\n") {
		return ""
	}
	if strings.HasPrefix(value, `\\`) {
		return ""
	} // Do not contact attacker-controlled UNC paths.
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	if strings.HasPrefix(strings.ToLower(value), `system32\`) || strings.HasPrefix(strings.ToLower(value), `syswow64\`) {
		return filepath.Join(root, value)
	}
	if commandchain.IsInterpreter(value) {
		name := strings.ToLower(value)
		if filepath.Ext(name) == "" {
			name += ".exe"
		}
		if name == "powershell.exe" {
			return filepath.Join(root, `System32\WindowsPowerShell\v1.0`, name)
		}
		if name != "pwsh.exe" {
			return filepath.Join(root, "System32", name)
		}
	}
	if filepath.IsAbs(workingDirectory) {
		return filepath.Clean(filepath.Join(workingDirectory, value))
	}
	return ""
}

func expandPersistenceEnv(value string) string {
	return percentEnvPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := strings.Trim(match, "%")
		switch strings.ToLower(name) {
		case "systemroot", "windir", "systemdrive", "programfiles", "programfiles(x86)", "programdata", "allusersprofile", "commonprogramfiles", "commonprogramfiles(x86)":
			if expanded := os.Getenv(name); expanded != "" {
				return expanded
			}
		}
		return match
	})
}

func enrichPersistence(snapshot *Snapshot, opts Options) {
	deadline := time.Now().Add(15 * time.Second)
	cache := make(map[string]commandchain.Target)
	inspect := func(target commandchain.Target) commandchain.Target {
		if target.Kind != "file" || target.Path == "" {
			return target
		}
		key := strings.ToLower(target.Path)
		if old, ok := cache[key]; ok {
			old.Raw, old.Via = target.Raw, target.Via
			return old
		}
		if len(cache) >= 256 || time.Now().After(deadline) {
			target.FileStatus = "未检查（达到补采预算）"
			return target
		}
		target = inspectPersistenceTarget(target, opts.HashLimitBytes, true)
		cache[key] = target
		return target
	}
	parse := func(command, dir string) *commandchain.Chain {
		if isNonExecutableCommand(command) {
			return &commandchain.Chain{Warnings: []string{"此项不是可直接解析的文件执行动作；需在任务计划程序中核对其处理器和完整定义。"}}
		}
		chain := commandchain.Parse(command, commandchain.Options{WorkingDirectory: dir, Expand: expandPersistenceEnv, Resolve: resolvePersistencePath})
		chain.Launcher = inspectPersistenceTarget(chain.Launcher, opts.HashLimitBytes, false)
		for i := range chain.Payloads {
			chain.Payloads[i] = inspect(chain.Payloads[i])
		}
		return &chain
	}
	for i := range snapshot.Services {
		item := &snapshot.Services[i]
		item.ExecutionChain = parse(item.Command, "")
		preserveLauncherMetadata(item.ExecutionChain, item.Path, item.MD5, item.Signature, item.SignatureMsg, item.HashError)
		for _, view := range []struct{ source, command string }{{"SCM", item.SCMPath}, {"注册表 ImagePath", item.RegistryImagePath}, {"WMI PathName", item.WMIPath}} {
			if view.command != "" && normalizeServiceCommand(view.command) != normalizeServiceCommand(item.Command) {
				other := parse(view.command, "")
				item.ExecutionChain.Warnings = append(item.ExecutionChain.Warnings, view.source+" 与首选命令不一致，已额外解析其静态目标")
				item.ExecutionChain.Interpreters = append(item.ExecutionChain.Interpreters, other.Interpreters...)
				item.ExecutionChain.Asynchronous = item.ExecutionChain.Asynchronous || other.Asynchronous
				if other.Launcher.Path != "" && !strings.EqualFold(other.Launcher.Path, item.ExecutionChain.Launcher.Path) {
					other.Launcher.Via = view.source + " 入口"
					item.ExecutionChain.Payloads = append(item.ExecutionChain.Payloads, other.Launcher)
				}
				for _, target := range other.Payloads {
					target.Via = view.source + " / " + target.Via
					item.ExecutionChain.Payloads = append(item.ExecutionChain.Payloads, target)
				}
			}
		}
		applyServiceRisk(item, item.SCMPath != "", item.RegistryPath != "", item.WMIPath != "")
		if item.ExecutionChain.Asynchronous {
			item.StateNotice = "入口包含异步启动。Stopped 只描述 SCM 当前状态，不能据此判断子进程、注入载荷或持久化是否已清除。"
		}
	}
	for i := range snapshot.ScheduledTasks {
		item := &snapshot.ScheduledTasks[i]
		command := strings.TrimSpace(item.Command + " " + item.Arguments)
		item.ExecutionChain = parse(command, item.WorkingDirectory)
		preserveLauncherMetadata(item.ExecutionChain, item.Executable, item.MD5, item.Signature, item.SignatureMsg, item.HashError)
		item.RiskScore, item.RiskReasons = persistenceChainRisk(item.ExecutionChain, false)
		item.RiskLevel = persistenceLevel(item.RiskScore)
	}
	for i := range snapshot.StartupItems {
		item := &snapshot.StartupItems[i]
		item.ExecutionChain = parse(item.Command, "")
		preserveLauncherMetadata(item.ExecutionChain, item.Path, item.MD5, item.Signature, item.SignatureMsg, item.HashError)
		item.RiskScore, item.RiskReasons = persistenceChainRisk(item.ExecutionChain, false)
		item.RiskLevel = persistenceLevel(item.RiskScore)
	}
	for i := range snapshot.WMISubscriptions {
		item := &snapshot.WMISubscriptions[i]
		command := item.CommandLine
		if strings.TrimSpace(command) == "" {
			command = item.ExecutablePath
		}
		item.ExecutionChain = parse(command, "")
		preserveLauncherMetadata(item.ExecutionChain, item.ExecutablePath, item.ExecutableMD5, item.ExecutableSignature, item.ExecutableSigMsg, item.ExecutableHashErr)
		if !item.SystemManaged {
			score, reasons := persistenceChainRisk(item.ExecutionChain, false)
			item.RiskScore += score * 5
			item.RiskReasons = append(item.RiskReasons, reasons...)
			if item.RiskScore >= 50 {
				item.RiskLevel = "高"
			} else if item.RiskScore >= 25 {
				item.RiskLevel = "中"
			}
		}
	}
	if len(cache) >= 256 || time.Now().After(deadline) {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "持久化目标检查达到 256 个文件或 15 秒预算；未检查目标已单独标记，不能视为文件不存在。")
	}
	var fileWarnings []string
	snapshot.TargetedFiles, fileWarnings = collectPersistenceFiles(*snapshot, opts.HashLimitBytes)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, fileWarnings...)
	var serviceNames []string
	for _, item := range snapshot.Services {
		if item.RiskScore >= 4 {
			serviceNames = append(serviceNames, item.Name)
		}
	}
	var eventWarnings []string
	snapshot.MatchedEvents, eventWarnings = securitylog.CollectPersistenceMatches(serviceNames)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, eventWarnings...)
}

func preserveLauncherMetadata(chain *commandchain.Chain, path, md5, signature, message, hashError string) {
	if chain != nil && strings.EqualFold(chain.Launcher.Path, path) {
		chain.Launcher.MD5 = md5
		chain.Launcher.Signature = signature
		chain.Launcher.SignatureMsg = message
		chain.Launcher.HashError = hashError
	}
}

func inspectPersistenceTarget(target commandchain.Target, hashLimit int64, hash bool) commandchain.Target {
	if target.Kind != "file" || !filepath.IsAbs(target.Path) || strings.HasPrefix(target.Path, `\\`) {
		return target
	}
	if reason := unsafePersistenceLocation(target.Path); reason != "" {
		target.FileStatus = "未检查（路径边界）"
		target.CheckError = reason
		return target
	}
	info, err := os.Lstat(target.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			target.FileStatus = "文件不存在"
		} else {
			target.FileStatus = "不可访问"
			target.CheckError = err.Error()
		}
		return target
	}
	if info.IsDir() {
		target.FileStatus = "路径为目录"
		return target
	}
	if attrs, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			target.FileStatus = "重解析点（未跟随）"
			return target
		}
		target.Created = time.Unix(0, attrs.CreationTime.Nanoseconds()).UTC().Format(time.RFC3339Nano)
	}
	target.FileStatus = "存在"
	target.Size = info.Size()
	target.Modified = info.ModTime().UTC().Format(time.RFC3339Nano)
	if !hash {
		return target
	}
	if hashLimit <= 0 || hashLimit > 64*1024*1024 {
		hashLimit = 64 * 1024 * 1024
	}
	if info.Size() > hashLimit {
		target.HashError = fmt.Sprintf("目标超过 %d MB 补采哈希/签名预算", hashLimit/1024/1024)
		return target
	}
	if info.Size() <= hashLimit {
		f, openErr := os.Open(target.Path)
		if openErr != nil {
			target.HashError = openErr.Error()
			return target
		}
		h := sha256.New()
		md5Hash := md5.New()
		n, readErr := io.Copy(io.MultiWriter(h, md5Hash), io.LimitReader(f, hashLimit+1))
		after, statErr := f.Stat()
		f.Close()
		if readErr != nil {
			target.HashError = readErr.Error()
		} else if n != info.Size() || statErr != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			target.MD5 = ""
			target.HashError = "文件在采集期间发生变化，哈希不能作为稳定文件身份"
		} else {
			target.SHA256 = hex.EncodeToString(h.Sum(nil))
			target.MD5 = hex.EncodeToString(md5Hash.Sum(nil))
		}
	}
	sig := process.CheckSignature(target.Path)
	target.Signature, target.SignatureMsg = sig.Status, sig.Message
	return target
}

func unsafePersistenceLocation(path string) string {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return "仅检查本地盘符路径；远程或设备路径未访问"
	}
	root, _ := windows.UTF16PtrFromString(volume + `\`)
	if windows.GetDriveType(root) == windows.DRIVE_REMOTE {
		return "目标位于映射网络驱动器，未访问"
	}
	var parents []string
	for dir := filepath.Dir(path); filepath.Dir(dir) != dir; dir = filepath.Dir(dir) {
		parents = append(parents, dir)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		p, err := windows.UTF16PtrFromString(parents[i])
		if err != nil {
			return "路径无效"
		}
		attrs, err := windows.GetFileAttributes(p)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				return ""
			}
			return "父目录不可访问：" + err.Error()
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "父目录为重解析点，未跟随：" + parents[i]
		}
	}
	return ""
}

func persistenceChainRisk(chain *commandchain.Chain, service bool) (int, []string) {
	if chain == nil || len(chain.Interpreters) == 0 {
		return 0, nil
	}
	score := 1
	reasons := []string{"持久化命令使用解释器或代理执行入口；入口签名不代表后续目标可信"}
	if service {
		score = 3
	}
	if chain.Encoded {
		score += 3
		reasons = append(reasons, "包含编码 PowerShell 命令")
	}
	if chain.Asynchronous {
		score++
		reasons = append(reasons, "命令包含异步启动，服务停止不能证明载荷退出")
	}
	if len(chain.Payloads) > 0 {
		score++
		reasons = append(reasons, "命令包含独立的后续目标")
	}
	flags := map[string]bool{}
	add := func(key string, points int, reason string) {
		if !flags[key] {
			flags[key] = true
			score += points
			reasons = append(reasons, reason)
		}
	}
	for _, target := range chain.Payloads {
		if target.Kind == "url" {
			add("url", 3, "命令引用远程 URL（仅保留字符串，未访问）")
			continue
		}
		if target.Kind != "file" {
			continue
		}
		if writableServicePath(target.Path) {
			add("path", 3, "后续目标位于用户可写或公共目录")
		} else if nonstandardPersistencePath(target.Path) {
			add("path", 2, "后续目标位于非标准安装目录，需结合目录权限复核")
		}
		if target.FileStatus == "文件不存在" {
			add("missing", 3, "后续目标文件缺失，持久化配置仍可能残留")
		}
		if target.Signature == "无签名请注意!!!" {
			add("signature", 2, "后续目标无可信签名")
		} else if target.Signature == "签名异常" {
			add("signature-bad", 4, "后续目标签名异常")
		}
	}
	return score, reasons
}

func nonstandardPersistencePath(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for _, root := range []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`} {
		if root != "" && strings.HasPrefix(strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(root))+`\`) {
			return false
		}
	}
	return true
}

func persistenceLevel(score int) string {
	if score >= 8 {
		return "高"
	}
	if score >= 4 {
		return "中"
	}
	if score > 0 {
		return "低"
	}
	return ""
}

func collectPersistenceFiles(snapshot Snapshot, hashLimit int64) ([]TargetedFile, []string) {
	var out []TargetedFile
	limited := false
	indices := map[string]int{}
	deadline := time.Now().Add(6 * time.Second)
	add := func(chain *commandchain.Chain, reference string) {
		if chain == nil {
			return
		}
		for _, target := range chain.Payloads {
			if target.Kind != "file" || target.Path == "" || commandchain.IsInterpreter(filepath.Base(target.Path)) {
				continue
			}
			if target.FileStatus == "未检查（路径边界）" {
				continue
			}
			key := strings.ToLower(target.Path)
			if index, ok := indices[key]; ok {
				out[index].References = append(out[index].References, reference)
				continue
			}
			if len(out) >= 32 || time.Now().After(deadline) {
				limited = true
				continue
			}
			entry := TargetedFile{Target: target, References: []string{reference}}
			dir := filepath.Dir(target.Path)
			info, err := os.Lstat(dir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					entry.DirectoryStatus = "目录不存在"
				} else {
					entry.DirectoryStatus = "不可访问"
					entry.Warnings = append(entry.Warnings, err.Error())
				}
			} else {
				entry.DirectoryStatus = "存在"
				if attrs, ok := info.Sys().(*syscall.Win32FileAttributeData); ok && attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
					entry.DirectoryStatus = "重解析点（未跟随）"
				} else {
					entry.DirectoryACL = directoryACL(dir)
					if filepath.Dir(dir) != dir {
						f, openErr := os.Open(dir)
						if openErr == nil {
							siblings, readErr := f.ReadDir(25)
							f.Close()
							if readErr != nil && readErr != io.EOF {
								entry.Warnings = append(entry.Warnings, readErr.Error())
							}
							if len(siblings) > 24 {
								siblings = siblings[:24]
								entry.Warnings = append(entry.Warnings, "同目录文件达到 24 条展示上限")
							}
							for _, sibling := range siblings {
								if !sibling.IsDir() && !strings.EqualFold(sibling.Name(), filepath.Base(target.Path)) {
									entry.NearbyFiles = append(entry.NearbyFiles, inspectPersistenceTarget(commandchain.Target{Path: filepath.Join(dir, sibling.Name()), Kind: "file", Via: "同目录文件（仅元数据）"}, hashLimit, false))
								}
							}
						} else {
							entry.Warnings = append(entry.Warnings, openErr.Error())
						}
					}
				}
			}
			if target.FileStatus == "存在" {
				entry.Streams = targetStreams(target.Path)
			}
			entry.Warnings = append(entry.Warnings, "定向补采仅包含当前文件、父目录 ACL、ADS 名称及同目录有限元数据；不代表完整目录或已删除文件取证。")
			indices[key] = len(out)
			out = append(out, entry)
		}
	}
	for _, item := range snapshot.Services {
		if item.RiskScore >= 4 {
			add(item.ExecutionChain, "服务："+item.Name)
		}
	}
	for _, item := range snapshot.ScheduledTasks {
		if item.RiskScore >= 4 {
			add(item.ExecutionChain, "计划任务："+item.Path)
		}
	}
	for _, item := range snapshot.StartupItems {
		if item.RiskScore >= 4 {
			add(item.ExecutionChain, "启动项："+item.Name)
		}
	}
	for _, item := range snapshot.WMISubscriptions {
		if item.RiskLevel == "中" || item.RiskLevel == "高" {
			add(item.ExecutionChain, "WMI："+item.ConsumerName)
		}
	}
	var warnings []string
	if limited {
		warnings = append(warnings, "持久化父目录补采达到 32 个目标或 6 秒预算；未覆盖目标仍可在原始执行链中查看。")
	}
	return out, warnings
}

func directoryACL(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "ACL 读取失败：" + err.Error()
	}
	return sd.String()
}

func targetStreams(path string) []string {
	var data struct {
		Size int64
		Name [296]uint16
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	first := syscall.NewLazyDLL("kernel32.dll").NewProc("FindFirstStreamW")
	next := syscall.NewLazyDLL("kernel32.dll").NewProc("FindNextStreamW")
	h, _, callErr := first.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&data)), 0)
	if h == ^uintptr(0) {
		if callErr == syscall.ERROR_HANDLE_EOF {
			return nil
		}
		return []string{"ADS 枚举不可用：" + callErr.Error()}
	}
	defer windows.FindClose(windows.Handle(h))
	var values []string
	for len(values) < 16 {
		values = append(values, fmt.Sprintf("%s (%d bytes)", syscall.UTF16ToString(data.Name[:]), data.Size))
		ok, _, _ := next.Call(h, uintptr(unsafe.Pointer(&data)))
		if ok == 0 {
			break
		}
	}
	return values
}
