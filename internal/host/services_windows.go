//go:build windows

package host

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type scmServiceInfo struct {
	Name, DisplayName, State, StartMode, Account, Command string
}

type registryServiceInfo struct {
	Name, DisplayName, Account, ImagePath, ServiceDLL, RegistryPath string
	Start, Type                                                     uint64
}

func collectSCMServices() ([]scmServiceInfo, error) {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	manager := &mgr.Mgr{Handle: handle}
	defer manager.Disconnect()
	names, err := manager.ListServices()
	if err != nil {
		return nil, err
	}
	items := make([]scmServiceInfo, 0, len(names))
	for _, name := range names {
		namePtr, ptrErr := syscall.UTF16PtrFromString(name)
		if ptrErr != nil {
			continue
		}
		serviceHandle, openErr := windows.OpenService(handle, namePtr, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
		if openErr != nil {
			continue
		}
		service := &mgr.Service{Name: name, Handle: serviceHandle}
		config, configErr := service.Config()
		status, statusErr := service.Query()
		service.Close()
		if configErr != nil {
			continue
		}
		item := scmServiceInfo{Name: name, DisplayName: config.DisplayName, StartMode: serviceStartMode(config.StartType), Account: config.ServiceStartName, Command: config.BinaryPathName}
		if statusErr == nil {
			item.State = serviceState(status.State)
		}
		items = append(items, item)
	}
	return items, nil
}

func collectRegistryServices() ([]registryServiceInfo, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.READ|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	items := make([]registryServiceInfo, 0, len(names))
	for _, name := range names {
		key, openErr := registry.OpenKey(root, name, registry.READ)
		if openErr != nil {
			continue
		}
		serviceType, _, _ := key.GetIntegerValue("Type")
		if serviceType != windows.SERVICE_WIN32_OWN_PROCESS && serviceType != windows.SERVICE_WIN32_SHARE_PROCESS {
			key.Close()
			continue
		}
		image, _, _ := key.GetStringValue("ImagePath")
		display, _, _ := key.GetStringValue("DisplayName")
		account, _, _ := key.GetStringValue("ObjectName")
		start, _, _ := key.GetIntegerValue("Start")
		key.Close()
		parameters, _ := registry.OpenKey(root, name+`\Parameters`, registry.READ)
		serviceDLL := ""
		if parameters != 0 {
			serviceDLL, _, _ = parameters.GetStringValue("ServiceDll")
			parameters.Close()
		}
		items = append(items, registryServiceInfo{Name: name, DisplayName: display, Account: account, ImagePath: image, ServiceDLL: serviceDLL, RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\` + name, Start: start, Type: serviceType})
	}
	return items, nil
}

func mergeServiceSources(wmi []psService, scmItems []scmServiceInfo, registryItems []registryServiceInfo, opts Options) []ServiceInfo {
	wmiByName := make(map[string]psService, len(wmi))
	scmByName := make(map[string]scmServiceInfo, len(scmItems))
	regByName := make(map[string]registryServiceInfo, len(registryItems))
	names := make(map[string]string)
	for _, item := range wmi {
		key := strings.ToLower(item.Name)
		wmiByName[key] = item
		names[key] = item.Name
	}
	for _, item := range scmItems {
		key := strings.ToLower(item.Name)
		scmByName[key] = item
		names[key] = item.Name
	}
	for _, item := range registryItems {
		key := strings.ToLower(item.Name)
		regByName[key] = item
		names[key] = item.Name
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ServiceInfo, 0, len(keys))
	for _, key := range keys {
		wmiItem, hasWMI := wmiByName[key]
		scmItem, hasSCM := scmByName[key]
		regItem, hasReg := regByName[key]
		command := firstServiceValue(scmItem.Command, regItem.ImagePath, wmiItem.Command)
		path := executablePathFromCommand(command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		serviceDLL := expandWindowsEnv(regItem.ServiceDLL)
		if serviceDLL != "" {
			serviceDLL = executablePathFromCommand(serviceDLL)
		}
		dllSig := process.SignatureResult{}
		if serviceDLL != "" {
			dllSig = process.CheckSignature(serviceDLL)
		}
		item := ServiceInfo{
			Name: names[key], DisplayName: firstServiceValue(scmItem.DisplayName, wmiItem.DisplayName, regItem.DisplayName), State: firstServiceValue(scmItem.State, wmiItem.State),
			StartMode: firstServiceValue(scmItem.StartMode, wmiItem.StartMode, serviceStartMode(uint32(regItem.Start))), Account: firstServiceValue(scmItem.Account, wmiItem.Account, regItem.Account),
			Command: command, Path: path, MD5: md5, Signature: sig.Status, SignatureMsg: sig.Message, HashError: hashErr, SCMPath: scmItem.Command, RegistryImagePath: regItem.ImagePath,
			WMIPath: wmiItem.Command, RegistryPath: regItem.RegistryPath, ServiceDLL: serviceDLL, ServiceDLLSignature: dllSig.Status, ServiceDLLSigMsg: dllSig.Message,
		}
		item.SourceStatus = serviceSourceStatus(hasSCM, hasReg, hasWMI, scmItem.Command, regItem.ImagePath, wmiItem.Command)
		item.FileStatus = serviceFileStatus(path)
		applyServiceRisk(&item, hasSCM, hasReg, hasWMI)
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func serviceSourceStatus(hasSCM, hasReg, hasWMI bool, scmPath, regPath, wmiPath string) string {
	if servicePathsDiffer(scmPath, regPath, wmiPath) {
		return "ImagePath不一致"
	}
	switch {
	case hasSCM && hasReg && hasWMI:
		return "三源一致"
	case hasSCM && hasReg && !hasWMI:
		return "WMI缺失"
	case hasSCM && !hasReg:
		return "仅SCM"
	case !hasSCM && hasReg:
		return "仅注册表"
	case hasWMI:
		return "仅WMI"
	default:
		return "来源未知"
	}
}
func servicePathsDiffer(values ...string) bool {
	normalized := map[string]struct{}{}
	for _, value := range values {
		value = normalizeServiceCommand(value)
		if value != "" {
			normalized[value] = struct{}{}
		}
	}
	return len(normalized) > 1
}
func normalizeServiceCommand(value string) string {
	value = expandWindowsEnv(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, `\??\`)
	value = strings.TrimPrefix(value, `\\?\`)
	return strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(value, `/`, `\`)), " "))
}
func applyServiceRisk(item *ServiceInfo, hasSCM, hasReg, hasWMI bool) {
	add := func(points int, reason string) {
		item.RiskScore += points
		item.RiskReasons = append(item.RiskReasons, reason)
	}
	if hasReg && !hasSCM && !hasWMI {
		add(4, "注册表存在，但 SCM/WMI 未发现")
	}
	if hasSCM && !hasReg {
		add(4, "SCM 存在，但 Services 注册表项缺失")
	}
	if item.SourceStatus == "ImagePath不一致" {
		add(4, "SCM、注册表和 WMI 的 ImagePath 不一致")
	}
	if item.Path != "" && item.FileStatus == "文件不存在" {
		add(4, "服务可执行文件不存在")
	}
	if writableServicePath(item.Path) {
		add(3, "服务文件位于用户可写目录")
	}
	if writableServicePath(item.ServiceDLL) {
		add(4, "ServiceDLL 位于用户可写目录")
	}
	if isAutomaticService(item.StartMode) && (item.Signature == "无签名请注意!!!" || item.Signature == "签名异常") {
		add(3, "自动启动服务文件无可信签名")
	}
	if item.ServiceDLL != "" && (item.ServiceDLLSignature == "无签名请注意!!!" || item.ServiceDLLSignature == "签名异常") {
		add(2, "ServiceDLL 无可信签名")
	}
	if randomServiceName(item.Name) {
		add(1, "服务名称疑似随机")
	}
	if item.RiskScore >= 8 {
		item.RiskLevel = "高"
	} else if item.RiskScore >= 4 {
		item.RiskLevel = "中"
	} else if item.RiskScore > 0 {
		item.RiskLevel = "低"
	}
}
func serviceFileStatus(path string) string {
	if path == "" {
		return "未解析"
	}
	info, err := os.Stat(path)
	if err != nil {
		return "文件不存在"
	}
	if info.IsDir() {
		return "路径为目录"
	}
	return "存在"
}
func writableServicePath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{`\users\`, `\appdata\`, `\temp\`, `\programdata\`, `\public\`, `\downloads\`, `\desktop\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func randomServiceName(value string) bool {
	if len(value) < 10 {
		return false
	}
	letters, digits := 0, 0
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letters++
		} else if r >= '0' && r <= '9' {
			digits++
		} else {
			return false
		}
	}
	return letters > 0 && digits > 0
}
func isAutomaticService(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "auto") || strings.Contains(lower, "自动")
}
func serviceStartMode(value uint32) string {
	switch value {
	case windows.SERVICE_AUTO_START:
		return "Automatic"
	case windows.SERVICE_DEMAND_START:
		return "Manual"
	case windows.SERVICE_DISABLED:
		return "Disabled"
	case windows.SERVICE_BOOT_START:
		return "Boot"
	case windows.SERVICE_SYSTEM_START:
		return "System"
	default:
		return fmt.Sprintf("%d", value)
	}
}
func serviceState(value svc.State) string {
	switch value {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "ContinuePending"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	default:
		return fmt.Sprintf("%d", value)
	}
}
func firstServiceValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
