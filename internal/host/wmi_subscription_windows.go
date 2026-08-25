//go:build windows

package host

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const rpcEChangedMode = uintptr(0x80010106)

type wmiFilter struct {
	Path           string
	Name           string
	Query          string
	QueryLanguage  string
	EventNamespace string
	CreatorSID     string
}

type wmiConsumer struct {
	Path             string
	Name             string
	Class            string
	CommandLine      string
	ExecutablePath   string
	ScriptText       string
	Details          string
	RunInteractively bool
	CreatorSID       string
}

type wmiBinding struct {
	Path       string
	Filter     string
	Consumer   string
	CreatorSID string
}

var (
	wmiExactTimePattern = regexp.MustCompile(`(?i)\b(hour|minute|second|day|dayofweek)\s*=\s*\d+`)
	wmiShortPathPattern = regexp.MustCompile(`(?i)(?:^|[\\/])[^\\/\s"']*~\d+(?:[\\/]|$)`)
	wmiCommandPattern   = regexp.MustCompile(`(?i)\b(powershell|pwsh|cmd(?:\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|invoke-webrequest|downloadstring|frombase64string|iex)\b`)
	quotedPathPattern   = regexp.MustCompile(`(?i)["']([^"']+\.(?:exe|com|bat|cmd|ps1|vbs|js|hta))["']`)
	plainPathPattern    = regexp.MustCompile(`(?i)([a-z]:\\[^\r\n"]+?\.(?:exe|com|bat|cmd|ps1|vbs|js|hta))`)
)

func collectWMISubscriptions(services []ServiceInfo, tasks []ScheduledTaskInfo, opts Options) ([]WMISubscription, []string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initialized := false
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || oleErr.Code() != rpcEChangedMode {
			return nil, []string{"WMI COM 初始化: " + err.Error()}
		}
	} else {
		initialized = true
	}
	if initialized {
		defer ole.CoUninitialize()
	}

	items := make([]WMISubscription, 0)
	warnings := make([]string, 0)
	for _, namespace := range []string{"root\\subscription", "root\\default"} {
		namespaceItems, err := collectWMINamespace(namespace, services, tasks, opts)
		if err != nil {
			if namespace == "root\\subscription" {
				warnings = append(warnings, "WMI 永久事件订阅 "+namespace+": "+err.Error())
			}
			continue
		}
		items = append(items, namespaceItems...)
	}
	items = dedupeWMISubscriptions(items)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].RiskScore != items[j].RiskScore {
			return items[i].RiskScore > items[j].RiskScore
		}
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return strings.ToLower(items[i].FilterName+items[i].ConsumerName) < strings.ToLower(items[j].FilterName+items[j].ConsumerName)
	})
	return items, warnings
}

func collectWMINamespace(namespace string, services []ServiceInfo, tasks []ScheduledTaskInfo, opts Options) ([]WMISubscription, error) {
	locatorUnknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, err
	}
	defer locatorUnknown.Release()
	locator, err := locatorUnknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer locator.Release()

	serviceVariant, err := oleutil.CallMethod(locator, "ConnectServer", ".", namespace)
	if err != nil {
		return nil, err
	}
	defer serviceVariant.Clear()
	service := serviceVariant.ToIDispatch()
	if service == nil {
		return nil, fmt.Errorf("ConnectServer 未返回 IWbemServices")
	}
	setWMISecurity(service)

	filterList := make([]wmiFilter, 0)
	err = queryWMIObjects(service, "SELECT * FROM __EventFilter", func(object *ole.IDispatch) {
		item := wmiFilter{
			Path:           wmiPathProperty(object, "Relpath"),
			Name:           wmiStringProperty(object, "Name"),
			Query:          wmiStringProperty(object, "Query"),
			QueryLanguage:  wmiStringProperty(object, "QueryLanguage"),
			EventNamespace: wmiStringProperty(object, "EventNamespace"),
			CreatorSID:     wmiSIDProperty(object, "CreatorSID"),
		}
		filterList = append(filterList, item)
	})
	if err != nil {
		return nil, err
	}

	consumerList := make([]wmiConsumer, 0)
	err = queryWMIObjects(service, "SELECT * FROM __EventConsumer", func(object *ole.IDispatch) {
		item := wmiConsumer{
			Path:             wmiPathProperty(object, "Relpath"),
			Name:             wmiStringProperty(object, "Name"),
			Class:            wmiPathProperty(object, "Class"),
			CommandLine:      wmiStringProperty(object, "CommandLineTemplate"),
			ExecutablePath:   wmiStringProperty(object, "ExecutablePath"),
			ScriptText:       limitedWMIText(wmiStringProperty(object, "ScriptText"), 64*1024),
			Details:          wmiConsumerDetails(object),
			RunInteractively: wmiBoolProperty(object, "RunInteractively"),
			CreatorSID:       wmiSIDProperty(object, "CreatorSID"),
		}
		consumerList = append(consumerList, item)
	})
	if err != nil {
		return nil, err
	}

	bindings := make([]wmiBinding, 0)
	err = queryWMIObjects(service, "SELECT * FROM __FilterToConsumerBinding", func(object *ole.IDispatch) {
		bindings = append(bindings, wmiBinding{
			Path:       wmiPathProperty(object, "Relpath"),
			Filter:     wmiStringProperty(object, "Filter"),
			Consumer:   wmiStringProperty(object, "Consumer"),
			CreatorSID: wmiSIDProperty(object, "CreatorSID"),
		})
	})
	if err != nil {
		return nil, err
	}

	return mergeWMISubscriptionObjects(namespace, filterList, consumerList, bindings, services, tasks, opts), nil
}

func mergeWMISubscriptionObjects(namespace string, filterList []wmiFilter, consumerList []wmiConsumer, bindings []wmiBinding, services []ServiceInfo, tasks []ScheduledTaskInfo, opts Options) []WMISubscription {
	filters := make(map[string]wmiFilter, len(filterList))
	for _, filter := range filterList {
		if key := canonicalWMIReference(filter.Path); key != "" {
			filters[key] = filter
		}
	}
	consumers := make(map[string]wmiConsumer, len(consumerList))
	for _, consumer := range consumerList {
		if key := canonicalWMIReference(consumer.Path); key != "" {
			consumers[key] = consumer
		}
	}

	boundFilters := make(map[string]bool)
	boundConsumers := make(map[string]bool)
	items := make([]WMISubscription, 0, len(bindings)+len(filterList)+len(consumerList))
	for _, binding := range bindings {
		filterKey := canonicalWMIReference(binding.Filter)
		consumerKey := canonicalWMIReference(binding.Consumer)
		filter, filterOK := filters[filterKey]
		consumer, consumerOK := consumers[consumerKey]
		if filterKey != "" {
			boundFilters[filterKey] = true
		}
		if consumerKey != "" {
			boundConsumers[consumerKey] = true
		}
		status := "已绑定"
		if !filterOK || !consumerOK {
			status = "绑定引用缺失"
		}
		item := newWMISubscription(namespace, status, binding, filter, consumer)
		enrichWMISubscription(&item, services, tasks, opts)
		items = append(items, item)
	}
	for _, filter := range filterList {
		if boundFilters[canonicalWMIReference(filter.Path)] {
			continue
		}
		item := newWMISubscription(namespace, "孤立过滤器", wmiBinding{}, filter, wmiConsumer{})
		enrichWMISubscription(&item, services, tasks, opts)
		items = append(items, item)
	}
	for _, consumer := range consumerList {
		if boundConsumers[canonicalWMIReference(consumer.Path)] {
			continue
		}
		item := newWMISubscription(namespace, "孤立消费者", wmiBinding{}, wmiFilter{}, consumer)
		enrichWMISubscription(&item, services, tasks, opts)
		items = append(items, item)
	}
	return items
}

func queryWMIObjects(service *ole.IDispatch, query string, visit func(*ole.IDispatch)) error {
	result, err := oleutil.CallMethod(service, "ExecQuery", query, "WQL", 0x30)
	if err != nil {
		return err
	}
	defer result.Clear()
	set := result.ToIDispatch()
	if set == nil {
		return fmt.Errorf("WMI 查询未返回对象集合")
	}
	return oleutil.ForEach(set, func(value *ole.VARIANT) error {
		object := value.ToIDispatch()
		if object == nil {
			return nil
		}
		defer object.Release()
		visit(object)
		return nil
	})
}

func setWMISecurity(service *ole.IDispatch) {
	security, err := service.GetProperty("Security_")
	if err != nil {
		return
	}
	defer security.Clear()
	dispatch := security.ToIDispatch()
	if dispatch == nil {
		return
	}
	if result, err := oleutil.PutProperty(dispatch, "ImpersonationLevel", 3); err == nil {
		result.Clear()
	}
}

func wmiStringProperty(object *ole.IDispatch, name string) string {
	value, err := object.GetProperty(name)
	if err == nil && value != nil {
		text := wmiVariantText(value)
		value.Clear()
		if text != "" {
			return text
		}
	}
	value, err = wmiPropertySetValue(object, name)
	if err != nil || value == nil {
		return ""
	}
	defer value.Clear()
	return wmiVariantText(value)
}

// WMI scripting objects expose system properties through Path_ rather than as
// ordinary dynamic properties. Reading __RELPATH/__CLASS directly works on
// some hosts but returns empty values on others.
func wmiPathProperty(object *ole.IDispatch, name string) string {
	pathValue, err := object.GetProperty("Path_")
	if err != nil || pathValue == nil {
		return ""
	}
	defer pathValue.Clear()
	pathObject := pathValue.ToIDispatch()
	if pathObject == nil {
		return ""
	}
	defer pathObject.Release()
	value, err := pathObject.GetProperty(name)
	if err != nil || value == nil {
		return ""
	}
	defer value.Clear()
	return wmiVariantText(value)
}

func wmiPropertySetValue(object *ole.IDispatch, name string) (*ole.VARIANT, error) {
	propertiesValue, err := object.GetProperty("Properties_")
	if err != nil || propertiesValue == nil {
		return nil, err
	}
	defer propertiesValue.Clear()
	properties := propertiesValue.ToIDispatch()
	if properties == nil {
		return nil, fmt.Errorf("WMI Properties_ 未返回属性集合")
	}
	defer properties.Release()
	propertyValue, err := oleutil.CallMethod(properties, "Item", name, 0)
	if err != nil || propertyValue == nil {
		return nil, err
	}
	defer propertyValue.Clear()
	property := propertyValue.ToIDispatch()
	if property == nil {
		return nil, fmt.Errorf("WMI 属性 %s 未返回属性对象", name)
	}
	defer property.Release()
	return property.GetProperty("Value")
}

func wmiVariantText(value *ole.VARIANT) string {
	if value == nil {
		return ""
	}
	if value.VT == ole.VT_BSTR {
		return strings.TrimSpace(value.ToString())
	}
	if value.VT&ole.VT_ARRAY != 0 || value.VT == ole.VT_DISPATCH || value.VT == ole.VT_UNKNOWN {
		return ""
	}
	if raw := value.Value(); raw != nil {
		return strings.TrimSpace(fmt.Sprint(raw))
	}
	return ""
}

func wmiBoolProperty(object *ole.IDispatch, name string) bool {
	value, err := object.GetProperty(name)
	if err != nil {
		return false
	}
	defer value.Clear()
	if result, ok := value.Value().(bool); ok {
		return result
	}
	parsed, _ := strconv.ParseBool(strings.TrimSpace(fmt.Sprint(value.Value())))
	return parsed
}

func wmiSIDProperty(object *ole.IDispatch, name string) string {
	value, err := object.GetProperty(name)
	if err != nil || value == nil || value.ToArray() == nil {
		if value != nil {
			value.Clear()
		}
		value, err = wmiPropertySetValue(object, name)
		if err != nil || value == nil {
			return ""
		}
	}
	defer value.Clear()
	array := value.ToArray()
	if array == nil {
		return ""
	}
	data := wmiSafeArrayBytes(array)
	if len(data) < 8 {
		return ""
	}
	sid := (*windows.SID)(unsafe.Pointer(&data[0]))
	if !sid.IsValid() {
		return ""
	}
	return sid.String()
}

func wmiSafeArrayBytes(array *ole.SafeArrayConversion) []byte {
	if array == nil {
		return nil
	}
	if valueType, err := array.GetType(); err == nil && (ole.VT(valueType) == ole.VT_UI1 || ole.VT(valueType) == ole.VT_I1) {
		return array.ToByteArray()
	}
	if elementSize, err := array.GetSize(); err == nil && elementSize != nil && *elementSize == 1 {
		return array.ToByteArray()
	}
	values := array.ToValueArray()
	data := make([]byte, 0, len(values))
	for _, value := range values {
		switch typed := value.(type) {
		case uint8:
			data = append(data, typed)
		case int8:
			data = append(data, byte(typed))
		case uint16:
			if typed > 255 {
				return nil
			}
			data = append(data, byte(typed))
		case int16:
			if typed < 0 || typed > 255 {
				return nil
			}
			data = append(data, byte(typed))
		case uint32:
			if typed > 255 {
				return nil
			}
			data = append(data, byte(typed))
		case int32:
			if typed < 0 || typed > 255 {
				return nil
			}
			data = append(data, byte(typed))
		default:
			return nil
		}
	}
	return data
}

func wmiConsumerDetails(object *ole.IDispatch) string {
	fields := []string{
		"WorkingDirectory", "ScriptingEngine", "Filename", "Text", "SourceName",
		"EventID", "EventType", "SMTPServer", "ToLine", "FromLine", "Subject", "Message",
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := limitedWMIText(wmiStringProperty(object, field), 4096); value != "" {
			parts = append(parts, field+"="+value)
		}
	}
	return strings.Join(parts, "；")
}

func newWMISubscription(namespace, status string, binding wmiBinding, filter wmiFilter, consumer wmiConsumer) WMISubscription {
	return WMISubscription{
		Namespace: namespace, Status: status, BindingPath: binding.Path,
		FilterPath: filter.Path, FilterName: filter.Name, Query: filter.Query, QueryLanguage: filter.QueryLanguage,
		EventNamespace: filter.EventNamespace, FilterCreatorSID: filter.CreatorSID,
		ConsumerPath: consumer.Path, ConsumerName: consumer.Name, ConsumerType: consumer.Class,
		CommandLine: consumer.CommandLine, ExecutablePath: consumer.ExecutablePath, ScriptText: consumer.ScriptText, ConsumerDetails: consumer.Details,
		RunInteractively: consumer.RunInteractively, ConsumerCreatorSID: consumer.CreatorSID, BindingCreatorSID: binding.CreatorSID,
	}
}

func enrichWMISubscription(item *WMISubscription, services []ServiceInfo, tasks []ScheduledTaskInfo, opts Options) {
	action := strings.TrimSpace(firstNonEmpty(item.ExecutablePath, item.CommandLine))
	path := executablePathFromWMI(action)
	if path != "" {
		item.ExecutablePath = path
		md5, hashErr, signature := enrichExecutable(path, opts)
		item.ExecutableMD5 = md5
		item.ExecutableHashErr = hashErr
		item.ExecutableSignature = signature.Status
		item.ExecutableSigMsg = signature.Message
	}
	item.RelatedServices, item.RelatedTasks = correlateWMIAction(action, item.ScriptText, path, services, tasks)
	item.SystemManaged = isWindowsSCMSubscription(*item)
	item.RiskScore, item.RiskLevel, item.RiskReasons = assessWMISubscription(*item)
	item.Summary = summarizeWMISubscription(*item)
}

func assessWMISubscription(item WMISubscription) (int, string, []string) {
	if item.SystemManaged {
		return 0, "", nil
	}
	query := strings.ToLower(item.Query)
	action := strings.TrimSpace(strings.Join([]string{item.ExecutablePath, item.CommandLine, item.ScriptText}, " "))
	reasons := make([]string, 0, 10)
	score := 0
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}
	if strings.Contains(query, "win32_localtime") && wmiExactTimePattern.MatchString(item.Query) {
		add(35, "使用 Win32_LocalTime 精确时间触发")
	}
	if strings.Contains(query, "win32_processstarttrace") {
		add(15, "监听进程启动事件")
	}
	if wmiShortPathPattern.MatchString(action) {
		add(25, "消费者命令使用 8.3 短路径")
	}
	if writableFileLocationForHost(item.ExecutablePath) {
		add(25, "消费者文件位于用户可写或公共目录")
	}
	if item.ExecutablePath != "" {
		if _, err := os.Stat(item.ExecutablePath); err != nil {
			add(15, "消费者指向的文件当前不存在或不可访问")
		}
	}
	if item.ExecutableSignature == "无签名请注意!!!" {
		add(15, "消费者可执行文件无可信签名")
	} else if item.ExecutableSignature == "签名异常" {
		add(25, "消费者可执行文件签名异常")
	}
	if wmiCommandPattern.MatchString(action) {
		add(20, "消费者包含脚本解释器、下载或代理执行命令")
	}
	if item.ConsumerType == "ActiveScriptEventConsumer" && strings.TrimSpace(item.ScriptText) != "" {
		add(10, "消费者直接保存并执行脚本")
	}
	if item.RunInteractively {
		add(10, "消费者设置为交互运行")
	}
	if strings.Contains(item.Status, "孤立") || item.Status == "绑定引用缺失" {
		add(10, item.Status)
	}
	if missingWMICreatorSID(item) {
		add(5, "一个或多个 WMI 对象缺少 CreatorSID")
	}
	if creatorSIDMismatch(item) {
		add(20, "过滤器、消费者与绑定的 CreatorSID 不一致")
	}
	if vendorIdentityMismatch(item, action) {
		add(20, "对象名称呈现常见厂商身份，但路径或签名不能支持该身份")
	}
	if len(item.RelatedServices) == 0 && len(item.RelatedTasks) == 0 && score >= 20 && action != "" {
		add(10, "未发现与该命令对应的标准服务或计划任务")
	}
	level := ""
	if score >= 50 {
		level = "高"
	} else if score >= 25 {
		level = "中"
	} else if score > 0 {
		level = "低"
	}
	return score, level, uniqueHostStrings(reasons)
}

func missingWMICreatorSID(item WMISubscription) bool {
	switch item.Status {
	case "孤立过滤器":
		return item.FilterCreatorSID == ""
	case "孤立消费者":
		return item.ConsumerCreatorSID == ""
	case "已绑定":
		return item.FilterCreatorSID == "" || item.ConsumerCreatorSID == "" || item.BindingCreatorSID == ""
	case "绑定引用缺失":
		if item.BindingCreatorSID == "" {
			return true
		}
		return (item.FilterName != "" && item.FilterCreatorSID == "") || (item.ConsumerName != "" && item.ConsumerCreatorSID == "")
	default:
		return false
	}
}

func isWindowsSCMSubscription(item WMISubscription) bool {
	if !strings.EqualFold(item.Namespace, `root\subscription`) || item.Status != "已绑定" {
		return false
	}
	query := strings.Join(strings.Fields(strings.ToLower(item.Query)), " ")
	if !strings.EqualFold(item.FilterName, "SCM Event Log Filter") || query != "select * from msft_scmeventlogevent" {
		return false
	}
	if !strings.EqualFold(item.QueryLanguage, "WQL") || !strings.EqualFold(item.EventNamespace, `root\cimv2`) {
		return false
	}
	if !strings.EqualFold(item.ConsumerName, "SCM Event Log Consumer") || !strings.EqualFold(item.ConsumerType, "NTEventLogEventConsumer") {
		return false
	}
	if strings.TrimSpace(item.CommandLine+item.ExecutablePath+item.ScriptText) != "" || item.RunInteractively {
		return false
	}
	if !strings.Contains(strings.ToLower(item.ConsumerDetails), "sourcename=service control manager") {
		return false
	}
	if creatorSIDMismatch(item) || item.FilterCreatorSID == "" || item.ConsumerCreatorSID == "" || item.BindingCreatorSID == "" {
		return false
	}
	return item.FilterCreatorSID == "S-1-5-18" || item.FilterCreatorSID == "S-1-5-32-544"
}

func summarizeWMISubscription(item WMISubscription) string {
	if item.SystemManaged {
		return "Windows 内置 SCM 事件日志订阅，不执行外部命令"
	}
	if len(item.RiskReasons) > 0 {
		return strings.Join(item.RiskReasons, "；")
	}
	if item.Status == "已绑定" {
		return "订阅关系完整，当前未发现明显异常信号"
	}
	return item.Status
}

func creatorSIDMismatch(item WMISubscription) bool {
	sids := []string{item.FilterCreatorSID, item.ConsumerCreatorSID}
	if item.Status == "已绑定" {
		sids = append(sids, item.BindingCreatorSID)
	}
	var expected string
	for _, sid := range sids {
		if sid == "" {
			continue
		}
		if expected == "" {
			expected = sid
			continue
		}
		if !strings.EqualFold(expected, sid) {
			return true
		}
	}
	return false
}

func vendorIdentityMismatch(item WMISubscription, action string) bool {
	identity := strings.ToLower(item.FilterName + " " + item.ConsumerName)
	action = strings.ToLower(action)
	brands := map[string][]string{
		"realtek": {"realtek", "rtk"}, "microsoft": {"microsoft", "\\windows\\"},
		"intel": {"intel"}, "nvidia": {"nvidia"}, "google": {"google", "chrome"},
		"adobe": {"adobe"}, "vmware": {"vmware"}, "lenovo": {"lenovo"}, "dell": {"dell"}, "hp": {"hewlett", "\\hp\\"},
	}
	for brand, markers := range brands {
		if !strings.Contains(identity, brand) {
			continue
		}
		matched := false
		for _, marker := range markers {
			if strings.Contains(action, marker) {
				matched = true
				break
			}
		}
		return !matched || item.ExecutableSignature == "无签名请注意!!!" || item.ExecutableSignature == "签名异常"
	}
	return false
}

func correlateWMIAction(action, script, path string, services []ServiceInfo, tasks []ScheduledTaskInfo) ([]string, []string) {
	needles := uniqueHostStrings([]string{strings.ToLower(path), strings.ToLower(filepath.Base(path))})
	if len(needles) == 0 || needles[0] == "." {
		needles = commandBasenames(action + " " + script)
	}
	serviceNames := make([]string, 0)
	taskNames := make([]string, 0)
	for _, service := range services {
		text := strings.ToLower(strings.Join([]string{service.Path, service.Command, service.ServiceDLL}, " "))
		if containsAnyNonEmpty(text, needles) {
			serviceNames = append(serviceNames, service.Name)
		}
	}
	for _, task := range tasks {
		text := strings.ToLower(strings.Join([]string{task.Executable, task.Command, task.Arguments}, " "))
		if containsAnyNonEmpty(text, needles) {
			taskNames = append(taskNames, task.Path)
		}
	}
	return uniqueHostStrings(serviceNames), uniqueHostStrings(taskNames)
}

func executablePathFromWMI(command string) string {
	command = strings.TrimSpace(expandWindowsEnv(command))
	if match := quotedPathPattern.FindStringSubmatch(command); len(match) > 1 {
		return normalizeExecutablePath(match[1], true)
	}
	if match := plainPathPattern.FindStringSubmatch(command); len(match) > 1 {
		return normalizeExecutablePath(strings.TrimSpace(match[1]), true)
	}
	return executablePathFromCommand(command)
}

func commandBasenames(value string) []string {
	matches := regexp.MustCompile(`(?i)[^\\/\s"']+\.(?:exe|com|bat|cmd|ps1|vbs|js|hta)`).FindAllString(value, 20)
	for i := range matches {
		matches[i] = strings.ToLower(filepath.Base(matches[i]))
	}
	return uniqueHostStrings(matches)
}

func canonicalWMIReference(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.LastIndex(value, ":"); index >= 0 {
		value = value[index+1:]
	}
	value = strings.ReplaceAll(value, `\\`, `\`)
	return strings.ToLower(strings.TrimSpace(value))
}

func dedupeWMISubscriptions(items []WMISubscription) []WMISubscription {
	seen := make(map[string]struct{})
	out := make([]WMISubscription, 0, len(items))
	for _, item := range items {
		key := strings.ToLower(strings.Join([]string{item.Namespace, item.BindingPath, item.FilterPath, item.ConsumerPath, item.Status}, "|"))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func containsAnyNonEmpty(value string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && needle != "." && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func writableFileLocationForHost(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{`\users\`, `\appdata\`, `\temp\`, `\programdata\`, `\public\`, `\downloads\`, `\desktop\`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func limitedWMIText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[内容已截断]"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniqueHostStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
