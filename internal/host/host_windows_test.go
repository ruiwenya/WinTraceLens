//go:build windows

package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutablePathFromCommandSkipsNonExecutableTaskActions(t *testing.T) {
	for _, command := range []string{
		"COM handler",
		"COM Handler",
		"N/A",
		"Multiple actions",
		"Custom handler",
	} {
		if got := executablePathFromCommand(command); got != "" {
			t.Fatalf("executablePathFromCommand(%q) = %q, want empty", command, got)
		}
	}
}

func TestExecutablePathFromCommandDoesNotAbsolutizeUnknownBareCommand(t *testing.T) {
	command := "DefinitelyNotARealExecutableNameForWinTraceLens --flag"
	if got := executablePathFromCommand(command); got != "" {
		t.Fatalf("executablePathFromCommand(%q) = %q, want empty", command, got)
	}
}

func TestExecutablePathFromCommandKeepsMissingAbsoluteExecutable(t *testing.T) {
	missing := filepath.Join(os.TempDir(), "process lens missing app", "missing.exe")
	got := executablePathFromCommand(missing + " --flag")
	if got != filepath.Clean(missing) {
		t.Fatalf("missing absolute executable = %q, want %q", got, filepath.Clean(missing))
	}
}

func TestExecutablePathFromCommandResolvesBareExecutableBeforeArgumentScripts(t *testing.T) {
	got := executablePathFromCommand(`cmd /c C:\Temp\example.ps1`)
	if got == "" {
		t.Fatal("cmd did not resolve from PATH")
	}
	if strings.ToLower(filepath.Base(got)) != "cmd.exe" {
		t.Fatalf("resolved executable = %q, want cmd.exe", got)
	}
}

func TestExecutablePathFromCommandDoesNotStopAtExtensionInDirectory(t *testing.T) {
	command := `C:\Temp\vendor.com\runner.cmd --flag`
	want := `C:\Temp\vendor.com\runner.cmd`
	if got := executablePathFromCommand(command); got != want {
		t.Fatalf("executablePathFromCommand(%q) = %q, want %q", command, got, want)
	}
}

func TestMergeServiceSourcesDetectsRegistryOnlyService(t *testing.T) {
	items := mergeServiceSources(nil, nil, []registryServiceInfo{{
		Name: "Abc123Def456", ImagePath: `C:\Users\Public\payload.exe`, RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\Abc123Def456`, Start: 2,
	}}, Options{})
	if len(items) != 1 {
		t.Fatalf("unexpected service count: %d", len(items))
	}
	if items[0].SourceStatus != "仅注册表" || items[0].RiskLevel != "高" {
		t.Fatalf("registry-only service was not raised: %+v", items[0])
	}
}

func TestMergeServiceSourcesDetectsPathMismatch(t *testing.T) {
	wmi := []psService{{Name: "Example", Command: `C:\Windows\System32\svchost.exe -k one`}}
	scm := []scmServiceInfo{{Name: "Example", Command: `C:\Windows\System32\svchost.exe -k two`}}
	reg := []registryServiceInfo{{Name: "Example", ImagePath: `%SystemRoot%\System32\svchost.exe -k one`, RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\Example`}}
	items := mergeServiceSources(wmi, scm, reg, Options{})
	if len(items) != 1 || items[0].SourceStatus != "ImagePath不一致" {
		t.Fatalf("path mismatch not detected: %+v", items)
	}
}

func TestAssessWMISubscriptionPromotesCombinedSignals(t *testing.T) {
	item := WMISubscription{
		Status:              "已绑定",
		FilterName:          "RealtekAudioUpdate",
		ConsumerName:        "RealtekAudioConsumer",
		ConsumerType:        "CommandLineEventConsumer",
		Query:               "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 19 AND TargetInstance.Minute = 50",
		CommandLine:         "C:\\Progra~1\\UnknownVendor\\RtkNGUI64.exe",
		ExecutablePath:      "C:\\Progra~1\\UnknownVendor\\RtkNGUI64.exe",
		ExecutableSignature: "无签名请注意!!!",
		FilterCreatorSID:    "S-1-5-32-544",
		ConsumerCreatorSID:  "S-1-5-32-544",
		BindingCreatorSID:   "S-1-5-32-544",
	}
	score, level, reasons := assessWMISubscription(item)
	if level != "高" || score < 50 {
		t.Fatalf("combined WMI persistence signals were not promoted: level=%q score=%d reasons=%v", level, score, reasons)
	}
}

func TestAssessWMISubscriptionDoesNotFlagPlainBoundSubscription(t *testing.T) {
	item := WMISubscription{
		Status:             "已绑定",
		Query:              "SELECT * FROM RegistryKeyChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE'",
		FilterCreatorSID:   "S-1-5-32-544",
		ConsumerCreatorSID: "S-1-5-32-544",
		BindingCreatorSID:  "S-1-5-32-544",
	}
	score, level, reasons := assessWMISubscription(item)
	if score != 0 || level != "" || len(reasons) != 0 {
		t.Fatalf("plain bound subscription was unexpectedly flagged: level=%q score=%d reasons=%v", level, score, reasons)
	}
}

func TestMergeWMISubscriptionObjectsKeepsWindowsSCMSubscriptionTogether(t *testing.T) {
	const creatorSID = "S-1-5-32-544"
	items := mergeWMISubscriptionObjects(
		`root\subscription`,
		[]wmiFilter{{
			Path: `__EventFilter.Name="SCM Event Log Filter"`, Name: "SCM Event Log Filter",
			Query: "select * from MSFT_SCMEventLogEvent", QueryLanguage: "WQL", EventNamespace: `root\cimv2`, CreatorSID: creatorSID,
		}},
		[]wmiConsumer{{
			Path: `NTEventLogEventConsumer.Name="SCM Event Log Consumer"`, Name: "SCM Event Log Consumer",
			Class: "NTEventLogEventConsumer", Details: "SourceName=Service Control Manager；EventID=0；EventType=1", CreatorSID: creatorSID,
		}},
		[]wmiBinding{{
			Path:   `__FilterToConsumerBinding.Consumer="NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\"",Filter="__EventFilter.Name=\"SCM Event Log Filter\""`,
			Filter: `__EventFilter.Name="SCM Event Log Filter"`, Consumer: `NTEventLogEventConsumer.Name="SCM Event Log Consumer"`, CreatorSID: creatorSID,
		}},
		nil, nil, Options{},
	)
	if len(items) != 1 {
		t.Fatalf("SCM subscription split into %d rows: %+v", len(items), items)
	}
	item := items[0]
	if item.Status != "已绑定" || !item.SystemManaged || item.RiskScore != 0 || item.RiskLevel != "" {
		t.Fatalf("SCM subscription not recognized as a bound system item: %+v", item)
	}
	if !strings.Contains(item.Summary, "Windows 内置 SCM") {
		t.Fatalf("unexpected SCM summary: %q", item.Summary)
	}
}

func TestWindowsSCMSubscriptionRequiresExactSafeStructure(t *testing.T) {
	item := WMISubscription{
		Namespace: `root\subscription`, Status: "已绑定",
		FilterName: "SCM Event Log Filter", Query: "select * from MSFT_SCMEventLogEvent", QueryLanguage: "WQL", EventNamespace: `root\cimv2`,
		ConsumerName: "SCM Event Log Consumer", ConsumerType: "CommandLineEventConsumer", CommandLine: `cmd.exe /c payload.cmd`,
		ConsumerDetails: "SourceName=Service Control Manager", FilterCreatorSID: "S-1-5-32-544", ConsumerCreatorSID: "S-1-5-32-544", BindingCreatorSID: "S-1-5-32-544",
	}
	if isWindowsSCMSubscription(item) {
		t.Fatal("same-name command consumer was incorrectly trusted")
	}
}

func TestMissingWMICreatorSIDOnlyChecksObjectsPresentInOrphanRows(t *testing.T) {
	if missingWMICreatorSID(WMISubscription{Status: "孤立过滤器", FilterCreatorSID: "S-1-5-18"}) {
		t.Fatal("orphan filter incorrectly required a consumer SID")
	}
	if missingWMICreatorSID(WMISubscription{Status: "孤立消费者", ConsumerCreatorSID: "S-1-5-18"}) {
		t.Fatal("orphan consumer incorrectly required a filter SID")
	}
}

func TestMergeWMISubscriptionObjectsDoesNotBindEmptyReferences(t *testing.T) {
	items := mergeWMISubscriptionObjects(
		`root\subscription`,
		[]wmiFilter{{Name: "FilterWithoutPath"}},
		[]wmiConsumer{{Name: "ConsumerWithoutPath"}},
		[]wmiBinding{{}},
		nil, nil, Options{},
	)
	if len(items) != 3 || items[0].Status != "绑定引用缺失" {
		t.Fatalf("empty WMI references were incorrectly joined: %+v", items)
	}
}
