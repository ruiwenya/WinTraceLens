package analysis

import (
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
)

func TestBuildFindingsRaisesUnsignedNetworkProcess(t *testing.T) {
	findings := BuildFindings([]process.Info{{
		PID:             1234,
		Name:            "sample.exe",
		Path:            `C:\Users\Public\sample.exe`,
		MD5:             "00112233445566778899aabbccddeeff",
		Signature:       signatureUnsigned,
		ConnectionCount: 2,
	}}, host.Snapshot{})

	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	if findings[0].Level != levelHigh {
		t.Fatalf("level = %q, want %q", findings[0].Level, levelHigh)
	}
	if findings[0].Source != "进程" {
		t.Fatalf("source = %q, want process", findings[0].Source)
	}
}

func TestRegistryFindingsPromotesOnlyMediumAndHigh(t *testing.T) {
	findings := RegistryFindings(registryanomaly.Snapshot{Records: []registryanomaly.Record{
		{Level: "低", Hive: "HKEY_USERS", KeyPath: `S-1-5-21\Software\Vendor`, ValueName: "Cache"},
		{Level: "中", Hive: "HKEY_USERS", KeyPath: `S-1-5-21\Software\VendorCache`, ValueName: "PayloadBlob", ValueType: "REG_BINARY", DataLength: 4096, Entropy: 7.8, SHA256: "abc", Reasons: []string{"大体积高熵二进制数据"}},
	}})
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	if findings[0].Source != "注册表异常" || findings[0].Level != "中" {
		t.Fatalf("unexpected registry finding: %+v", findings[0])
	}
}

func TestBuildFindingsSkipsComHandlerTaskWithoutExecutable(t *testing.T) {
	findings := BuildFindings(nil, host.Snapshot{
		ScheduledTasks: []host.ScheduledTaskInfo{{
			Name:    "COM task",
			Command: "COM handler",
		}},
	})

	if len(findings) != 0 {
		t.Fatalf("finding count = %d, want 0", len(findings))
	}
}

func TestBuildFindingsFlagsImageHijack(t *testing.T) {
	findings := BuildFindings(nil, host.Snapshot{
		ImageHijacks: []host.ImageHijackInfo{{
			Image:     "notepad.exe",
			Debugger:  `C:\Temp\debugger.exe`,
			Path:      `C:\Temp\debugger.exe`,
			Signature: signatureUnsigned,
		}},
	})

	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	if findings[0].Level != levelHigh || findings[0].Source != "镜像劫持" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestBuildFindingsPromotesOnlyNotableWMISubscriptions(t *testing.T) {
	findings := BuildFindings(nil, host.Snapshot{
		WMISubscriptions: []host.WMISubscription{
			{FilterName: "RoutineFilter", ConsumerName: "RoutineConsumer", RiskLevel: "低", RiskScore: 10},
			{
				FilterName: "TimedFilter", ConsumerName: "CommandConsumer", RiskLevel: "高", RiskScore: 75,
				RiskReasons: []string{"使用 Win32_LocalTime 精确时间触发", "消费者命令使用 8.3 短路径"},
				CommandLine: "C:\\Progra~1\\Vendor\\agent.exe", ExecutablePath: "C:\\Progra~1\\Vendor\\agent.exe",
			},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	if findings[0].Source != "WMI 永久事件订阅" || findings[0].Level != "高" {
		t.Fatalf("unexpected WMI finding: %+v", findings[0])
	}
}
