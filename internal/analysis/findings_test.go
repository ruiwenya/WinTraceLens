package analysis

import (
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
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
