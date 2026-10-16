package evidence

import (
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/host"
)

func TestPersistenceTraceSurvivesOrdinaryFileQuota(t *testing.T) {
	path := `C:\CustomRoot\agent.exe`
	traces := filetrace.Snapshot{Records: []filetrace.Record{{Name: "unrelated.exe", Path: `C:\Tests\unrelated.exe`}}}
	machine := host.Snapshot{TargetedFiles: []host.TargetedFile{{Target: commandchain.Target{Path: path, FileStatus: "文件不存在"}, References: []string{"服务：Example"}}}}
	result := appendPersistenceTraces(traces, machine)
	if len(result.Records) != 2 || result.Records[1].Path != path || !strings.Contains(result.Records[1].Reason, "文件不存在") {
		t.Fatalf("target displaced by ordinary quota: %+v", result)
	}
}

func TestCachedHostExecutionChainsAreIsolated(t *testing.T) {
	value := host.Snapshot{Services: []host.ServiceInfo{{ExecutionChain: &commandchain.Chain{Payloads: []commandchain.Target{{Path: "original"}}, Warnings: []string{"original"}}}}, TargetedFiles: []host.TargetedFile{{References: []string{"original"}}}}
	copy := cloneHost(value)
	copy.Services[0].ExecutionChain.Payloads[0].Path = "changed"
	copy.Services[0].ExecutionChain.Warnings[0] = "changed"
	copy.TargetedFiles[0].References[0] = "changed"
	if value.Services[0].ExecutionChain.Payloads[0].Path != "original" || value.Services[0].ExecutionChain.Warnings[0] != "original" || value.TargetedFiles[0].References[0] != "original" {
		t.Fatal("caller mutated cached evidence")
	}
}
