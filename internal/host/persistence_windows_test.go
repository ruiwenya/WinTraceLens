//go:build windows

package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
)

func TestSystemLauncherDoesNotMaskMissingPayload(t *testing.T) {
	command := `cmd /c cd /d "C:\CustomRoot\alpha\beta\" && start "" "C:\CustomRoot\alpha\beta\agent.exe"`
	chain := commandchain.Parse(command, commandchain.Options{Resolve: resolvePersistencePath, Expand: expandWindowsEnv})
	if len(chain.Payloads) != 1 {
		t.Fatalf("payload not extracted: %+v", chain)
	}
	chain.Payloads[0].FileStatus = "文件不存在"
	item := ServiceInfo{Name: "AbcDef123_XY", State: "Stopped", StartMode: "Automatic", Account: "LocalSystem", Path: chain.Launcher.Path, FileStatus: "存在", Signature: "系统文件", ExecutionChain: &chain}
	applyServiceRisk(&item, true, true, true)
	if item.RiskLevel != "高" || item.RiskScore < 8 {
		t.Fatalf("system launcher masked risk: %+v", item)
	}
	stoppedScore := item.RiskScore
	item.State = "Running"
	applyServiceRisk(&item, true, true, true)
	if item.RiskScore != stoppedScore {
		t.Fatal("risk changed with SCM runtime state")
	}
}

func TestNormalSignedServiceAndMissingFileStatus(t *testing.T) {
	item := ServiceInfo{Name: "RegularService", State: "Stopped", StartMode: "Automatic", Account: "LocalSystem", Path: `C:\Program Files\Vendor\service.exe`, FileStatus: "存在", Signature: "已签名"}
	applyServiceRisk(&item, true, true, true)
	if item.RiskScore != 0 {
		t.Fatalf("ordinary service gained command risk: %+v", item)
	}
	path := filepath.Join(t.TempDir(), "不存在.exe")
	target := inspectPersistenceTarget(commandchain.Target{Kind: "file", Path: path}, 1024, true)
	if target.FileStatus != "文件不存在" || target.SHA256 != "" {
		t.Fatalf("missing target: %+v", target)
	}
	if got := resolvePersistencePath(`agent.exe`, ""); got != "" {
		t.Fatalf("relative path used collector CWD: %q", got)
	}
	if got := resolvePersistencePath(`\\untrusted.example\share\a.exe`, ""); got != "" {
		t.Fatal("UNC target permitted")
	}
}

func TestUserEnvironmentIsNotBorrowedForUnknownPersistenceAccount(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\Collector\AppData\Roaming`)
	if got := expandPersistenceEnv(`%APPDATA%\agent.exe`); got != `%APPDATA%\agent.exe` {
		t.Fatalf("collector user context leaked into target path: %q", got)
	}
	if got := resolvePersistencePath(`%APPDATA%\agent.exe`, ""); got != "" {
		t.Fatalf("unknown user target resolved: %q", got)
	}
}

func TestTargetedFileMetadataUsesIndependentHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-data.bin")
	if err := os.WriteFile(path, []byte("read-only test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	target := inspectPersistenceTarget(commandchain.Target{Kind: "file", Path: path}, 1024, true)
	if target.FileStatus != "存在" || len(target.SHA256) != 64 || len(target.MD5) != 32 || target.Modified == "" {
		t.Fatalf("metadata unavailable: %+v", target)
	}
	if !strings.EqualFold(target.Path, path) {
		t.Fatal("target identity changed")
	}
}
