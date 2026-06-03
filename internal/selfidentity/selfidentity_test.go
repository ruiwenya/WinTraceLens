package selfidentity

import (
	"os"
	"testing"
)

func TestIsScannerProcessName(t *testing.T) {
	for _, name := range []string{"WinTraceLens.exe", "wintracelens-cli"} {
		if !IsScannerProcessName(name) {
			t.Fatalf("IsScannerProcessName(%q) = false, want true", name)
		}
	}
	if IsScannerProcessName("notepad.exe") {
		t.Fatalf("IsScannerProcessName(notepad.exe) = true, want false")
	}
}

func TestIsSelfProcessRequiresCurrentPID(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	pid := uint32(os.Getpid())
	if !IsSelfProcess(pid, exe) {
		t.Fatalf("IsSelfProcess(current pid, executable path) = false, want true")
	}
	if IsSelfProcess(pid+1, exe) {
		t.Fatalf("IsSelfProcess(other pid, executable path) = true, want false")
	}
}
