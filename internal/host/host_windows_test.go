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
