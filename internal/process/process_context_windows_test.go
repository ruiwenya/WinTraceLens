//go:build windows

package process

import (
	"os"
	"testing"
)

func TestIntegrityLabel(t *testing.T) {
	cases := map[uint32]string{
		0x0000: "不受信任",
		0x1000: "低",
		0x2000: "中",
		0x3000: "高",
		0x4000: "系统",
		0x5000: "受保护",
	}
	for rid, want := range cases {
		if got := integrityLabel(rid); got != want {
			t.Fatalf("integrityLabel(%#x)=%q, want %q", rid, got, want)
		}
	}
}

func TestMachineLabel(t *testing.T) {
	if got := machineLabel(imageFileMachineAMD64); got != "x64" {
		t.Fatalf("machineLabel(amd64)=%q", got)
	}
	if got := machineLabel(imageFileMachineI386); got != "x86" {
		t.Fatalf("machineLabel(i386)=%q", got)
	}
}

func TestCurrentProcessContext(t *testing.T) {
	context := queryProcessContext(uint32(os.Getpid()))
	if context.Architecture == "" {
		t.Fatal("current process architecture is empty")
	}
	if context.UserSID == "" {
		t.Fatal("current process SID is empty")
	}
	if context.WorkingSetBytes == 0 {
		t.Fatal("current process working set is zero")
	}
	if context.CommandLine == "" {
		t.Fatal("current process command line is empty")
	}
}

func TestWMIProcessSnapshotContainsCurrentProcess(t *testing.T) {
	items, err := snapshotProcessesWMI()
	if err != nil {
		t.Skipf("WMI process snapshot unavailable: %v", err)
	}
	item, ok := items[uint32(os.Getpid())]
	if !ok {
		t.Fatal("WMI process snapshot does not contain current process")
	}
	if item.CommandLine == "" {
		t.Fatal("WMI current process command line is empty")
	}
}
