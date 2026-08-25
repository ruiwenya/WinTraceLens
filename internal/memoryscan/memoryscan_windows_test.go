//go:build windows

package memoryscan

import (
	"encoding/binary"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestEmbeddedPEAndHardSignalPreserveRisk(t *testing.T) {
	data := make([]byte, 1024)
	copy(data, []byte("MZ"))
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], []byte{'P', 'E', 0, 0})
	if !containsEmbeddedPE(data) {
		t.Fatal("expected embedded PE")
	}
	record := Record{Level: "高", Category: "内存区域", HardSignals: []string{"区域中存在有效 PE 结构"}}
	applyProcessContext(process.Info{Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Signature: "已签名"}, &record)
	if record.Level != "高" {
		t.Fatalf("hard signal was incorrectly downgraded: %+v", record)
	}
}

func TestExpectedJITWithoutHardSignalIsDowngraded(t *testing.T) {
	record := Record{Level: "高", Category: "内存区域"}
	applyProcessContext(process.Info{Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Signature: "已签名"}, &record)
	if record.Level != "低" {
		t.Fatalf("expected normal JIT context downgrade: %+v", record)
	}
}
