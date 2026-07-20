//go:build windows

package filetrace

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseUSNRecordV2(t *testing.T) {
	name := utf16.Encode([]rune("payload.exe"))
	recordLength := 60 + len(name)*2
	data := make([]byte, recordLength)
	binary.LittleEndian.PutUint32(data[0:4], uint32(recordLength))
	binary.LittleEndian.PutUint16(data[4:6], 2)
	binary.LittleEndian.PutUint64(data[8:16], 0x1234)
	binary.LittleEndian.PutUint64(data[16:24], 0x5678)
	binary.LittleEndian.PutUint64(data[24:32], 42)
	binary.LittleEndian.PutUint64(data[32:40], 133960000000000000)
	binary.LittleEndian.PutUint32(data[40:44], 0x00000100)
	binary.LittleEndian.PutUint16(data[56:58], uint16(len(name)*2))
	binary.LittleEndian.PutUint16(data[58:60], 60)
	for i, value := range name {
		binary.LittleEndian.PutUint16(data[60+i*2:], value)
	}

	item, ok := parseUSNRecord("C:", data)
	if !ok {
		t.Fatal("parseUSNRecord rejected a valid V2 record")
	}
	if item.Name != "payload.exe" || item.Source != "USN Journal" || item.Modified == "" {
		t.Fatalf("unexpected USN record: %+v", item)
	}
}

func TestUSNSuspicionFlagsDeletedExecutable(t *testing.T) {
	level, reason := usnSuspicion("agent.exe", 0x00000200)
	if level != "中" || reason == "" {
		t.Fatalf("level=%q reason=%q", level, reason)
	}
}
