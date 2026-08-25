package registryanomaly

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestAnalyzeLargeEncryptedBinaryInUserSoftware(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte((i*73 + 19) % 251)
	}
	record, ok := analyzeValue(valueEvidence{
		hive: "HKU", sid: "S-1-5-21-test", keyPath: `S-1-5-21-test\Software\VendorCache`,
		valueName: "PayloadBlob", valueType: 3, dataLength: len(data), data: data,
		lastWrite: time.Now(), nonTraditional: true,
	})
	if !ok {
		t.Fatal("expected anomalous binary value")
	}
	if record.Score < 5 || record.Level == "低" {
		t.Fatalf("unexpected score/level: %+v", record)
	}
	if record.SHA256 == "" || record.Entropy == 0 {
		t.Fatalf("missing evidence fields: %+v", record)
	}
}

func TestAnalyzeEmbeddedPE(t *testing.T) {
	data := make([]byte, 1024)
	copy(data, []byte("MZ"))
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], []byte{'P', 'E', 0, 0})
	record, ok := analyzeValue(valueEvidence{hive: "HKCU", keyPath: `Software\Example`, valueName: "blob", valueType: 3, dataLength: len(data), data: data})
	if !ok || record.Score < 5 {
		t.Fatalf("embedded PE was not scored strongly: %+v", record)
	}
}

func TestReferenceRoundTrip(t *testing.T) {
	want := ExportReference{Hive: "HKU", KeyPath: `S-1-5-21\Software\VendorCache`, ValueName: "PayloadBlob"}
	got, err := DecodeReference(encodeReference(want))
	if err != nil || got != want {
		t.Fatalf("round trip failed: got=%+v err=%v", got, err)
	}
}
