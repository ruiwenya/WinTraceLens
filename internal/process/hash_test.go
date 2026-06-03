package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileMD5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("process lens"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, errText := fileMD5(path, 1024)
	if errText != "" {
		t.Fatalf("unexpected hash error: %s", errText)
	}

	const want = "8ddf8431c12916ec6cccd7cda52d12f4"
	if got != want {
		t.Fatalf("md5 mismatch: got %s want %s", got, want)
	}
}
