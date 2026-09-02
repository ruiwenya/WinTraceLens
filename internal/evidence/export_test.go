package evidence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestExportPreservesExpiredSnapshotsAndOptions(t *testing.T) {
	s := NewStore()
	at := time.Now().Add(-time.Hour).UTC()
	s.processes.values = map[string]cacheEntry[[]process.Info]{
		`{"SkipHashes":true}`:  {value: []process.Info{{PID: 41, Name: "old.exe"}}, expiresAt: at, collectedAt: at},
		`{"SkipHashes":false}`: {value: []process.Info{{PID: 42, Name: "完整.exe", MD5: "abc"}}, expiresAt: at, collectedAt: at},
	}
	datasets, err := s.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(datasets) != 2 {
		t.Fatalf("got %d datasets", len(datasets))
	}
	for _, d := range datasets {
		if d.Source != "processes" || !d.CollectedAt.Equal(at) || !json.Valid(d.Options) {
			t.Fatalf("metadata lost: %+v", d)
		}
	}
	datasets[0].Data[0] = '!'
	again, err := s.ExportSnapshot()
	if err != nil || !json.Valid(again[0].Data) {
		t.Fatal("export mutated the retained snapshot", err)
	}
}

func TestFailedBatchDoesNotRemoveSuccessfulEvidence(t *testing.T) {
	s := NewStore()
	if err := s.RecordResult("findings", nil, map[string]any{"items": []string{"saved"}}); err != nil {
		t.Fatal(err)
	}
	s.RecordCollectionFailure("findings", errors.New("refresh failed"))
	datasets, err := s.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(datasets) != 2 {
		t.Fatal("failure replaced earlier evidence")
	}
	s.RecordCollectionFailure("findings", nil)
	datasets, err = s.ExportSnapshot()
	if err != nil || len(datasets) != 1 {
		t.Fatal("failure not cleared after retry", err)
	}
}

func TestExportDoesNotWaitForInFlightCollector(t *testing.T) {
	s := NewStore()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.processes.get("{}", false, time.Minute, func() ([]process.Info, error) {
			close(started)
			<-release
			return []process.Info{{PID: 5}}, nil
		}, cloneProcesses)
	}()
	<-started
	defer func() { close(release); <-done }()
	exported := make(chan error, 1)
	go func() { _, err := s.ExportSnapshot(); exported <- err }()
	select {
	case err := <-exported:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("export blocked on collection")
	}
}

func TestRecordResultRejectsSecretsAndCopiesResults(t *testing.T) {
	s := NewStore()
	if err := s.RecordResult("ai-session", nil, map[string]string{"apiKey": "secret"}); err == nil {
		t.Fatal("AI session allowed")
	}
	value := map[string]any{"items": []string{"original"}}
	if err := s.RecordResult("findings", nil, value); err != nil {
		t.Fatal(err)
	}
	value["items"] = []string{"changed"}
	data, err := s.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || !strings.Contains(string(data[0].Data), "original") {
		t.Fatal("retained result mutated")
	}
	if err := s.RecordResult("findings", nil, map[string]any{"items": []string{"new"}}); err != nil {
		t.Fatal(err)
	}
	data, _ = s.ExportSnapshot()
	if len(data) != 1 || !strings.Contains(string(data[0].Data), "new") {
		t.Fatal("same result scope was not replaced")
	}
}
