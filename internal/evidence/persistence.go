package evidence

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/host"
)

func (s *Store) latestPersistence() (host.Snapshot, time.Time) {
	s.host.mu.Lock()
	defer s.host.mu.Unlock()
	var value host.Snapshot
	var at time.Time
	for _, entry := range s.host.values {
		if entry.collectedAt.After(at) {
			value = entry.value
			at = entry.collectedAt
		}
	}
	return cloneHost(value), at
}

func appendPersistenceTraces(snapshot filetrace.Snapshot, machine host.Snapshot) filetrace.Snapshot {
	for _, entry := range machine.TargetedFiles {
		t := entry.Target
		var references []string
		for _, record := range snapshot.Records {
			if strings.EqualFold(record.Path, t.Path) || (record.Source == "Prefetch" && strings.HasPrefix(strings.ToUpper(record.Name), strings.ToUpper(filepath.Base(t.Path))+"-")) {
				references = append(references, record.Source+": "+record.Path)
			}
		}
		snapshot.Records = append(snapshot.Records, filetrace.Record{Category: "持久化载荷", Source: "持久化定向补采", Name: filepath.Base(t.Path), Path: t.Path, Directory: filepath.Dir(t.Path), Extension: filepath.Ext(t.Path), Size: t.Size, Created: t.Created, Modified: t.Modified, SHA256: t.SHA256, Signature: t.Signature, SignatureMsg: t.SignatureMsg, Suspicion: "中", Reason: strings.Join(entry.References, "；") + "；目标状态：" + t.FileStatus, Details: fmt.Sprintf("父目录=%s；ACL=%s；ADS=%s；已有痕迹关联=%s；补采限制=%s；错误=%s %s", entry.DirectoryStatus, entry.DirectoryACL, strings.Join(entry.Streams, "；"), strings.Join(references, "；"), strings.Join(entry.Warnings, "；"), t.CheckError, t.HashError)})
	}
	if snapshot.Coverage != nil && len(machine.TargetedFiles) > 0 {
		snapshot.Coverage.Returned = len(snapshot.Records)
		snapshot.Coverage.Sources = append(snapshot.Coverage.Sources, "持久化定向补采")
	}
	return snapshot
}

func (s *Store) persistenceDatasets() ([]Dataset, error) {
	machine, at := s.latestPersistence()
	if len(machine.TargetedFiles) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(appendPersistenceTraces(filetrace.Snapshot{}, machine))
	if err != nil {
		return nil, err
	}
	return []Dataset{{Source: "persistence-files", Options: json.RawMessage(`{"derivedFrom":"host","bounded":true}`), CollectedAt: at, Data: data}}, nil
}
