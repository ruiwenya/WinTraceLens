package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/evidencebundle"
)

// Dataset is a completed collection, not a new scan or a full forensic image.
type Dataset = evidencebundle.Dataset

// RecordResult keeps derived results which do not have a collector cache.
// Only explicitly approved evidence sources are allowed; AI session state and
// credentials must never enter an evidence package.
func (s *Store) RecordResult(source string, options, value any) error {
	switch source {
	case "process-modules", "findings", "behavior", "investigation", "registry-correlated", "yara":
	default:
		return fmt.Errorf("unsupported evidence result: %s", source)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	opts, err := json.Marshal(options)
	if err != nil {
		return err
	}
	entry := Dataset{Source: source, Options: opts, CollectedAt: time.Now(), Data: data}
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	if s.results == nil {
		s.results = make(map[string]Dataset)
	}
	s.results[source+"\n"+string(opts)] = entry
	return nil
}

// Keep a failed batch attempt alongside older successful evidence, so a refresh
// failure cannot silently turn old data into a claim of current coverage.
func (s *Store) RecordCollectionFailure(source string, failure error) {
	if _, err := evidencebundle.NormalizeSelection([]string{source}); err != nil {
		return
	}
	key := source + "\nbatch-failure"
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	if failure == nil {
		delete(s.results, key)
		return
	}
	if s.results == nil {
		s.results = make(map[string]Dataset)
	}
	data, _ := json.Marshal(map[string]any{"collectionStatus": "failed", "collectionErrors": []string{failure.Error()}})
	s.results[key] = Dataset{Source: source, Options: json.RawMessage(`{"batchFailure":true}`), CollectedAt: time.Now(), Data: data}
}

// ExportSnapshot also retains expired cache entries: expiration requests a new
// live view, but does not invalidate evidence already collected in this run.
// No collector is invoked, and in-flight scans do not hold the snapshot locks.
func (s *Store) ExportSnapshot() ([]Dataset, error) {
	var out []Dataset
	collectors := []func() ([]Dataset, error){
		func() ([]Dataset, error) { return cachedDatasets("processes", &s.processes) },
		func() ([]Dataset, error) { return cachedDatasets("connections", &s.connections) },
		func() ([]Dataset, error) { return cachedDatasets("host", &s.host) },
		func() ([]Dataset, error) { return cachedDatasets("file-traces", &s.fileTraces) },
		func() ([]Dataset, error) { return cachedDatasets("network-history", &s.history) },
		func() ([]Dataset, error) { return cachedDatasets("security-events", &s.security) },
		func() ([]Dataset, error) { return cachedDatasets("drivers", &s.drivers) },
		func() ([]Dataset, error) { return cachedDatasets("memory", &s.memory) },
		func() ([]Dataset, error) { return cachedDatasets("log-health", &s.logHealth) },
		func() ([]Dataset, error) { return cachedDatasets("registry", &s.registry) },
		func() ([]Dataset, error) { return cachedDatasets("native-files", &s.nativeFiles) },
	}
	for _, collect := range collectors {
		entries, err := collect()
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	s.resultMu.Lock()
	for _, entry := range s.results {
		entry.Data = append(json.RawMessage(nil), entry.Data...)
		entry.Options = append(json.RawMessage(nil), entry.Options...)
		out = append(out, entry)
	}
	s.resultMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return string(out[i].Options) < string(out[j].Options)
	})
	return out, nil
}

func cachedDatasets[T any](source string, c *cache[T]) ([]Dataset, error) {
	c.mu.Lock()
	entries := make(map[string]cacheEntry[T], len(c.values))
	for key, entry := range c.values {
		entries[key] = entry
	}
	c.mu.Unlock()
	var out []Dataset
	for key, entry := range entries {
		data, err := json.Marshal(entry.value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		opts := json.RawMessage(key)
		if !json.Valid(opts) {
			opts, _ = json.Marshal(key)
		}
		out = append(out, Dataset{Source: source, Options: opts, CollectedAt: entry.collectedAt, Data: data})
	}
	return out, nil
}
