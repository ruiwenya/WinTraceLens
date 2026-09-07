package evidence

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/driveranalysis"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/loghealth"
	"github.com/ruiwenya/WinTraceLens/internal/memoryscan"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

const (
	processTTL    = 10 * time.Second
	connectionTTL = 5 * time.Second
	hostTTL       = 2 * time.Minute
	fileTraceTTL  = 2 * time.Minute
	historyTTL    = 2 * time.Minute
	securityTTL   = 2 * time.Minute
	driverTTL     = 2 * time.Minute
	memoryTTL     = 30 * time.Second
	logHealthTTL  = time.Minute
	registryTTL   = 2 * time.Minute
	nativeFileTTL = 2 * time.Minute
)

type cacheEntry[T any] struct {
	value       T
	expiresAt   time.Time
	collectedAt time.Time
}

type cache[T any] struct {
	mu        sync.Mutex
	collectMu sync.Mutex
	values    map[string]cacheEntry[T]
}

func (c *cache[T]) get(key string, force bool, ttl time.Duration, collect func() (T, error), clone func(T) T) (T, error) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()
	c.mu.Lock()
	if c.values == nil {
		c.values = make(map[string]cacheEntry[T])
	}
	if !force {
		if entry, ok := c.values[key]; ok && time.Now().Before(entry.expiresAt) {
			c.mu.Unlock()
			return clone(entry.value), nil
		}
	}
	c.mu.Unlock()
	value, err := collect()
	if err != nil {
		var zero T
		return zero, err
	}
	now := time.Now()
	c.mu.Lock()
	c.values[key] = cacheEntry[T]{value: clone(value), expiresAt: now.Add(ttl), collectedAt: now}
	c.mu.Unlock()
	return clone(value), nil
}

// Store is the shared collection boundary for HTTP pages, exports, case analysis,
// behavior analysis and AI evidence. Cache keys include every collector option.
type Store struct {
	resultMu    sync.Mutex
	results     map[string]Dataset
	processes   cache[[]process.Info]
	connections cache[[]process.ConnectionInfo]
	host        cache[host.Snapshot]
	fileTraces  cache[filetrace.Snapshot]
	history     cache[history.Snapshot]
	security    cache[securitylog.Snapshot]
	drivers     cache[driveranalysis.Snapshot]
	memory      cache[memoryscan.Snapshot]
	logHealth   cache[loghealth.Snapshot]
	registry    cache[registryanomaly.Snapshot]
	nativeFiles cache[filetrace.Snapshot]
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Processes(opts process.Options, force bool) ([]process.Info, error) {
	return s.processes.get(cacheKey(opts), force, processTTL, func() ([]process.Info, error) {
		return process.Collect(opts)
	}, cloneProcesses)
}

func (s *Store) Connections(force bool) ([]process.ConnectionInfo, error) {
	return s.connections.get("all", force, connectionTTL, process.CollectConnections, cloneConnections)
}

func (s *Store) Host(opts host.Options, force bool) (host.Snapshot, error) {
	return s.host.get(cacheKey(opts), force, hostTTL, func() (host.Snapshot, error) {
		return host.Collect(opts)
	}, cloneHost)
}

func (s *Store) FileTraces(opts filetrace.Options, force bool) (filetrace.Snapshot, error) {
	return s.fileTraces.get(cacheKey(opts), force, fileTraceTTL, func() (filetrace.Snapshot, error) {
		return filetrace.Collect(opts)
	}, cloneFileTrace)
}

func (s *Store) History(opts history.Options, force bool) (history.Snapshot, error) {
	return s.history.get(cacheKey(opts), force, historyTTL, func() (history.Snapshot, error) {
		return history.Collect(opts)
	}, cloneHistory)
}

func (s *Store) Security(opts securitylog.Options, force bool) (securitylog.Snapshot, error) {
	return s.security.get(cacheKey(opts), force, securityTTL, func() (securitylog.Snapshot, error) {
		return securitylog.Collect(opts)
	}, cloneSecurity)
}

func (s *Store) Drivers(opts driveranalysis.Options, force bool) (driveranalysis.Snapshot, error) {
	return s.drivers.get(cacheKey(opts), force, driverTTL, func() (driveranalysis.Snapshot, error) {
		return driveranalysis.Collect(opts)
	}, cloneDrivers)
}

func (s *Store) Memory(opts memoryscan.Options, force bool) (memoryscan.Snapshot, error) {
	return s.memory.get(cacheKey(opts), force, memoryTTL, func() (memoryscan.Snapshot, error) {
		items, err := s.Processes(process.Options{SkipHashes: true}, force)
		if err != nil {
			return memoryscan.Snapshot{}, err
		}
		return memoryscan.CollectForProcesses(items, opts), nil
	}, cloneMemory)
}

func (s *Store) LogHealth(force bool) (loghealth.Snapshot, error) {
	return s.logHealth.get("all", force, logHealthTTL, loghealth.Collect, cloneLogHealth)
}

func (s *Store) Registry(opts registryanomaly.Options, force bool) (registryanomaly.Snapshot, error) {
	return s.registry.get(cacheKey(opts), force, registryTTL, func() (registryanomaly.Snapshot, error) {
		return registryanomaly.Collect(opts)
	}, cloneRegistry)
}

func (s *Store) NativeFiles(opts filetrace.Options, force bool) (filetrace.Snapshot, error) {
	return s.nativeFiles.get(cacheKey(opts), force, nativeFileTTL, func() (filetrace.Snapshot, error) {
		return filetrace.CollectNative(opts)
	}, cloneFileTrace)
}

func cacheKey(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(encoded)
}

func cloneProcesses(value []process.Info) []process.Info {
	return append([]process.Info(nil), value...)
}

func cloneConnections(value []process.ConnectionInfo) []process.ConnectionInfo {
	return append([]process.ConnectionInfo(nil), value...)
}

func cloneHost(value host.Snapshot) host.Snapshot {
	value.Services = append([]host.ServiceInfo(nil), value.Services...)
	for i := range value.Services {
		value.Services[i].RiskReasons = append([]string(nil), value.Services[i].RiskReasons...)
	}
	value.ScheduledTasks = append([]host.ScheduledTaskInfo(nil), value.ScheduledTasks...)
	value.StartupItems = append([]host.StartupItem(nil), value.StartupItems...)
	value.Users = append([]host.UserInfo(nil), value.Users...)
	value.ImageHijacks = append([]host.ImageHijackInfo(nil), value.ImageHijacks...)
	value.WMISubscriptions = append([]host.WMISubscription(nil), value.WMISubscriptions...)
	for i := range value.WMISubscriptions {
		value.WMISubscriptions[i].RiskReasons = append([]string(nil), value.WMISubscriptions[i].RiskReasons...)
		value.WMISubscriptions[i].RelatedServices = append([]string(nil), value.WMISubscriptions[i].RelatedServices...)
		value.WMISubscriptions[i].RelatedTasks = append([]string(nil), value.WMISubscriptions[i].RelatedTasks...)
	}
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneFileTrace(value filetrace.Snapshot) filetrace.Snapshot {
	value.Records = append([]filetrace.Record(nil), value.Records...)
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneHistory(value history.Snapshot) history.Snapshot {
	value.Records = append([]history.Record(nil), value.Records...)
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneSecurity(value securitylog.Snapshot) securitylog.Snapshot {
	value.Events = append([]securitylog.Event(nil), value.Events...)
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneDrivers(value driveranalysis.Snapshot) driveranalysis.Snapshot {
	value.Items = append([]driveranalysis.Item(nil), value.Items...)
	value.Checks = append([]driveranalysis.SourceCheck(nil), value.Checks...)
	for i := range value.Checks {
		value.Checks[i].Samples = append([]string(nil), value.Checks[i].Samples...)
	}
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneMemory(value memoryscan.Snapshot) memoryscan.Snapshot {
	value.Records = append([]memoryscan.Record(nil), value.Records...)
	for i := range value.Records {
		value.Records[i].HardSignals = append([]string(nil), value.Records[i].HardSignals...)
	}
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}

func cloneLogHealth(value loghealth.Snapshot) loghealth.Snapshot {
	value.Sources = append([]loghealth.SourceHealth(nil), value.Sources...)
	return value
}

func cloneRegistry(value registryanomaly.Snapshot) registryanomaly.Snapshot {
	value.Records = append([]registryanomaly.Record(nil), value.Records...)
	for i := range value.Records {
		value.Records[i].Reasons = append([]string(nil), value.Records[i].Reasons...)
		value.Records[i].Associations = append([]string(nil), value.Records[i].Associations...)
	}
	value.CollectionErrors = append([]string(nil), value.CollectionErrors...)
	return value
}
