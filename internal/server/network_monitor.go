package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	connectionMonitorInterval = time.Second
	connectionMonitorCapacity = 5000
)

type monitoredConnectionItem struct {
	PID             uint32 `json:"pid"`
	Process         string `json:"process"`
	Path            string `json:"path"`
	Protocol        string `json:"protocol"`
	Local           string `json:"local"`
	Remote          string `json:"remote"`
	RemoteIP        string `json:"remoteIp"`
	RemotePort      uint16 `json:"remotePort"`
	RemoteKind      string `json:"remoteKind"`
	State           string `json:"state"`
	FirstSeen       string `json:"firstSeen"`
	LastSeen        string `json:"lastSeen"`
	Occurrences     uint64 `json:"occurrences"`
	Samples         uint64 `json:"samples"`
	CurrentlyActive bool   `json:"currentlyActive"`

	firstSeenTime time.Time
	lastSeenTime  time.Time
}

type connectionMonitor struct {
	mu        sync.Mutex
	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
	started   chan struct{}
	startedAt time.Time
	lastError string
	items     map[string]*monitoredConnectionItem
	active    map[string]struct{}
}

type connectionMonitorSnapshot struct {
	Items           []monitoredConnectionItem `json:"items"`
	Count           int                       `json:"count"`
	StartedAt       string                    `json:"startedAt"`
	GeneratedAt     string                    `json:"generatedAt"`
	IntervalSeconds int                       `json:"intervalSeconds"`
	Capacity        int                       `json:"capacity"`
	LastError       string                    `json:"lastError,omitempty"`
}

func newConnectionMonitor() *connectionMonitor {
	return &connectionMonitor{
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		started: make(chan struct{}),
		items:   make(map[string]*monitoredConnectionItem),
		active:  make(map[string]struct{}),
	}
}

func (m *connectionMonitor) start(collect func() ([]liveConnectionItem, error)) {
	m.startOnce.Do(func() {
		m.mu.Lock()
		m.startedAt = time.Now()
		m.mu.Unlock()
		close(m.started)
		go m.loop(collect)
	})
}

func (m *connectionMonitor) loop(collect func() ([]liveConnectionItem, error)) {
	defer close(m.done)
	m.collectOnce(collect)
	ticker := time.NewTicker(connectionMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.collectOnce(collect)
		case <-m.stop:
			return
		}
	}
}

func (m *connectionMonitor) collectOnce(collect func() ([]liveConnectionItem, error)) {
	items, err := collect()
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return
	}
	m.observe(items, time.Now())
}

func (m *connectionMonitor) observe(items []liveConnectionItem, observedAt time.Time) {
	current := make(map[string]struct{}, len(items))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, item := range items {
		if !monitorableConnection(item) {
			continue
		}
		key := monitoredConnectionKey(item)
		current[key] = struct{}{}
		record, exists := m.items[key]
		if !exists {
			record = &monitoredConnectionItem{
				PID:           item.PID,
				Process:       item.Process,
				Path:          item.Path,
				Protocol:      item.Protocol,
				Local:         item.Local,
				Remote:        item.Remote,
				RemoteIP:      item.RemoteIP,
				RemotePort:    item.RemotePort,
				RemoteKind:    item.RemoteKind,
				State:         item.State,
				Occurrences:   1,
				firstSeenTime: observedAt,
			}
			m.items[key] = record
		} else if _, wasActive := m.active[key]; !wasActive {
			record.Occurrences++
		}
		record.Process = firstNonEmpty(item.Process, record.Process)
		record.Path = firstNonEmpty(item.Path, record.Path)
		record.RemoteKind = firstNonEmpty(item.RemoteKind, record.RemoteKind)
		record.State = item.State
		record.lastSeenTime = observedAt
		record.Samples++
		record.CurrentlyActive = true
	}
	for key := range m.active {
		if _, ok := current[key]; ok {
			continue
		}
		if record := m.items[key]; record != nil {
			record.CurrentlyActive = false
		}
	}
	m.active = current
	m.lastError = ""
	m.pruneLocked()
}

func (m *connectionMonitor) pruneLocked() {
	if len(m.items) <= connectionMonitorCapacity {
		return
	}
	type candidate struct {
		key    string
		active bool
		seen   time.Time
	}
	candidates := make([]candidate, 0, len(m.items))
	for key, item := range m.items {
		candidates = append(candidates, candidate{key: key, active: item.CurrentlyActive, seen: item.lastSeenTime})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].active != candidates[j].active {
			return !candidates[i].active
		}
		return candidates[i].seen.Before(candidates[j].seen)
	})
	for len(m.items) > connectionMonitorCapacity {
		item := candidates[0]
		candidates = candidates[1:]
		delete(m.items, item.key)
		delete(m.active, item.key)
	}
}

func (m *connectionMonitor) snapshot() connectionMonitorSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]monitoredConnectionItem, 0, len(m.items))
	for _, source := range m.items {
		item := *source
		item.FirstSeen = formatObservationTime(item.firstSeenTime)
		item.LastSeen = formatObservationTime(item.lastSeenTime)
		item.firstSeenTime = time.Time{}
		item.lastSeenTime = time.Time{}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen == items[j].LastSeen {
			return items[i].Remote < items[j].Remote
		}
		return items[i].LastSeen > items[j].LastSeen
	})
	return connectionMonitorSnapshot{
		Items:           items,
		Count:           len(items),
		StartedAt:       formatObservationTime(m.startedAt),
		GeneratedAt:     formatObservationTime(time.Now()),
		IntervalSeconds: int(connectionMonitorInterval / time.Second),
		Capacity:        connectionMonitorCapacity,
		LastError:       m.lastError,
	}
}

func (m *connectionMonitor) close() {
	m.stopOnce.Do(func() { close(m.stop) })
	select {
	case <-m.started:
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
		}
	default:
	}
}

func monitorableConnection(item liveConnectionItem) bool {
	ip := strings.TrimSpace(item.RemoteIP)
	return item.RemotePort != 0 && ip != "" && ip != "0.0.0.0" && ip != "::" && ip != "*"
}

func monitoredConnectionKey(item liveConnectionItem) string {
	return fmt.Sprintf("%d|%s|%s|%s", item.PID, strings.ToUpper(item.Protocol), item.Local, item.Remote)
}

func formatObservationTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
