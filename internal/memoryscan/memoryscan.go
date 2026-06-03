package memoryscan

type Options struct {
	MaxProcesses         int
	MaxRecords           int
	MaxRegionsPerProcess int
	IncludeThreads       bool
}

type Snapshot struct {
	Records          []Record `json:"records"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
	ScannedProcesses int      `json:"scannedProcesses"`
	SkippedProcesses int      `json:"skippedProcesses"`
}

type Record struct {
	Level      string `json:"level"`
	Category   string `json:"category"`
	PID        uint32 `json:"pid"`
	Process    string `json:"process"`
	Path       string `json:"path"`
	Reason     string `json:"reason"`
	Base       string `json:"base"`
	Size       uint64 `json:"size"`
	Protect    string `json:"protect"`
	MemoryType string `json:"memoryType"`
	ThreadID   uint32 `json:"threadId"`
	Details    string `json:"details"`
	Context    string `json:"context"`
}
