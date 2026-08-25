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
	Level             string   `json:"level"`
	Category          string   `json:"category"`
	PID               uint32   `json:"pid"`
	Process           string   `json:"process"`
	Path              string   `json:"path"`
	Reason            string   `json:"reason"`
	Base              string   `json:"base"`
	RegionBase        string   `json:"regionBase"`
	Size              uint64   `json:"size"`
	Protect           string   `json:"protect"`
	AllocationProtect string   `json:"allocationProtect"`
	MemoryType        string   `json:"memoryType"`
	BackingFile       string   `json:"backingFile"`
	ThreadID          uint32   `json:"threadId"`
	SHA256            string   `json:"sha256"`
	HashScope         string   `json:"hashScope"`
	Entropy           float64  `json:"entropy"`
	HexPreview        string   `json:"hexPreview"`
	StringsPreview    string   `json:"stringsPreview"`
	HasMZ             bool     `json:"hasMZ"`
	HasPE             bool     `json:"hasPE"`
	HardSignals       []string `json:"hardSignals"`
	Exportable        bool     `json:"exportable"`
	Details           string   `json:"details"`
	Context           string   `json:"context"`
}

type RegionExport struct {
	PID               uint32 `json:"pid"`
	Base              string `json:"base"`
	Size              uint64 `json:"size"`
	BytesRead         uint64 `json:"bytesRead"`
	Protect           string `json:"protect"`
	AllocationProtect string `json:"allocationProtect"`
	MemoryType        string `json:"memoryType"`
	BackingFile       string `json:"backingFile"`
	SHA256            string `json:"sha256"`
	CollectedAt       string `json:"collectedAt"`
	Warning           string `json:"warning,omitempty"`
	Data              []byte `json:"-"`
}
