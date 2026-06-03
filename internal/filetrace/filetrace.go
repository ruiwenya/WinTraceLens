package filetrace

type Options struct {
	MaxRecords    int
	Hours         int
	ModifiedRoots []string
}

type Snapshot struct {
	Records          []Record `json:"records"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
}

type Record struct {
	Category  string `json:"category"`
	Source    string `json:"source"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Directory string `json:"directory"`
	Extension string `json:"extension"`
	Size      int64  `json:"size"`
	Created   string `json:"created"`
	Modified  string `json:"modified"`
	Accessed  string `json:"accessed"`
	LastRun   string `json:"lastRun"`
	RunCount  string `json:"runCount"`
	Suspicion string `json:"suspicion"`
	Reason    string `json:"reason"`
	Details   string `json:"details"`
}
