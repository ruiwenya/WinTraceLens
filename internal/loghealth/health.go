package loghealth

type Snapshot struct {
	Sources     []SourceHealth `json:"sources"`
	Summary     Summary        `json:"summary"`
	GeneratedAt string         `json:"generatedAt"`
}

type Summary struct {
	Total           int `json:"total"`
	Available       int `json:"available"`
	NoEvents        int `json:"noEvents"`
	Unavailable     int `json:"unavailable"`
	PermissionIssue int `json:"permissionIssue"`
}

type SourceHealth struct {
	Category       string `json:"category"`
	Name           string `json:"name"`
	LogName        string `json:"logName"`
	Status         string `json:"status"`
	EventIDs       string `json:"eventIds"`
	LastEventTime  string `json:"lastEventTime"`
	RecordCount    int64  `json:"recordCount"`
	Details        string `json:"details"`
	Recommendation string `json:"recommendation"`
}
