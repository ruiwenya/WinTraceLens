package history

import "time"

type Options struct {
	MaxRecords int
	StartTime  time.Time
	EndTime    time.Time
}

type Snapshot struct {
	Records          []Record `json:"records"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
}

type Record struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	EventID string `json:"eventId"`
	Process string `json:"process"`
	PID     string `json:"pid"`
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	Query   string `json:"query"`
	Action  string `json:"action"`
	User    string `json:"user"`
	Details string `json:"details"`
}
