package securitylog

import "time"

type Options struct {
	MaxRecords int
	StartTime  time.Time
	EndTime    time.Time
}

type Snapshot struct {
	Events           []Event  `json:"events"`
	CollectionErrors []string `json:"collectionErrors"`
	GeneratedAt      string   `json:"generatedAt"`
}

type Event struct {
	Time          string `json:"time"`
	Category      string `json:"category"`
	Source        string `json:"source"`
	EventID       string `json:"eventId"`
	Action        string `json:"action"`
	Account       string `json:"account"`
	Domain        string `json:"domain"`
	Subject       string `json:"subject"`
	LogonType     string `json:"logonType"`
	LogonTypeName string `json:"logonTypeName"`
	SourceIP      string `json:"sourceIp"`
	SourcePort    string `json:"sourcePort"`
	Workstation   string `json:"workstation"`
	Process       string `json:"process"`
	ServiceName   string `json:"serviceName"`
	Command       string `json:"command"`
	AuthPackage   string `json:"authPackage"`
	Status        string `json:"status"`
	FailureReason string `json:"failureReason"`
	TargetSID     string `json:"targetSid"`
	Provider      string `json:"provider"`
	Level         string `json:"level"`
	Message       string `json:"message"`
	Details       string `json:"details"`
}
