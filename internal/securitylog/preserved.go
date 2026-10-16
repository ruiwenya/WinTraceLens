package securitylog

// PreservedEvent retains the exact record referenced by persistence/driver
// checks independently of the normal event list's display quota.
type PreservedEvent struct {
	Time        string `json:"time"`
	TimeUTC     string `json:"timeUtc"`
	Source      string `json:"source"`
	Channel     string `json:"channel"`
	Provider    string `json:"provider"`
	Computer    string `json:"computer"`
	EventID     string `json:"eventId"`
	RecordID    string `json:"recordId"`
	ServiceName string `json:"serviceName"`
	ImagePath   string `json:"imagePath"`
	ServiceType string `json:"serviceType"`
	StartType   string `json:"startType"`
	Account     string `json:"account"`
	SubjectSID  string `json:"subjectSid"`
	Message     string `json:"message"`
	XML         string `json:"xml"`
	Details     string `json:"details"`
}
