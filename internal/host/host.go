package host

type Options struct {
	HashLimitBytes int64
}

type Snapshot struct {
	Services         []ServiceInfo       `json:"services"`
	ScheduledTasks   []ScheduledTaskInfo `json:"scheduledTasks"`
	StartupItems     []StartupItem       `json:"startupItems"`
	Users            []UserInfo          `json:"users"`
	ImageHijacks     []ImageHijackInfo   `json:"imageHijacks"`
	CollectionErrors []string            `json:"collectionErrors"`
}

type ServiceInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	State        string `json:"state"`
	StartMode    string `json:"startMode"`
	Account      string `json:"account"`
	Command      string `json:"command"`
	Path         string `json:"path"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type ScheduledTaskInfo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	State        string `json:"state"`
	Status       string `json:"status"`
	Author       string `json:"author"`
	Command      string `json:"command"`
	Arguments    string `json:"arguments"`
	Executable   string `json:"executable"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type StartupItem struct {
	Source       string `json:"source"`
	Name         string `json:"name"`
	Command      string `json:"command"`
	Location     string `json:"location"`
	Path         string `json:"path"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type UserInfo struct {
	Name             string `json:"name"`
	SID              string `json:"sid"`
	Disabled         bool   `json:"disabled"`
	Lockout          bool   `json:"lockout"`
	PasswordRequired bool   `json:"passwordRequired"`
	LocalAccount     bool   `json:"localAccount"`
}

type ImageHijackInfo struct {
	Image        string `json:"image"`
	Debugger     string `json:"debugger"`
	RegistryPath string `json:"registryPath"`
	Path         string `json:"path"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}
