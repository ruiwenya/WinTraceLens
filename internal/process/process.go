package process

type Info struct {
	PID                uint32 `json:"pid"`
	Name               string `json:"name"`
	ParentPID          uint32 `json:"parentPid"`
	ParentName         string `json:"parentName"`
	CreatedAt          string `json:"createdAt"`
	ParentCreatedAt    string `json:"parentCreatedAt"`
	Path               string `json:"path"`
	CommandLine        string `json:"commandLine"`
	UserName           string `json:"userName"`
	UserSID            string `json:"userSid"`
	SessionID          uint32 `json:"sessionId"`
	IntegrityLevel     string `json:"integrityLevel"`
	Architecture       string `json:"architecture"`
	Protection         string `json:"protection"`
	ThreadCount        uint32 `json:"threadCount"`
	HandleCount        uint32 `json:"handleCount"`
	PrivateMemoryBytes uint64 `json:"privateMemoryBytes"`
	WorkingSetBytes    uint64 `json:"workingSetBytes"`
	FileCreated        string `json:"fileCreated"`
	FileModified       string `json:"fileModified"`
	MD5                string `json:"md5"`
	Signature          string `json:"signature"`
	SignatureMsg       string `json:"signatureMsg"`
	ConnectionCount    int    `json:"connectionCount"`
	HashError          string `json:"hashError"`
	PathError          string `json:"pathError"`
	EnumerationSources string `json:"enumerationSources"`
	EnumerationWarning string `json:"enumerationWarning"`
}

type Options struct {
	HashLimitBytes int64
	SkipHashes     bool
	SkipSignatures bool
}

type ModuleInfo struct {
	Name         string `json:"name"`
	Kind         string `json:"kind,omitempty"`
	Path         string `json:"path"`
	BaseAddress  string `json:"baseAddress"`
	SizeKB       uint32 `json:"sizeKb"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type ConnectionInfo struct {
	PID        uint32 `json:"pid"`
	Protocol   string `json:"protocol"`
	Local      string `json:"local"`
	LocalIP    string `json:"localIp"`
	LocalPort  uint16 `json:"localPort"`
	Remote     string `json:"remote"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort uint16 `json:"remotePort"`
	RemoteKind string `json:"remoteKind"`
	State      string `json:"state"`
}
