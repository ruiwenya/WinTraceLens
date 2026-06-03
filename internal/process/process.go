package process

type Info struct {
	PID             uint32 `json:"pid"`
	Name            string `json:"name"`
	ParentPID       uint32 `json:"parentPid"`
	ParentName      string `json:"parentName"`
	CreatedAt       string `json:"createdAt"`
	Path            string `json:"path"`
	FileCreated     string `json:"fileCreated"`
	FileModified    string `json:"fileModified"`
	MD5             string `json:"md5"`
	Signature       string `json:"signature"`
	SignatureMsg    string `json:"signatureMsg"`
	ConnectionCount int    `json:"connectionCount"`
	HashError       string `json:"hashError"`
	PathError       string `json:"pathError"`
}

type Options struct {
	HashLimitBytes int64
	SkipHashes     bool
	SkipSignatures bool
}

type ModuleInfo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	SizeKB       uint32 `json:"sizeKb"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type ConnectionInfo struct {
	PID      uint32 `json:"pid"`
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
}
