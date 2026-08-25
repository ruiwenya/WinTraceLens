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
	WMISubscriptions []WMISubscription   `json:"wmiSubscriptions"`
	CollectionErrors []string            `json:"collectionErrors"`
}

// WMISubscription represents a permanent WMI event subscription or an
// unbound filter/consumer. Full objects stay visible; RiskLevel only promotes
// subscriptions with concrete suspicious signals.
type WMISubscription struct {
	Namespace           string   `json:"namespace"`
	Status              string   `json:"status"`
	BindingPath         string   `json:"bindingPath"`
	FilterPath          string   `json:"filterPath"`
	FilterName          string   `json:"filterName"`
	Query               string   `json:"query"`
	QueryLanguage       string   `json:"queryLanguage"`
	EventNamespace      string   `json:"eventNamespace"`
	FilterCreatorSID    string   `json:"filterCreatorSid"`
	ConsumerPath        string   `json:"consumerPath"`
	ConsumerName        string   `json:"consumerName"`
	ConsumerType        string   `json:"consumerType"`
	CommandLine         string   `json:"commandLine"`
	ExecutablePath      string   `json:"executablePath"`
	ExecutableMD5       string   `json:"executableMd5"`
	ExecutableHashErr   string   `json:"executableHashError"`
	ExecutableSignature string   `json:"executableSignature"`
	ExecutableSigMsg    string   `json:"executableSignatureMsg"`
	ScriptText          string   `json:"scriptText"`
	ConsumerDetails     string   `json:"consumerDetails"`
	RunInteractively    bool     `json:"runInteractively"`
	ConsumerCreatorSID  string   `json:"consumerCreatorSid"`
	BindingCreatorSID   string   `json:"bindingCreatorSid"`
	SystemManaged       bool     `json:"systemManaged"`
	Summary             string   `json:"summary"`
	RiskLevel           string   `json:"riskLevel"`
	RiskScore           int      `json:"riskScore"`
	RiskReasons         []string `json:"riskReasons"`
	RelatedServices     []string `json:"relatedServices"`
	RelatedTasks        []string `json:"relatedTasks"`
}

type ServiceInfo struct {
	Name                string   `json:"name"`
	DisplayName         string   `json:"displayName"`
	State               string   `json:"state"`
	StartMode           string   `json:"startMode"`
	Account             string   `json:"account"`
	Command             string   `json:"command"`
	Path                string   `json:"path"`
	MD5                 string   `json:"md5"`
	Signature           string   `json:"signature"`
	SignatureMsg        string   `json:"signatureMsg"`
	HashError           string   `json:"hashError"`
	SourceStatus        string   `json:"sourceStatus"`
	SCMPath             string   `json:"scmPath"`
	RegistryImagePath   string   `json:"registryImagePath"`
	WMIPath             string   `json:"wmiPath"`
	RegistryPath        string   `json:"registryPath"`
	ServiceDLL          string   `json:"serviceDll"`
	ServiceDLLSignature string   `json:"serviceDllSignature"`
	ServiceDLLSigMsg    string   `json:"serviceDllSignatureMsg"`
	FileStatus          string   `json:"fileStatus"`
	RiskLevel           string   `json:"riskLevel"`
	RiskScore           int      `json:"riskScore"`
	RiskReasons         []string `json:"riskReasons"`
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
