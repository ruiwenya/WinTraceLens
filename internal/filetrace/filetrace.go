package filetrace

type Options struct {
	MaxRecords    int
	Hours         int
	ModifiedRoots []string
	ArtifactsOnly bool
	AmcachePath   string
}

type Snapshot struct {
	Records          []Record `json:"records"`
	CollectionErrors []string `json:"collectionErrors"`
	Notices          []string `json:"notices,omitempty"`
	GeneratedAt      string   `json:"generatedAt"`
}

type Record struct {
	Category        string   `json:"category"`
	Source          string   `json:"source"`
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Directory       string   `json:"directory"`
	Extension       string   `json:"extension"`
	Size            int64    `json:"size"`
	Created         string   `json:"created"`
	Modified        string   `json:"modified"`
	Accessed        string   `json:"accessed"`
	LastRun         string   `json:"lastRun"`
	RunCount        string   `json:"runCount"`
	Suspicion       string   `json:"suspicion"`
	Reason          string   `json:"reason"`
	Details         string   `json:"details"`
	Schema          string   `json:"schema,omitempty"`
	SHA1            string   `json:"sha1,omitempty"`
	Publisher       string   `json:"publisher,omitempty"`
	ProductName     string   `json:"productName,omitempty"`
	ProductVersion  string   `json:"productVersion,omitempty"`
	BinaryType      string   `json:"binaryType,omitempty"`
	ProgramID       string   `json:"programId,omitempty"`
	Association     string   `json:"association,omitempty"`
	EvidenceTime    string   `json:"evidenceTime,omitempty"`
	TimeMeaning     string   `json:"timeMeaning,omitempty"`
	LinkDate        string   `json:"linkDate,omitempty"`
	Signature       string   `json:"signature,omitempty"`
	SignatureMsg    string   `json:"signatureMsg,omitempty"`
	SHA256          string   `json:"sha256,omitempty"`
	Magic           string   `json:"magic,omitempty"`
	Entropy         float64  `json:"entropy,omitempty"`
	Attributes      string   `json:"attributes,omitempty"`
	RelatedServices []string `json:"relatedServices,omitempty"`
}
