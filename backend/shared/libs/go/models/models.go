package models

import "time"

// BackendVerdict represents the deterministic backend classification.
type BackendVerdict string

const (
	VerdictClean               BackendVerdict = "CLEAN"
	VerdictSuspicious          BackendVerdict = "SUSPICIOUS"
	VerdictMalicious           BackendVerdict = "MALICIOUS"
	VerdictPkiTrustCompromised BackendVerdict = "PKI_TRUST_COMPROMISED"
)

// FastPathVerdict represents sub-150ms synchronous lane evaluation telemetry.
type FastPathVerdict struct {
	EvaluatedInMs           int            `json:"evaluatedInMs"`
	BloomFilterHit          bool           `json:"bloomFilterHit"`
	BloomSource             string         `json:"bloomSource,omitempty"` // "Abuse.ch URLhaus" | "Internal Cuckoo" | "None"
	GoogleSafeBrowsingMatch bool           `json:"googleSafeBrowsingMatch"`
	GsbThreatType           string         `json:"gsbThreatType,omitempty"`
	CachedReputation        string         `json:"cachedReputation,omitempty"` // "BENIGN" | "SUSPICIOUS" | "MALICIOUS" | "UNRATED"
	MozillaOneCrlRevoked    bool           `json:"mozillaOneCrlRevoked"`
	PreliminaryVerdict      BackendVerdict `json:"preliminaryVerdict"`
	Summary                 string         `json:"summary"`
}

// WorkerPoolId identifies worker queues.
type WorkerPoolId string

const (
	PoolPhishingDetonation WorkerPoolId = "phishing_detonation"
	PoolPkiCtValidation    WorkerPoolId = "pki_ct_validation"
	PoolAppSecAuditing     WorkerPoolId = "app_sec_auditing"
	PoolCtiGraph           WorkerPoolId = "cti_graph_correlation"
)

// WorkerStatus tracks progress of an asynchronous worker.
type WorkerStatus struct {
	ID             WorkerPoolId `json:"id"`
	Name           string       `json:"name"`
	Status         string       `json:"status"` // "pending" | "queued" | "running" | "completed" | "failed" | "timed_out"
	DurationMs     int          `json:"durationMs,omitempty"`
	SummarySnippet string       `json:"summarySnippet,omitempty"`
}

// Finding represents a single flagged vulnerability or indicator.
type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"` // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
	Category       string   `json:"category"` // "PHISHING" | "PKI" | "WEB_SEC" | "CTI"
	Description    string   `json:"description"`
	Source         string   `json:"source"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	CveReference   string   `json:"cveReference,omitempty"`
}

// CertificateSummaryItem represents an X.509 certificate node in the chain.
type CertificateSummaryItem struct {
	Type               string `json:"type"` // "leaf" | "intermediate" | "root"
	SubjectCommonName  string `json:"subjectCommonName"`
	SubjectOrg         string `json:"subjectOrg,omitempty"`
	IssuerCommonName   string `json:"issuerCommonName"`
	IssuerOrg          string `json:"issuerOrg,omitempty"`
	SerialNumber       string `json:"serialNumber"`
	ValidFrom          string `json:"validFrom"`
	ValidUntil         string `json:"validUntil"`
	DaysRemaining      int    `json:"daysRemaining"`
	IsExpired          bool   `json:"isExpired"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	KeySizeBits        int    `json:"keySizeBits"`
	Sha256Fingerprint  string `json:"sha256Fingerprint"`
	RawPem             string `json:"rawPem,omitempty"`
}

// ScanTaskPayload is dispatched to Kafka topics.
type ScanTaskPayload struct {
	ScanID             string            `json:"scan_id"`
	SubmittedURL       string            `json:"submitted_url"`
	CanonicalURL       string            `json:"canonical_url"`
	Hostname           string            `json:"hostname"`
	TargetURLDefanged  string            `json:"target_url_defanged"`
	TenantID           string            `json:"tenant_id,omitempty"`
	IsPrivate          bool              `json:"is_private"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	MaxRedirectHops    int               `json:"max_redirect_hops"`
	MaxBodyBytes       int64             `json:"max_body_bytes"`
	MaxCertChainBytes  int64             `json:"max_cert_chain_bytes"`
	CreatedAt          string            `json:"created_at"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ScanProgressEvent represents a frame sent over WebSocket.
type ScanProgressEvent struct {
	ScanID             string       `json:"scanId"`
	EventType          string       `json:"eventType"` // "WORKER_STARTED" | "WORKER_PROGRESS" | "WORKER_COMPLETED" | "WORKER_FAILED" | "SCAN_COMPLETED"
	WorkerID           WorkerPoolId `json:"workerId"`
	WorkerName         string       `json:"workerName"`
	Status             string       `json:"status"`
	ProgressPercentage int          `json:"progressPercentage,omitempty"`
	Snippet            string       `json:"snippet,omitempty"`
	Timestamp          string       `json:"timestamp"`
}

// ExtendedScanReport is the comprehensive response conforming to frontend expectations.
type ExtendedScanReport struct {
	ScanID                 string                 `json:"scanId"`
	SubmittedURL           string                 `json:"submittedUrl"`
	Hostname               string                 `json:"hostname"`
	CanonicalURL           string                 `json:"canonicalUrl"`
	CheckedAt              string                 `json:"checkedAt"`
	BackendVerdict         BackendVerdict         `json:"backendVerdict"`
	BackendRiskScore       int                    `json:"backendRiskScore"`
	UITrustScore           int                    `json:"uiTrustScore"`
	Summary                string                 `json:"summary"`
	AnalystReasonCodes     []string               `json:"analystReasonCodes"`
	FastPath               FastPathVerdict        `json:"fastPath"`
	WorkerPools            []WorkerStatus         `json:"workerPools"`
	PhishingDetonation     map[string]interface{} `json:"phishingDetonation"`
	PkiIntelligence        map[string]interface{} `json:"pkiIntelligence"`
	WebSecurityAudit       map[string]interface{} `json:"webSecurityAudit"`
	ThreatIntelligence     map[string]interface{} `json:"threatIntelligence"`
	Forensics              map[string]interface{} `json:"forensics"`
	Findings               []Finding              `json:"findings"`
}

// ScanHistoryItem represents an entry in the scan history list.
type ScanHistoryItem struct {
	ScanID       string         `json:"scanId"`
	Hostname     string         `json:"hostname"`
	SubmittedURL string         `json:"submittedUrl"`
	Timestamp    string         `json:"timestamp"`
	Verdict      BackendVerdict `json:"verdict"`
	RiskScore    int            `json:"riskScore"`
	TrustScore   int            `json:"trustScore"`
	ResolvedIP   string         `json:"resolvedIp,omitempty"`
}

