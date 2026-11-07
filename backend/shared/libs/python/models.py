"""
Shared Data Models for TrustShield Workers
Native Python dataclasses with dictionary serialization, mirroring Protobuf schemas
and frontend contracts with zero-dependency compatibility.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any

class BackendVerdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    PKI_TRUST_COMPROMISED = "PKI_TRUST_COMPROMISED"

class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingCategory(str, Enum):
    PHISHING = "PHISHING"
    PKI = "PKI"
    WEB_SEC = "WEB_SEC"
    CTI = "CTI"

class WorkerPoolId(str, Enum):
    PHISHING_DETONATION = "phishing_detonation"
    PKI_CT_VALIDATION = "pki_ct_validation"
    APP_SEC_AUDITING = "app_sec_auditing"
    CTI_GRAPH_CORRELATION = "cti_graph_correlation"

class WorkerStatusState(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"

class TlpMarking(str, Enum):
    TLP_WHITE = "TLP:WHITE"
    TLP_GREEN = "TLP:GREEN"
    TLP_AMBER = "TLP:AMBER"
    TLP_RED = "TLP:RED"

@dataclass
class Finding:
    id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    source: str
    evidence: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    cveReference: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class WorkerStatus:
    id: WorkerPoolId
    name: str
    status: WorkerStatusState
    durationMs: Optional[int] = None
    summarySnippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ScanTaskPayload:
    scan_id: str
    submitted_url: str
    canonical_url: str
    hostname: str
    target_url_defanged: str
    tenant_id: Optional[str] = None
    is_private: bool = False
    timeout_seconds: int = 15
    max_redirect_hops: int = 5
    max_body_bytes: int = 10485760 # 10MB
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RedirectHop:
    hop: int
    url: str
    type: str # "HTTP 301", "HTTP 302", "Meta Refresh", "window.location", "Direct"
    statusCode: int
    destinationIp: Optional[str] = None
    asn: Optional[str] = None

@dataclass
class DomHeuristics:
    passwordInputsCount: int = 0
    paymentFieldsCount: int = 0
    otpFieldsCount: int = 0
    crossOriginSubmissionTarget: Optional[str] = None
    browserInTheBrowserDetected: bool = False
    hiddenIframesCount: int = 0
    devToolsBlockerDetected: bool = False

@dataclass
class ComputerVisionTelemetry:
    targetedBrand: Optional[str] = None
    visualSimilarityScore: float = 0.0
    pHashHex: Optional[str] = None
    dHashHex: Optional[str] = None
    faviconMurmurHash3: Optional[str] = None
    isImpersonation: bool = False

@dataclass
class PhishingDetonationTelemetry:
    detonationSandbox: str = "Firecracker microVM"
    antiBotCloakingDefeated: bool = False
    redirectChain: List[RedirectHop] = field(default_factory=list)
    domHeuristics: DomHeuristics = field(default_factory=DomHeuristics)
    yaraRulesMatched: List[str] = field(default_factory=list)
    computerVision: ComputerVisionTelemetry = field(default_factory=ComputerVisionTelemetry)
    screenshotUrl: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class CertificateSummaryItem:
    type: str # 'leaf' | 'intermediate' | 'root'
    subjectCommonName: str
    issuerCommonName: str
    serialNumber: str
    validFrom: str
    validUntil: str
    daysRemaining: int
    signatureAlgorithm: str
    publicKeyAlgorithm: str
    keySizeBits: int
    sha256Fingerprint: str
    isExpired: bool = False
    subjectOrg: Optional[str] = None
    issuerOrg: Optional[str] = None
    rawPem: Optional[str] = None

@dataclass
class PkiIntelligence:
    keyEntropyVerdict: str = "VALID"
    fermatFactorizationPassed: bool = True
    smallPrimeGcdPassed: bool = True
    curvePointValid: bool = True
    keyCeremonyAnomalyFlag: bool = False
    chainValidationStatus: str = "VERIFIED"
    pathLenConstraintValid: bool = True
    crossSignedBypassDetected: bool = False
    keyCeremonyNotes: Optional[str] = None
    trustStoreCompatibility: Dict[str, bool] = field(default_factory=dict)
    certificateTransparency: Dict[str, Any] = field(default_factory=dict)
    revocationHealth: Dict[str, Any] = field(default_factory=dict)
    dnsCaaPolicy: Dict[str, Any] = field(default_factory=dict)
    chain: List[CertificateSummaryItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class WebSecurityAudit:
    httpHeaders: Dict[str, Any] = field(default_factory=dict)
    cookieSecurity: Dict[str, Any] = field(default_factory=dict)
    corsPolicy: Dict[str, Any] = field(default_factory=dict)
    tlsFingerprints: Dict[str, Any] = field(default_factory=dict)
    passiveExposure: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ThreatGraphNode:
    id: str
    type: str
    label: str
    subLabel: Optional[str] = None
    riskState: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class ThreatGraphEdge:
    id: str
    source: str
    target: str
    label: str
    relationshipType: str

@dataclass
class ThreatGraphData:
    nodes: List[ThreatGraphNode] = field(default_factory=list)
    edges: List[ThreatGraphEdge] = field(default_factory=list)

@dataclass
class ScanHistoryItem:
    scanId: str
    hostname: str
    submittedUrl: str
    timestamp: str
    verdict: BackendVerdict
    riskScore: int
    trustScore: int
    resolvedIp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class StixThreatIndicator:
    id: str
    name: str
    description: str
    pattern: str
    validFrom: str
    sourceAttribution: str
    type: str = "indicator"
    specVersion: str = "2.1"
    indicatorTypes: List[str] = field(default_factory=list)
    patternType: str = "stix"
    validUntil: Optional[str] = None
    tlpMarking: TlpMarking = TlpMarking.TLP_AMBER
    confidenceScore: int = 80
    externalReferences: Optional[List[Dict[str, str]]] = None
    reputationDecay: Dict[str, Any] = field(default_factory=dict)
    communitySightingsCount: int = 0
    reporterReliabilityScore: int = 85

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
