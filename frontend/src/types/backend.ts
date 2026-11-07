import type { FindingSeverity } from './scan';

/**
 * Backend deterministic verdicts as specified in the architecture document:
 * - CLEAN: No significant threat or compliance issues observed.
 * - SUSPICIOUS: Anomalies observed in heuristics, lexical analysis, or redirect hops.
 * - MALICIOUS: Confirmed malicious indicators (phishing kit, credential harvester, threat feed hit).
 * - PKI_TRUST_COMPROMISED: Cryptographic failure, key ceremony flaw, revoked intermediate, or rogue CA issuance.
 */
export type BackendVerdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'PKI_TRUST_COMPROMISED';

/**
 * Fast-path sub-150ms synchronous lane telemetry
 */
export interface FastPathVerdict {
  evaluatedInMs: number;
  bloomFilterHit: boolean;
  bloomSource?: 'Abuse.ch URLhaus' | 'Internal Cuckoo' | 'None';
  googleSafeBrowsingMatch: boolean;
  gsbThreatType?: string;
  cachedReputation?: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNRATED';
  mozillaOneCrlRevoked: boolean;
  preliminaryVerdict: BackendVerdict;
  summary: string;
}

/**
 * Deep-scan asynchronous lane worker status
 */
export type WorkerPoolId =
  | 'phishing_detonation'
  | 'pki_ct_validation'
  | 'app_sec_auditing'
  | 'cti_graph_correlation';

export interface WorkerStatus {
  id: WorkerPoolId;
  name: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'skipped' | 'timed_out';
  durationMs?: number;
  summarySnippet?: string;
}

/**
 * Pillar 1: Advanced Phishing & DOM Detonation Telemetry
 */
export interface PhishingDetonationTelemetry {
  detonationSandbox: 'Firecracker microVM' | 'gVisor sandbox' | 'Mock Container';
  antiBotCloakingDefeated: boolean;
  redirectChain: {
    hop: number;
    url: string;
    type: 'HTTP 301' | 'HTTP 302' | 'Meta Refresh' | 'window.location' | 'Direct';
    statusCode: number;
    destinationIp?: string;
    asn?: string;
  }[];
  domHeuristics: {
    passwordInputsCount: number;
    paymentFieldsCount: number;
    otpFieldsCount: number;
    crossOriginSubmissionTarget?: string;
    browserInTheBrowserDetected: boolean;
    hiddenIframesCount: number;
    devToolsBlockerDetected: boolean;
  };
  yaraRulesMatched: string[];
  computerVision: {
    targetedBrand?: string;
    visualSimilarityScore: number; // 0 - 100 percentage
    pHashHex?: string;
    dHashHex?: string;
    faviconMurmurHash3?: string;
    isImpersonation: boolean;
  };
  screenshotUrl?: string;
}

/**
 * Pillar 2: Cryptographic Trust, PKI & Certificate Validation Telemetry
 */
export interface CertificateSummaryItem {
  type: 'leaf' | 'intermediate' | 'root';
  subjectCommonName: string;
  subjectOrg?: string;
  issuerCommonName: string;
  issuerOrg?: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  daysRemaining: number;
  isExpired: boolean;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  keySizeBits: number;
  sha256Fingerprint: string;
  rawPem?: string;
}

export interface PkiIntelligence {
  // Key Entropy & Curve Audit
  keyEntropyVerdict: 'VALID' | 'WEAK_ENTROPY' | 'SMALL_SUBGROUP' | 'ROCA_VULNERABLE';
  fermatFactorizationPassed: boolean;
  smallPrimeGcdPassed: boolean;
  curvePointValid: boolean;
  keyCeremonyAnomalyFlag: boolean;
  keyCeremonyNotes?: string;

  // Multi-Store Path Validation
  chainValidationStatus: 'VERIFIED' | 'REVOKED' | 'UNTRUSTED_ROOT' | 'CROSS_SIGN_SUSPECT';
  trustStoreCompatibility: {
    mozillaNss: boolean;
    chromeRoot: boolean;
    apple: boolean;
    microsoft: boolean;
    oracleJava: boolean;
  };
  pathLenConstraintValid: boolean;
  crossSignedBypassDetected: boolean;

  // Certificate Transparency (CT) Logs
  certificateTransparency: {
    sctsDeliveredCount: number;
    sctSources: ('X.509 Extension' | 'TLS Extension' | 'OCSP Stapling')[];
    merkleInclusionProofStatus: 'PROVEN' | 'PENDING' | 'INVALID';
    signedTreeHeadTimestamp: string;
    unexpectedIssuanceAlert: boolean;
  };

  // Revocation & CA Health
  revocationHealth: {
    ocspStatus: 'GOOD' | 'REVOKED' | 'UNKNOWN' | 'UNRESPONSIVE';
    ocspStapled: boolean;
    mustStapleCompliant: boolean;
    crlSignatureValid: boolean;
    crlNextUpdateExpired: boolean;
    oneCrlIncluded: boolean;
    chromeCrlSetIncluded: boolean;
  };

  // DNS CAA Policy
  dnsCaaPolicy: {
    caaRecordsPresent: boolean;
    allowedIssuers: string[];
    actualIssuer: string;
    policyMismatch: boolean;
  };

  // Certificate Chain Hierarchy
  chain: CertificateSummaryItem[];
}

/**
 * Pillar 3: Application-Level Web Security Assessment Telemetry
 */
export interface WebSecurityAudit {
  httpHeaders: {
    csp: {
      present: boolean;
      directivesCount: number;
      unsafeInline: boolean;
      unsafeEval: boolean;
      wildcardOrigins: boolean;
      grade: 'A+' | 'A' | 'B' | 'C' | 'F';
      rawHeader?: string;
    };
    hsts: {
      present: boolean;
      maxAgeSeconds: number;
      includeSubdomains: boolean;
      preloaded: boolean;
      grade: 'EXCELLENT' | 'ADEQUATE' | 'DEFICIENT';
    };
    xFrameOptions: 'DENY' | 'SAMEORIGIN' | 'ALLOW-FROM' | 'MISSING';
    xContentTypeOptionsNosniff: boolean;
    referrerPolicy?: string;
    permissionsPolicy?: string;
  };
  cookieSecurity: {
    totalCookiesCount: number;
    secureFlagsMissingCount: number;
    httpOnlyMissingCount: number;
    sameSiteMissingCount: number;
    sessionCookiesSafe: boolean;
  };
  corsPolicy: {
    wildcardOrigin: boolean;
    originReflection: boolean;
    credentialsAllowed: boolean;
    verdict: 'RESTRICTED' | 'PERMISSIVE' | 'VULNERABLE';
  };
  tlsFingerprints: {
    negotiatedProtocol: 'TLS 1.3' | 'TLS 1.2' | 'TLS 1.1' | 'TLS 1.0' | 'SSLv3';
    negotiatedCipher: string;
    forwardSecrecy: boolean;
    weakCipherDetected: boolean;
    ja3sHash?: string;
    ja4sHash?: string;
    aitmProxySignatureDetected: boolean; // e.g. Evilginx2
  };
  passiveExposure: {
    serverBanner?: string;
    xPoweredBy?: string;
    exposedFilesObserved: string[]; // e.g., ['/.git/HEAD', '/.env']
    matchedCves: {
      cveId: string;
      component: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      summary: string;
    }[];
  };
}

/**
 * Pillar 4: STIX 2.1 & TAXII 2.1 Collaborative Threat Intelligence
 */
export type TlpMarking = 'TLP:WHITE' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';

export interface StixThreatIndicator {
  id: string; // STIX format indicator--uuid
  type: 'indicator' | 'malware' | 'infrastructure' | 'sighting';
  specVersion: '2.1';
  name: string;
  description: string;
  indicatorTypes: string[];
  pattern: string; // STIX pattern expression
  patternType: 'stix';
  validFrom: string;
  validUntil?: string;
  tlpMarking: TlpMarking;
  confidenceScore: number; // 0 - 100
  sourceAttribution: string;
  externalReferences?: {
    sourceName: string;
    url?: string;
    externalId?: string;
  }[];
  reputationDecay: {
    firstSeen: string;
    lastSeen: string;
    decayHalfLifeDays: number;
    currentWeight: number; // 0.0 - 1.0
  };
  communitySightingsCount: number;
  reporterReliabilityScore: number; // 0 - 100
}

/**
 * Threat Relationship Graph Entities (for @xyflow/react)
 */
export interface ThreatGraphNode {
  id: string;
  type: 'domain' | 'ip' | 'asn' | 'certificate' | 'ja4' | 'threat_actor';
  label: string;
  subLabel?: string;
  riskState?: 'clean' | 'suspicious' | 'malicious' | 'pki_compromised';
  details?: Record<string, string | number | boolean>;
}

export interface ThreatGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  relationshipType: 'RESOLVES_TO' | 'ANNOUNCED_BY' | 'SECURED_BY' | 'FINGERPRINTED_AS' | 'ATTRIBUTED_TO';
}

export interface ThreatGraphData {
  nodes: ThreatGraphNode[];
  edges: ThreatGraphEdge[];
}

/**
 * Forensic Evidence Artifacts
 */
export interface ForensicArtifacts {
  targetUrlDefanged: string; // e.g. hxxps://domain[.]com/login
  screenshotFullPageUrl?: string;
  screenshotTimestamp?: string;
  domSnapshotDefangedHtml?: string;
  harTraceSummary?: {
    totalRequests: number;
    totalBytesTransferred: number;
    externalDomainsContacted: string[];
    suspiciousRequestsCount: number;
    entries: {
      method: string;
      url: string;
      status: number;
      mimeType: string;
      sizeBytes: number;
      durationMs: number;
    }[];
  };
  rawCertificatePemChain?: string;
}

/**
 * Scan History Item for user tracking and reopening past scans
 */
export interface ScanHistoryItem {
  scanId: string;
  hostname: string;
  submittedUrl: string;
  timestamp: string;
  verdict: BackendVerdict;
  riskScore: number; // 0 - 100 risk
  trustScore: number; // 0 - 100 trust
  resolvedIp?: string;
}

/**
 * Complete Extended Backend Scan Report
 */
export interface ExtendedScanReport {
  scanId: string;
  submittedUrl: string;
  hostname: string;
  canonicalUrl: string;
  checkedAt: string;
  backendVerdict: BackendVerdict;
  backendRiskScore: number; // 0 (min risk) to 100 (max risk)
  uiTrustScore: number; // 100 (max trust) to 0 (min trust)
  summary: string;
  analystReasonCodes: string[];
  fastPath: FastPathVerdict;
  workerPools: WorkerStatus[];
  phishingDetonation: PhishingDetonationTelemetry;
  pkiIntelligence: PkiIntelligence;
  webSecurityAudit: WebSecurityAudit;
  threatIntelligence: {
    stixIndicators: StixThreatIndicator[];
    graphData: ThreatGraphData;
    mispSyncStatus: 'SYNCED' | 'PENDING' | 'OFFLINE';
  };
  forensics: ForensicArtifacts;
  findings: {
    id: string;
    title: string;
    severity: FindingSeverity;
    category: 'PHISHING' | 'PKI' | 'WEB_SEC' | 'CTI';
    description: string;
    source: string;
    evidence?: string[];
    recommendation?: string;
    cveReference?: string;
  }[];
}

