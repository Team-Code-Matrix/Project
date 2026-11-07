import { z } from 'zod';

export const BackendVerdictSchema = z.enum([
  'CLEAN',
  'SUSPICIOUS',
  'MALICIOUS',
  'PKI_TRUST_COMPROMISED',
]);

export const FastPathVerdictSchema = z.object({
  evaluatedInMs: z.number(),
  bloomFilterHit: z.boolean(),
  bloomSource: z.enum(['Abuse.ch URLhaus', 'Internal Cuckoo', 'None']).optional(),
  googleSafeBrowsingMatch: z.boolean(),
  gsbThreatType: z.string().optional(),
  cachedReputation: z.enum(['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNRATED']).optional(),
  mozillaOneCrlRevoked: z.boolean(),
  preliminaryVerdict: BackendVerdictSchema,
  summary: z.string(),
});

export const WorkerStatusSchema = z.object({
  id: z.enum([
    'phishing_detonation',
    'pki_ct_validation',
    'app_sec_auditing',
    'cti_graph_correlation',
  ]),
  name: z.string(),
  status: z.enum(['pending', 'queued', 'running', 'completed', 'failed', 'skipped', 'timed_out']),
  durationMs: z.number().optional(),
  summarySnippet: z.string().optional(),
});

export const CertificateSummaryItemSchema = z.object({
  type: z.enum(['leaf', 'intermediate', 'root']),
  subjectCommonName: z.string(),
  subjectOrg: z.string().optional(),
  issuerCommonName: z.string(),
  issuerOrg: z.string().optional(),
  serialNumber: z.string(),
  validFrom: z.string(),
  validUntil: z.string(),
  daysRemaining: z.number(),
  isExpired: z.boolean(),
  signatureAlgorithm: z.string(),
  publicKeyAlgorithm: z.string(),
  keySizeBits: z.number(),
  sha256Fingerprint: z.string(),
  rawPem: z.string().optional(),
});

export const PkiIntelligenceSchema = z.object({
  keyEntropyVerdict: z.enum(['VALID', 'WEAK_ENTROPY', 'SMALL_SUBGROUP', 'ROCA_VULNERABLE']),
  fermatFactorizationPassed: z.boolean(),
  smallPrimeGcdPassed: z.boolean(),
  curvePointValid: z.boolean(),
  keyCeremonyAnomalyFlag: z.boolean(),
  keyCeremonyNotes: z.string().optional(),
  chainValidationStatus: z.enum(['VERIFIED', 'REVOKED', 'UNTRUSTED_ROOT', 'CROSS_SIGN_SUSPECT']),
  trustStoreCompatibility: z.object({
    mozillaNss: z.boolean(),
    chromeRoot: z.boolean(),
    apple: z.boolean(),
    microsoft: z.boolean(),
    oracleJava: z.boolean(),
  }),
  pathLenConstraintValid: z.boolean(),
  crossSignedBypassDetected: z.boolean(),
  certificateTransparency: z.object({
    sctsDeliveredCount: z.number(),
    sctSources: z.array(z.enum(['X.509 Extension', 'TLS Extension', 'OCSP Stapling'])),
    merkleInclusionProofStatus: z.enum(['PROVEN', 'PENDING', 'INVALID']),
    signedTreeHeadTimestamp: z.string(),
    unexpectedIssuanceAlert: z.boolean(),
  }),
  revocationHealth: z.object({
    ocspStatus: z.enum(['GOOD', 'REVOKED', 'UNKNOWN', 'UNRESPONSIVE']),
    ocspStapled: z.boolean(),
    mustStapleCompliant: z.boolean(),
    crlSignatureValid: z.boolean(),
    crlNextUpdateExpired: z.boolean(),
    oneCrlIncluded: z.boolean(),
    chromeCrlSetIncluded: z.boolean(),
  }),
  dnsCaaPolicy: z.object({
    caaRecordsPresent: z.boolean(),
    allowedIssuers: z.array(z.string()),
    actualIssuer: z.string(),
    policyMismatch: z.boolean(),
  }),
  chain: z.array(CertificateSummaryItemSchema),
});

export const WebSecurityAuditSchema = z.object({
  httpHeaders: z.object({
    csp: z.object({
      present: z.boolean(),
      directivesCount: z.number(),
      unsafeInline: z.boolean(),
      unsafeEval: z.boolean(),
      wildcardOrigins: z.boolean(),
      grade: z.enum(['A+', 'A', 'B', 'C', 'F']),
      rawHeader: z.string().optional(),
    }),
    hsts: z.object({
      present: z.boolean(),
      maxAgeSeconds: z.number(),
      includeSubdomains: z.boolean(),
      preloaded: z.boolean(),
      grade: z.enum(['EXCELLENT', 'ADEQUATE', 'DEFICIENT']),
    }),
    xFrameOptions: z.enum(['DENY', 'SAMEORIGIN', 'ALLOW-FROM', 'MISSING']),
    xContentTypeOptionsNosniff: z.boolean(),
    referrerPolicy: z.string().optional(),
    permissionsPolicy: z.string().optional(),
  }),
  cookieSecurity: z.object({
    totalCookiesCount: z.number(),
    secureFlagsMissingCount: z.number(),
    httpOnlyMissingCount: z.number(),
    sameSiteMissingCount: z.number(),
    sessionCookiesSafe: z.boolean(),
  }),
  corsPolicy: z.object({
    wildcardOrigin: z.boolean(),
    originReflection: z.boolean(),
    credentialsAllowed: z.boolean(),
    verdict: z.enum(['RESTRICTED', 'PERMISSIVE', 'VULNERABLE']),
  }),
  tlsFingerprints: z.object({
    negotiatedProtocol: z.enum(['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSLv3']),
    negotiatedCipher: z.string(),
    forwardSecrecy: z.boolean(),
    weakCipherDetected: z.boolean(),
    ja3sHash: z.string().optional(),
    ja4sHash: z.string().optional(),
    aitmProxySignatureDetected: z.boolean(),
  }),
  passiveExposure: z.object({
    serverBanner: z.string().optional(),
    xPoweredBy: z.string().optional(),
    exposedFilesObserved: z.array(z.string()),
    matchedCves: z.array(
      z.object({
        cveId: z.string(),
        component: z.string(),
        severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
        summary: z.string(),
      })
    ),
  }),
});

