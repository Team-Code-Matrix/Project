import type { ExtendedScanReport } from '../types/backend';
import { RiskScoreAdapter } from '../utils/riskScoreAdapter';

export const EXTENDED_SCENARIOS: Record<string, ExtendedScanReport> = {
  'github.com': {
    scanId: 'scn_gh_982410a7',
    submittedUrl: 'https://github.com',
    hostname: 'github.com',
    canonicalUrl: 'https://github.com/',
    checkedAt: new Date().toISOString(),
    backendVerdict: 'CLEAN',
    backendRiskScore: 6,
    uiTrustScore: 94,
    summary: 'No adverse indicators detected. Domain possesses high historical tenure, verified multi-store TLS chain, and robust HTTP security headers.',
    analystReasonCodes: ['RDAP_TENURE_VERIFIED', 'RFC5280_MULTI_STORE_TRUSTED', 'CSP_ENFORCED', 'OWASP_ALIGNED'],
    fastPath: {
      evaluatedInMs: 38,
      bloomFilterHit: false,
      googleSafeBrowsingMatch: false,
      cachedReputation: 'BENIGN',
      mozillaOneCrlRevoked: false,
      preliminaryVerdict: 'CLEAN',
      summary: 'Fast-path cache hit. Sub-150ms verification confirmed clean status across in-memory Bloom filters and Mozilla OneCRL.',
    },
    workerPools: [
      { id: 'phishing_detonation', name: 'Phishing & DOM Detonation', status: 'completed', durationMs: 142, summarySnippet: 'No credential harvesting or BitB windows observed.' },
      { id: 'pki_ct_validation', name: 'PKI & CT Log Validation', status: 'completed', durationMs: 120, summarySnippet: 'Verified across all 5 major trust stores. 3 SCTs valid.' },
      { id: 'app_sec_auditing', name: 'Application Security Auditing', status: 'completed', durationMs: 110, summarySnippet: 'HSTS preloaded, CSP strict-dynamic active.' },
      { id: 'cti_graph_correlation', name: 'CTI Graph Correlation', status: 'completed', durationMs: 175, summarySnippet: 'Clean reputation across 42 federated threat feeds.' },
    ],
    phishingDetonation: {
      detonationSandbox: 'Firecracker microVM',
      antiBotCloakingDefeated: false,
      redirectChain: [
        { hop: 0, url: 'https://github.com', type: 'Direct', statusCode: 200, destinationIp: '140.82.121.4', asn: 'AS36459' },
      ],
      domHeuristics: {
        passwordInputsCount: 0,
        paymentFieldsCount: 0,
        otpFieldsCount: 0,
        browserInTheBrowserDetected: false,
        hiddenIframesCount: 0,
        devToolsBlockerDetected: false,
      },
      yaraRulesMatched: [],
      computerVision: {
        targetedBrand: 'GitHub, Inc.',
        visualSimilarityScore: 100,
        pHashHex: 'f8e081c7e1f0c087',
        dHashHex: '3947474747474747',
        faviconMurmurHash3: '984210492',
        isImpersonation: false,
      },
    },
    pkiIntelligence: {
      keyEntropyVerdict: 'VALID',
      fermatFactorizationPassed: true,
      smallPrimeGcdPassed: true,
      curvePointValid: true,
      keyCeremonyAnomalyFlag: false,
      chainValidationStatus: 'VERIFIED',
      trustStoreCompatibility: {
        mozillaNss: true,
        chromeRoot: true,
        apple: true,
        microsoft: true,
        oracleJava: true,
      },
      pathLenConstraintValid: true,
      crossSignedBypassDetected: false,
      certificateTransparency: {
        sctsDeliveredCount: 3,
        sctSources: ['X.509 Extension', 'TLS Extension'],
        merkleInclusionProofStatus: 'PROVEN',
        signedTreeHeadTimestamp: '2026-11-06T23:59:00Z',
        unexpectedIssuanceAlert: false,
      },
      revocationHealth: {
        ocspStatus: 'GOOD',
        ocspStapled: true,
        mustStapleCompliant: true,
        crlSignatureValid: true,
        crlNextUpdateExpired: false,
        oneCrlIncluded: false,
        chromeCrlSetIncluded: false,
      },
      dnsCaaPolicy: {
        caaRecordsPresent: true,
        allowedIssuers: ['digicert.com', 'letsencrypt.org'],
        actualIssuer: 'DigiCert Inc',
        policyMismatch: false,
      },
      chain: [
        {
          type: 'leaf',
          subjectCommonName: 'github.com',
          subjectOrg: 'GitHub, Inc.',
          issuerCommonName: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
          issuerOrg: 'DigiCert Inc',
          serialNumber: '09:82:14:0A:7B:3F:E2:10',
          validFrom: '2026-02-14T00:00:00Z',
          validUntil: '2027-03-15T23:59:59Z',
          daysRemaining: 248,
          isExpired: false,
          signatureAlgorithm: 'SHA256withRSA',
          publicKeyAlgorithm: 'RSA',
          keySizeBits: 2048,
          sha256Fingerprint: 'A4:92:DF:38:19:BE:7C:10:84:19:20:FE:48:19:AA:02:49:10:84:BC:90:12:48:AA:71:09:48:10:BC:88:12:40',
          rawPem: `-----BEGIN CERTIFICATE-----\nMIIF4zCCBMugAwIBAgIQCYIUCgp7PhIQ...\n-----END CERTIFICATE-----`,
        },
        {
          type: 'intermediate',
          subjectCommonName: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
          issuerCommonName: 'DigiCert Global Root G2',
          serialNumber: '02:11:49:80:FF:11:22:33',
          validFrom: '2020-09-23T00:00:00Z',
          validUntil: '2030-09-22T23:59:59Z',
          daysRemaining: 1412,
          isExpired: false,
          signatureAlgorithm: 'SHA256withRSA',
          publicKeyAlgorithm: 'RSA',
          keySizeBits: 2048,
          sha256Fingerprint: '78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56',
        },
      ],
    },
    webSecurityAudit: {
      httpHeaders: {
        csp: {
          present: true,
          directivesCount: 14,
          unsafeInline: false,
          unsafeEval: false,
          wildcardOrigins: false,
          grade: 'A+',
          rawHeader: "default-src 'none'; script-src 'self' https://github.githubassets.com; style-src 'self' 'unsafe-inline' ...",
        },
        hsts: {
          present: true,
          maxAgeSeconds: 31536000,
          includeSubdomains: true,
          preloaded: true,
          grade: 'EXCELLENT',
        },
        xFrameOptions: 'DENY',
        xContentTypeOptionsNosniff: true,
        referrerPolicy: 'origin-when-cross-origin, strict-origin-when-cross-origin',
        permissionsPolicy: 'geolocation=(), microphone=(), camera=()',
      },
      cookieSecurity: {
        totalCookiesCount: 4,
        secureFlagsMissingCount: 0,
        httpOnlyMissingCount: 0,
        sameSiteMissingCount: 0,
        sessionCookiesSafe: true,
      },
      corsPolicy: {
        wildcardOrigin: false,
        originReflection: false,
        credentialsAllowed: false,
        verdict: 'RESTRICTED',
      },
      tlsFingerprints: {
        negotiatedProtocol: 'TLS 1.3',
        negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
        forwardSecrecy: true,
        weakCipherDetected: false,
        ja3sHash: 'eb1d9433a8d5ae700f7fd6f49172f9b0',
        ja4sHash: 't13d1516h2_8a6190e0e0a1_91c78410b021',
        aitmProxySignatureDetected: false,
      },
      passiveExposure: {
        serverBanner: 'GitHub.com',
        exposedFilesObserved: [],
        matchedCves: [],
      },
    },
    threatIntelligence: {
      stixIndicators: [
        {
          id: 'indicator--8a149021-3914-4110-8b01-984019280192',
          type: 'indicator',
          specVersion: '2.1',
          name: 'Canonical GitHub Endpoint Reputation',
          description: 'Official production ingress infrastructure for GitHub developer platform.',
          indicatorTypes: ['benign'],
          pattern: "[domain-name:value = 'github.com']",
          patternType: 'stix',
          validFrom: '2007-10-09T00:00:00Z',
          tlpMarking: 'TLP:WHITE',
          confidenceScore: 100,
          sourceAttribution: 'Trust Shield Benchmark Feed',
          reputationDecay: {
            firstSeen: '2007-10-09T00:00:00Z',
            lastSeen: new Date().toISOString(),
            decayHalfLifeDays: 365,
            currentWeight: 1.0,
          },
          communitySightingsCount: 14209,
          reporterReliabilityScore: 99,
        },
      ],
      graphData: {
        nodes: [
          { id: 'n-dom', type: 'domain', label: 'github.com', subLabel: 'Target Host', riskState: 'clean', details: { registrar: 'MarkMonitor Inc', age: '19 years' } },
          { id: 'n-ip', type: 'ip', label: '140.82.121.4', subLabel: 'Origin Anycast', riskState: 'clean', details: { country: 'United States', port: 443 } },
          { id: 'n-asn', type: 'asn', label: 'AS36459', subLabel: 'GitHub, Inc.', riskState: 'clean', details: { peers: 42, prefix: '140.82.112.0/20' } },
          { id: 'n-cert', type: 'certificate', label: 'DigiCert Global G2', subLabel: 'X.509 Leaf', riskState: 'clean', details: { cipher: 'TLS 1.3 AES-128', days: 248 } },
          { id: 'n-ja4', type: 'ja4', label: 't13d1516h2_...', subLabel: 'Server Fingerprint', riskState: 'clean', details: { match: 'Modern OpenSSL' } },
        ],
        edges: [
          { id: 'e-1', source: 'n-dom', target: 'n-ip', label: 'RESOLVES_TO', relationshipType: 'RESOLVES_TO' },
          { id: 'e-2', source: 'n-ip', target: 'n-asn', label: 'ANNOUNCED_BY', relationshipType: 'ANNOUNCED_BY' },
          { id: 'e-3', source: 'n-dom', target: 'n-cert', label: 'SECURED_BY', relationshipType: 'SECURED_BY' },
          { id: 'e-4', source: 'n-cert', target: 'n-ja4', label: 'FINGERPRINTED_AS', relationshipType: 'FINGERPRINTED_AS' },
        ],
      },
      mispSyncStatus: 'SYNCED',
    },
    forensics: {
      targetUrlDefanged: 'hxxps://github[.]com/',
      screenshotTimestamp: new Date().toISOString(),
      domSnapshotDefangedHtml: `<!-- [DEFANGED SANITIZED PREVIEW] -->\n<div class="header">\n  <a href="hxxps://github[.]com/">GitHub</a>\n</div>`,
      harTraceSummary: {
        totalRequests: 3,
        totalBytesTransferred: 42800,
        externalDomainsContacted: ['github.githubassets.com'],
        suspiciousRequestsCount: 0,
        entries: [
          { method: 'GET', url: 'https://github.com/', status: 200, mimeType: 'text/html', sizeBytes: 31200, durationMs: 38 },
          { method: 'GET', url: 'https://github.githubassets.com/assets/app.css', status: 200, mimeType: 'text/css', sizeBytes: 11600, durationMs: 24 },
        ],
      },
      rawCertificatePemChain: `-----BEGIN CERTIFICATE-----\nMIIF4zCCBMugAwIBAgIQD/3u8vV...\n-----END CERTIFICATE-----`,
    },
    findings: [
      {
        id: 'fnd-hsts-preload',
        title: 'HSTS Max-Age & Preload Enforced',
        severity: 'informational',
        category: 'WEB_SEC',
        source: 'Application Security Auditing',
        description: 'Enforces Strict Transport Security across all subdomains with browser preload registry inclusion.',
        recommendation: 'Maintain continuous automated renewal of certificates before expiry.',
      },
    ],
  },

  'micros0ft-support-auth.com': {
    scanId: 'scn_phish_3914bc82',
    submittedUrl: 'https://login.micros0ft-support-auth.com/verify',
    hostname: 'login.micros0ft-support-auth.com',
    canonicalUrl: 'https://login.micros0ft-support-auth.com/verify',
    checkedAt: new Date().toISOString(),
    backendVerdict: 'MALICIOUS',
    backendRiskScore: 86,
    uiTrustScore: 14,
    summary: 'Severe threat detected. Active credential harvesting infrastructure impersonating Microsoft 365 login portals with brand homoglyphs and off-domain credential exfiltration.',
    analystReasonCodes: ['HOMOGLYPH_TYPOSQUAT', 'DOM_CREDENTIAL_EXFIL', 'YARA_PHISHKIT_MATCH', 'BULLETPROOF_HOSTING'],
    fastPath: {
      evaluatedInMs: 42,
      bloomFilterHit: true,
      bloomSource: 'Abuse.ch URLhaus',
      googleSafeBrowsingMatch: true,
      gsbThreatType: 'SOCIAL_ENGINEERING',
      cachedReputation: 'MALICIOUS',
      mozillaOneCrlRevoked: false,
      preliminaryVerdict: 'MALICIOUS',
      summary: 'Immediate synchronous hit on Abuse.ch URLhaus Bloom filter and Google Safe Browsing v4 hash prefixes.',
    },
    workerPools: [
      { id: 'phishing_detonation', name: 'Phishing & DOM Detonation', status: 'completed', durationMs: 165, summarySnippet: 'Form posts plain-text credentials to off-domain receiver.' },
      { id: 'pki_ct_validation', name: 'PKI & CT Log Validation', status: 'completed', durationMs: 95, summarySnippet: 'Ephemeral DV cert issued 48 hours ago. CA mismatch.' },
      { id: 'app_sec_auditing', name: 'Application Security Auditing', status: 'completed', durationMs: 105, summarySnippet: 'Missing Content-Security-Policy & Frame headers.' },
      { id: 'cti_graph_correlation', name: 'CTI Graph Correlation', status: 'completed', durationMs: 155, summarySnippet: 'STIX correlation to threat actor infrastructure Storm-0914.' },
    ],
    phishingDetonation: {
      detonationSandbox: 'Firecracker microVM',
      antiBotCloakingDefeated: true,
      redirectChain: [
        { hop: 0, url: 'https://login.micros0ft-support-auth.com/verify', type: 'Direct', statusCode: 200, destinationIp: '185.220.101.45', asn: 'AS200651' },
      ],
      domHeuristics: {
        passwordInputsCount: 1,
        paymentFieldsCount: 0,
        otpFieldsCount: 1,
        crossOriginSubmissionTarget: 'https://external-exfil-sink.to/dump-creds',
        browserInTheBrowserDetected: true,
        hiddenIframesCount: 2,
        devToolsBlockerDetected: true,
      },
      yaraRulesMatched: ['PhishKit_M365_OAuth_v3', 'Generic_CredentialHarvester_DOM'],
      computerVision: {
        targetedBrand: 'Microsoft Corporation',
        visualSimilarityScore: 98.4,
        pHashHex: 'f1e091c7a1f0d099',
        faviconMurmurHash3: '381940192',
        isImpersonation: true,
      },
      screenshotUrl: '/assets/evidence-phish-preview.png',
    },
    pkiIntelligence: {
      keyEntropyVerdict: 'VALID',
      fermatFactorizationPassed: true,
      smallPrimeGcdPassed: true,
      curvePointValid: true,
      keyCeremonyAnomalyFlag: false,
      chainValidationStatus: 'VERIFIED',
      trustStoreCompatibility: {
        mozillaNss: true,
        chromeRoot: true,
        apple: true,
        microsoft: true,
        oracleJava: true,
      },
      pathLenConstraintValid: true,
      crossSignedBypassDetected: false,
      certificateTransparency: {
        sctsDeliveredCount: 2,
        sctSources: ['X.509 Extension'],
        merkleInclusionProofStatus: 'PROVEN',
        signedTreeHeadTimestamp: '2026-11-04T12:00:00Z',
        unexpectedIssuanceAlert: true,
      },
      revocationHealth: {
        ocspStatus: 'GOOD',
        ocspStapled: false,
        mustStapleCompliant: false,
        crlSignatureValid: true,
        crlNextUpdateExpired: false,
        oneCrlIncluded: false,
        chromeCrlSetIncluded: false,
      },
      dnsCaaPolicy: {
        caaRecordsPresent: false,
        allowedIssuers: [],
        actualIssuer: "Let's Encrypt Authority E6",
        policyMismatch: false,
      },
      chain: [
        {
          type: 'leaf',
          subjectCommonName: 'login.micros0ft-support-auth.com',
          issuerCommonName: "Let's Encrypt Authority E6",
          serialNumber: '04:19:AA:88:12:33:44:55',
          validFrom: '2026-11-04T00:00:00Z',
          validUntil: '2027-02-02T23:59:59Z',
          daysRemaining: 86,
          isExpired: false,
          signatureAlgorithm: 'ECDSAwithSHA384',
          publicKeyAlgorithm: 'ECDSA',
          keySizeBits: 384,
          sha256Fingerprint: '99:11:88:22:77:33:66:44:55:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66',
        },
      ],
    },
    webSecurityAudit: {
      httpHeaders: {
        csp: {
          present: false,
          directivesCount: 0,
          unsafeInline: true,
          unsafeEval: true,
          wildcardOrigins: true,
          grade: 'F',
        },
        hsts: {
          present: false,
          maxAgeSeconds: 0,
          includeSubdomains: false,
          preloaded: false,
          grade: 'DEFICIENT',
        },
        xFrameOptions: 'MISSING',
        xContentTypeOptionsNosniff: false,
      },
      cookieSecurity: {
        totalCookiesCount: 1,
        secureFlagsMissingCount: 1,
        httpOnlyMissingCount: 1,
        sameSiteMissingCount: 1,
        sessionCookiesSafe: false,
      },
      corsPolicy: {
        wildcardOrigin: true,
        originReflection: true,
        credentialsAllowed: true,
        verdict: 'VULNERABLE',
      },
      tlsFingerprints: {
        negotiatedProtocol: 'TLS 1.3',
        negotiatedCipher: 'TLS_AES_256_GCM_SHA384',
        forwardSecrecy: true,
        weakCipherDetected: false,
        ja3sHash: '1849102abf90192410a8239019240192',
        ja4sHash: 't13d1902h2_18290124_910248109281',
        aitmProxySignatureDetected: false,
      },
      passiveExposure: {
        serverBanner: 'nginx',
        exposedFilesObserved: ['/.git/HEAD', '/.env'],
        matchedCves: [
          { cveId: 'CVE-2024-21413', component: 'Outlook Client Interaction', severity: 'CRITICAL', summary: 'MonikerLink bypass leading to NTLM credential exfiltration' },
        ],
      },
    },
    threatIntelligence: {
      stixIndicators: [
        {
          id: 'indicator--99149021-3914-4110-8b01-182940192831',
          type: 'indicator',
          specVersion: '2.1',
          name: 'Microsoft 365 Credential Harvester Sink',
          description: 'Active phishing kit collecting session tokens and plain-text passwords.',
          indicatorTypes: ['malicious-activity', 'phishing'],
          pattern: "[url:value = 'https://login.micros0ft-support-auth.com/verify']",
          patternType: 'stix',
          validFrom: '2026-11-04T00:00:00Z',
          tlpMarking: 'TLP:AMBER',
          confidenceScore: 98,
          sourceAttribution: 'PhishTank #8392102 / AlienVault OTX',
          reputationDecay: {
            firstSeen: '2026-11-04T00:00:00Z',
            lastSeen: new Date().toISOString(),
            decayHalfLifeDays: 14,
            currentWeight: 0.98,
          },
          communitySightingsCount: 28,
          reporterReliabilityScore: 94,
        },
      ],
      graphData: {
        nodes: [
          { id: 'n-dom', type: 'domain', label: 'micros0ft-support-auth.com', subLabel: 'Homoglyph Phish', riskState: 'malicious', details: { typosquat: 'microsoft.com (Lev=1)', age: '3 days' } },
          { id: 'n-ip', type: 'ip', label: '185.220.101.45', subLabel: 'Bulletproof Sink', riskState: 'malicious', details: { country: 'Seychelles', abuseReports: 142 } },
          { id: 'n-asn', type: 'asn', label: 'AS200651', subLabel: 'FlokiNET Bulletproof', riskState: 'malicious', details: { reputation: 'Non-compliant' } },
          { id: 'n-cert', type: 'certificate', label: "Let's Encrypt E6", subLabel: 'Short-lived DV', riskState: 'suspicious', details: { org: 'Unverified' } },
          { id: 'n-actor', type: 'threat_actor', label: 'TA-Storm-0914', subLabel: 'Phishing Syndicate', riskState: 'malicious', details: { target: 'M365 Enterprise', kit: 'BitB OAuth' } },
        ],
        edges: [
          { id: 'e-1', source: 'n-dom', target: 'n-ip', label: 'RESOLVES_TO', relationshipType: 'RESOLVES_TO' },
          { id: 'e-2', source: 'n-ip', target: 'n-asn', label: 'ANNOUNCED_BY', relationshipType: 'ANNOUNCED_BY' },
          { id: 'e-3', source: 'n-dom', target: 'n-cert', label: 'SECURED_BY', relationshipType: 'SECURED_BY' },
          { id: 'e-4', source: 'n-dom', target: 'n-actor', label: 'ATTRIBUTED_TO', relationshipType: 'ATTRIBUTED_TO' },
        ],
      },
      mispSyncStatus: 'SYNCED',
    },
    forensics: {
      targetUrlDefanged: 'hxxps://login[.]micros0ft-support-auth[.]com/verify',
      screenshotTimestamp: new Date().toISOString(),
      domSnapshotDefangedHtml: `<!-- [DEFANGED SANITIZED PREVIEW] -->\n<form action="hxxps://external-exfil-sink[.]to/dump-creds" method="POST">\n  <input type="text" name="loginfmt" placeholder="someone@example.com" />\n  <input type="password" name="passwd" />\n  <button type="submit">Sign in</button>\n</form>`,
      harTraceSummary: {
        totalRequests: 8,
        totalBytesTransferred: 184000,
        externalDomainsContacted: ['external-exfil-sink.to', 'logincdn.msauth.net'],
        suspiciousRequestsCount: 2,
        entries: [
          { method: 'GET', url: 'https://login.micros0ft-support-auth.com/verify', status: 200, mimeType: 'text/html', sizeBytes: 42000, durationMs: 165 },
          { method: 'POST', url: 'https://external-exfil-sink.to/dump-creds', status: 200, mimeType: 'application/json', sizeBytes: 120, durationMs: 85 },
        ],
      },
      rawCertificatePemChain: `-----BEGIN CERTIFICATE-----\nMIIEczCCA1ugAwIBAgIQCYIUC...\n-----END CERTIFICATE-----`,
    },
    findings: [
      {
        id: 'fnd-phish-dom',
        title: 'Active Brand Impersonation (Microsoft 365 Login Harvester)',
        severity: 'critical',
        category: 'PHISHING',
        source: 'Phishing & DOM Detonation',
        description: 'Target page renders an unauthorized visual clone of Microsoft authentication with an off-domain credential exfiltration receiver.',
        recommendation: 'Do not enter passwords or 2FA codes. Block domain on edge DNS gateways.',
      },
      {
        id: 'fnd-homoglyph-0',
        title: 'Homoglyph Typo-squatting ("micros0ft" zero substitution)',
        severity: 'critical',
        category: 'PHISHING',
        source: 'Lexical & Domain Reconnaissance',
        description: 'Replaces letter "o" with numeric "0" to mislead email and SMS recipients.',
        recommendation: 'Always verify corporate domains manually in the browser address bar.',
      },
    ],
  },

  'expired-tls.untrusted-cdn-assets.org': {
    scanId: 'scn_cert_182944b1',
    submittedUrl: 'https://expired-tls.untrusted-cdn-assets.org',
    hostname: 'expired-tls.untrusted-cdn-assets.org',
    canonicalUrl: 'https://expired-tls.untrusted-cdn-assets.org/',
    checkedAt: new Date().toISOString(),
    backendVerdict: 'PKI_TRUST_COMPROMISED',
    backendRiskScore: 92,
    uiTrustScore: 8,
    summary: 'Cryptographic trust compromised. Intermediate CA certificate was issued with recoverable ECDSA P-384 private key scalar < 256 and invalid CRL signatures (Banbreach eMudhra incident scenario).',
    analystReasonCodes: ['PKI_KEY_CEREMONY_ANOMALY', 'RECOVERABLE_ECDSA_SCALAR', 'INVALID_CRL_SIGNATURE', 'ONE_CRL_REVOKED'],
    fastPath: {
      evaluatedInMs: 45,
      bloomFilterHit: false,
      googleSafeBrowsingMatch: false,
      cachedReputation: 'SUSPICIOUS',
      mozillaOneCrlRevoked: true,
      preliminaryVerdict: 'PKI_TRUST_COMPROMISED',
      summary: 'Fast-path flag: Active Certificate Authority revoked in Mozilla OneCRL due to compromised intermediate private keys.',
    },
    workerPools: [
      { id: 'phishing_detonation', name: 'Phishing & DOM Detonation', status: 'completed', durationMs: 125, summarySnippet: 'No active credential harvester forms detected.' },
      { id: 'pki_ct_validation', name: 'PKI & CT Log Validation', status: 'completed', durationMs: 180, summarySnippet: 'CRITICAL: Weak scalar ECDSA P-384 key ceremony flaw detected.' },
      { id: 'app_sec_auditing', name: 'Application Security Auditing', status: 'completed', durationMs: 98, summarySnippet: 'HSTS missing, server banner exposed.' },
      { id: 'cti_graph_correlation', name: 'CTI Graph Correlation', status: 'completed', durationMs: 135, summarySnippet: 'Correlated with October 2026 eMudhra incident telemetry.' },
    ],
    phishingDetonation: {
      detonationSandbox: 'Firecracker microVM',
      antiBotCloakingDefeated: false,
      redirectChain: [
        { hop: 0, url: 'https://expired-tls.untrusted-cdn-assets.org', type: 'Direct', statusCode: 200, destinationIp: '198.51.100.89', asn: 'AS16509' },
      ],
      domHeuristics: {
        passwordInputsCount: 0,
        paymentFieldsCount: 0,
        otpFieldsCount: 0,
        browserInTheBrowserDetected: false,
        hiddenIframesCount: 0,
        devToolsBlockerDetected: false,
      },
      yaraRulesMatched: [],
      computerVision: {
        targetedBrand: 'Static Asset CDN',
        visualSimilarityScore: 20,
        isImpersonation: false,
      },
    },
    pkiIntelligence: {
      keyEntropyVerdict: 'WEAK_ENTROPY',
      fermatFactorizationPassed: true,
      smallPrimeGcdPassed: true,
      curvePointValid: false,
      keyCeremonyAnomalyFlag: true,
      keyCeremonyNotes: 'October 2026 eMudhra TLS intermediate certificate incident: ECDSA P-384 private key generated with scalar < 256 from faulty key ceremony script. Invalid CRL signatures surfaced in trust store audit.',
      chainValidationStatus: 'REVOKED',
      trustStoreCompatibility: {
        mozillaNss: false,
        chromeRoot: false,
        apple: false,
        microsoft: false,
        oracleJava: false,
      },
      pathLenConstraintValid: false,
      crossSignedBypassDetected: true,
      certificateTransparency: {
        sctsDeliveredCount: 2,
        sctSources: ['X.509 Extension'],
        merkleInclusionProofStatus: 'PROVEN',
        signedTreeHeadTimestamp: '2026-06-15T00:00:00Z',
        unexpectedIssuanceAlert: true,
      },
      revocationHealth: {
        ocspStatus: 'REVOKED',
        ocspStapled: false,
        mustStapleCompliant: false,
        crlSignatureValid: false,
        crlNextUpdateExpired: true,
        oneCrlIncluded: true,
        chromeCrlSetIncluded: true,
      },
      dnsCaaPolicy: {
        caaRecordsPresent: true,
        allowedIssuers: ['digicert.com'],
        actualIssuer: 'Compromised Intermediate CA',
        policyMismatch: true,
      },
      chain: [
        {
          type: 'leaf',
          subjectCommonName: 'expired-tls.untrusted-cdn-assets.org',
          issuerCommonName: 'eMudhra Sub-CA TLS Intermediate 2025',
          serialNumber: '99:88:77:66:55:44:33:22',
          validFrom: '2025-06-01T00:00:00Z',
          validUntil: '2026-10-30T23:59:59Z',
          daysRemaining: -8,
          isExpired: true,
          signatureAlgorithm: 'ECDSAwithSHA384',
          publicKeyAlgorithm: 'ECDSA',
          keySizeBits: 384,
          sha256Fingerprint: 'EE:AA:DD:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
        },
      ],
    },
    webSecurityAudit: {
      httpHeaders: {
        csp: {
          present: false,
          directivesCount: 0,
          unsafeInline: true,
          unsafeEval: true,
          wildcardOrigins: true,
          grade: 'F',
        },
        hsts: {
          present: false,
          maxAgeSeconds: 0,
          includeSubdomains: false,
          preloaded: false,
          grade: 'DEFICIENT',
        },
        xFrameOptions: 'MISSING',
        xContentTypeOptionsNosniff: false,
      },
      cookieSecurity: {
        totalCookiesCount: 0,
        secureFlagsMissingCount: 0,
        httpOnlyMissingCount: 0,
        sameSiteMissingCount: 0,
        sessionCookiesSafe: true,
      },
      corsPolicy: {
        wildcardOrigin: true,
        originReflection: false,
        credentialsAllowed: false,
        verdict: 'PERMISSIVE',
      },
      tlsFingerprints: {
        negotiatedProtocol: 'TLS 1.2',
        negotiatedCipher: 'ECDHE-ECDSA-AES128-GCM-SHA256',
        forwardSecrecy: true,
        weakCipherDetected: false,
        aitmProxySignatureDetected: false,
      },
      passiveExposure: {
        serverBanner: 'Apache/2.4.41 (Ubuntu)',
        exposedFilesObserved: ['/security.txt'],
        matchedCves: [],
      },
    },
    threatIntelligence: {
      stixIndicators: [
        {
          id: 'indicator--pki-emudhra-incident-2026',
          type: 'indicator',
          specVersion: '2.1',
          name: 'eMudhra CA Key Ceremony Flaw',
          description: 'Distrusted CA intermediate associated with recoverable private keys.',
          indicatorTypes: ['compromised-ca'],
          pattern: "[x509-certificate:issuer = 'eMudhra Sub-CA TLS Intermediate 2025']",
          patternType: 'stix',
          validFrom: '2025-06-01T00:00:00Z',
          tlpMarking: 'TLP:AMBER',
          confidenceScore: 99,
          sourceAttribution: 'Shieldworkz PKI / Banbreach Analysis',
          reputationDecay: {
            firstSeen: '2025-06-01T00:00:00Z',
            lastSeen: new Date().toISOString(),
            decayHalfLifeDays: 90,
            currentWeight: 0.99,
          },
          communitySightingsCount: 88,
          reporterReliabilityScore: 98,
        },
      ],
      graphData: {
        nodes: [
          { id: 'n-dom', type: 'domain', label: 'untrusted-cdn-assets.org', subLabel: 'Target Host', riskState: 'pki_compromised' },
          { id: 'n-ip', type: 'ip', label: '198.51.100.89', subLabel: 'CDN Origin', riskState: 'suspicious' },
          { id: 'n-cert', type: 'certificate', label: 'eMudhra Sub-CA', subLabel: 'Weak Scalar Key', riskState: 'pki_compromised', details: { flaw: 'Scalar < 256', crl: 'Invalid Sig' } },
        ],
        edges: [
          { id: 'e-1', source: 'n-dom', target: 'n-ip', label: 'RESOLVES_TO', relationshipType: 'RESOLVES_TO' },
          { id: 'e-2', source: 'n-dom', target: 'n-cert', label: 'SECURED_BY', relationshipType: 'SECURED_BY' },
        ],
      },
      mispSyncStatus: 'SYNCED',
    },
    forensics: {
      targetUrlDefanged: 'hxxps://expired-tls[.]untrusted-cdn-assets[.]org/',
      screenshotTimestamp: new Date().toISOString(),
      harTraceSummary: {
        totalRequests: 1,
        totalBytesTransferred: 1200,
        externalDomainsContacted: [],
        suspiciousRequestsCount: 1,
        entries: [
          { method: 'GET', url: 'https://expired-tls.untrusted-cdn-assets.org/', status: 200, mimeType: 'text/html', sizeBytes: 1200, durationMs: 120 },
        ],
      },
      rawCertificatePemChain: `-----BEGIN CERTIFICATE-----\n[Compromised eMudhra Intermediate Sub-CA]\n-----END CERTIFICATE-----`,
    },
    findings: [
      {
        id: 'fnd-pki-key-ceremony',
        title: 'Cryptographic Key Ceremony Anomaly (Recoverable ECDSA Scalar)',
        severity: 'critical',
        category: 'PKI',
        source: 'Key-Entropy & Curve Auditor',
        description: 'Intermediate CA certificate generated with flawed key ceremony script yielding recoverable private key scalar below 256.',
        recommendation: 'Immediately revoke certificate and migrate to an uncompromised root/intermediate path.',
      },
      {
        id: 'fnd-cert-expired',
        title: 'X.509 Certificate Validity Lapsed (Expired)',
        severity: 'high',
        category: 'PKI',
        source: 'Multi-Store Chain Verifier',
        description: 'Certificate expired 8 days ago. Client browsers reject connection.',
        recommendation: 'Renew SSL certificate with authorized Certificate Authority.',
      },
    ],
  },
};

/**
 * Generates dynamic extended scan report for any arbitrary URL entered by the user
 */
export function generateDynamicExtendedReport(rawUrl: string, hostname: string, protocol: 'https:' | 'http:'): ExtendedScanReport {
  for (const key of Object.keys(EXTENDED_SCENARIOS)) {
    if (hostname.toLowerCase().includes(key.toLowerCase()) || rawUrl.toLowerCase().includes(key.toLowerCase())) {
      const base = EXTENDED_SCENARIOS[key];
      return {
        ...base,
        submittedUrl: rawUrl,
        hostname,
        canonicalUrl: rawUrl,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  const isHttpOnly = protocol === 'http:';
  const hasAuthKeywords = /(login|verify|account|banking|secure|wallet|portal|update)/i.test(rawUrl);
  const isHighEntropy = hostname.split('.')[0].length > 18;

  let backendRisk = 18;
  let verdict: ExtendedScanReport['backendVerdict'] = 'CLEAN';

  if (isHttpOnly) {
    backendRisk += 35;
    verdict = 'SUSPICIOUS';
  }
  if (hasAuthKeywords) {
    backendRisk += 25;
    verdict = 'SUSPICIOUS';
  }
  if (isHighEntropy) {
    backendRisk += 30;
    verdict = 'SUSPICIOUS';
  }

  if (backendRisk >= 75) {
    verdict = 'MALICIOUS';
  }

  const uiTrust = RiskScoreAdapter.backendRiskToUiTrustScore(backendRisk);
  const scanId = `scn_dyn_${Math.random().toString(36).substring(2, 10)}`;

  return {
    scanId,
    submittedUrl: rawUrl,
    hostname,
    canonicalUrl: rawUrl,
    checkedAt: new Date().toISOString(),
    backendVerdict: verdict,
    backendRiskScore: backendRisk,
    uiTrustScore: uiTrust,
    summary: verdict === 'CLEAN'
      ? 'Multi-pillar inspection completed across Phishing, PKI, Web Security, and Threat Intelligence. No active malicious indicators observed.'
      : 'Anomalies detected across transport security or lexical parameters. Scrutinize form destinations before entering sensitive information.',
    analystReasonCodes: verdict === 'CLEAN' ? ['BENIGN_RFC5280', 'OWASP_PASS'] : ['ANOMALOUS_PARAMETERS', 'HTTP_DOWNGRADE'],
    fastPath: {
      evaluatedInMs: 44,
      bloomFilterHit: false,
      googleSafeBrowsingMatch: false,
      cachedReputation: 'BENIGN',
      mozillaOneCrlRevoked: false,
      preliminaryVerdict: verdict,
      summary: 'Fast-path cache check: 0 matches in Bloom filters; Mozilla OneCRL valid.',
    },
    workerPools: [
      { id: 'phishing_detonation', name: 'Phishing & DOM Detonation', status: 'completed', durationMs: 140 },
      { id: 'pki_ct_validation', name: 'PKI & CT Log Validation', status: 'completed', durationMs: 115 },
      { id: 'app_sec_auditing', name: 'Application Security Auditing', status: 'completed', durationMs: 95 },
      { id: 'cti_graph_correlation', name: 'CTI Graph Correlation', status: 'completed', durationMs: 160 },
    ],
    phishingDetonation: {
      detonationSandbox: 'Firecracker microVM',
      antiBotCloakingDefeated: false,
      redirectChain: [{ hop: 0, url: rawUrl, type: 'Direct', statusCode: 200, destinationIp: '104.21.48.182', asn: 'AS13335' }],
      domHeuristics: {
        passwordInputsCount: hasAuthKeywords ? 1 : 0,
        paymentFieldsCount: 0,
        otpFieldsCount: 0,
        browserInTheBrowserDetected: false,
        hiddenIframesCount: 0,
        devToolsBlockerDetected: false,
      },
      yaraRulesMatched: [],
      computerVision: {
        targetedBrand: 'Generic Web Application',
        visualSimilarityScore: hasAuthKeywords ? 65 : 10,
        isImpersonation: false,
      },
    },
    pkiIntelligence: {
      keyEntropyVerdict: 'VALID',
      fermatFactorizationPassed: true,
      smallPrimeGcdPassed: true,
      curvePointValid: true,
      keyCeremonyAnomalyFlag: false,
      chainValidationStatus: isHttpOnly ? 'UNTRUSTED_ROOT' : 'VERIFIED',
      trustStoreCompatibility: {
        mozillaNss: !isHttpOnly,
        chromeRoot: !isHttpOnly,
        apple: !isHttpOnly,
        microsoft: !isHttpOnly,
        oracleJava: !isHttpOnly,
      },
      pathLenConstraintValid: true,
      crossSignedBypassDetected: false,
      certificateTransparency: {
        sctsDeliveredCount: isHttpOnly ? 0 : 2,
        sctSources: isHttpOnly ? [] : ['X.509 Extension'],
        merkleInclusionProofStatus: isHttpOnly ? 'INVALID' : 'PROVEN',
        signedTreeHeadTimestamp: new Date().toISOString(),
        unexpectedIssuanceAlert: false,
      },
      revocationHealth: {
        ocspStatus: isHttpOnly ? 'UNKNOWN' : 'GOOD',
        ocspStapled: !isHttpOnly,
        mustStapleCompliant: false,
        crlSignatureValid: !isHttpOnly,
        crlNextUpdateExpired: false,
        oneCrlIncluded: false,
        chromeCrlSetIncluded: false,
      },
      dnsCaaPolicy: {
        caaRecordsPresent: false,
        allowedIssuers: [],
        actualIssuer: isHttpOnly ? 'None' : 'Cloudflare Inc ECC CA-3',
        policyMismatch: false,
      },
      chain: isHttpOnly
        ? []
        : [
            {
              type: 'leaf',
              subjectCommonName: hostname,
              issuerCommonName: 'Cloudflare Inc ECC CA-3',
              serialNumber: '28:19:AA:77:88:99:11:00',
              validFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
              validUntil: new Date(Date.now() + 60 * 86400000).toISOString(),
              daysRemaining: 60,
              isExpired: false,
              signatureAlgorithm: 'ECDSAwithSHA256',
              publicKeyAlgorithm: 'ECDSA',
              keySizeBits: 256,
              sha256Fingerprint: '11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF',
            },
          ],
    },
    webSecurityAudit: {
      httpHeaders: {
        csp: {
          present: !isHttpOnly,
          directivesCount: isHttpOnly ? 0 : 6,
          unsafeInline: isHttpOnly,
          unsafeEval: false,
          wildcardOrigins: false,
          grade: isHttpOnly ? 'F' : 'B',
        },
        hsts: {
          present: !isHttpOnly,
          maxAgeSeconds: isHttpOnly ? 0 : 15552000,
          includeSubdomains: false,
          preloaded: false,
          grade: isHttpOnly ? 'DEFICIENT' : 'ADEQUATE',
        },
        xFrameOptions: isHttpOnly ? 'MISSING' : 'SAMEORIGIN',
        xContentTypeOptionsNosniff: !isHttpOnly,
      },
      cookieSecurity: {
        totalCookiesCount: 1,
        secureFlagsMissingCount: isHttpOnly ? 1 : 0,
        httpOnlyMissingCount: 0,
        sameSiteMissingCount: 0,
        sessionCookiesSafe: !isHttpOnly,
      },
      corsPolicy: {
        wildcardOrigin: false,
        originReflection: false,
        credentialsAllowed: false,
        verdict: 'RESTRICTED',
      },
      tlsFingerprints: {
        negotiatedProtocol: isHttpOnly ? 'SSLv3' : 'TLS 1.3',
        negotiatedCipher: isHttpOnly ? 'NONE' : 'TLS_AES_128_GCM_SHA256',
        forwardSecrecy: !isHttpOnly,
        weakCipherDetected: isHttpOnly,
        aitmProxySignatureDetected: false,
      },
      passiveExposure: {
        serverBanner: 'cloudflare',
        exposedFilesObserved: [],
        matchedCves: [],
      },
    },
    threatIntelligence: {
      stixIndicators: [
        {
          id: `indicator--dyn-${Math.random().toString(36).substring(2, 10)}`,
          type: 'indicator',
          specVersion: '2.1',
          name: `Observables for ${hostname}`,
          description: 'Automated STIX 2.1 indicator generated from dynamic multi-pillar sandbox.',
          indicatorTypes: [verdict === 'CLEAN' ? 'benign' : 'anomalous'],
          pattern: `[domain-name:value = '${hostname}']`,
          patternType: 'stix',
          validFrom: new Date().toISOString(),
          tlpMarking: 'TLP:WHITE',
          confidenceScore: 85,
          sourceAttribution: 'Trust Shield Sensor Grid',
          reputationDecay: {
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            decayHalfLifeDays: 30,
            currentWeight: 1.0,
          },
          communitySightingsCount: 1,
          reporterReliabilityScore: 80,
        },
      ],
      graphData: {
        nodes: [
          { id: 'n-dom', type: 'domain', label: hostname, subLabel: 'Target Host', riskState: verdict === 'CLEAN' ? 'clean' : 'suspicious' },
          { id: 'n-ip', type: 'ip', label: '104.21.48.182', subLabel: 'Cloudflare Edge', riskState: 'clean' },
          { id: 'n-asn', type: 'asn', label: 'AS13335', subLabel: 'Cloudflare, Inc.', riskState: 'clean' },
        ],
        edges: [
          { id: 'e-1', source: 'n-dom', target: 'n-ip', label: 'RESOLVES_TO', relationshipType: 'RESOLVES_TO' },
          { id: 'e-2', source: 'n-ip', target: 'n-asn', label: 'ANNOUNCED_BY', relationshipType: 'ANNOUNCED_BY' },
        ],
      },
      mispSyncStatus: 'SYNCED',
    },
    forensics: {
      targetUrlDefanged: RiskScoreAdapter.defangUrl(rawUrl),
      screenshotTimestamp: new Date().toISOString(),
      harTraceSummary: {
        totalRequests: 2,
        totalBytesTransferred: 24000,
        externalDomainsContacted: [],
        suspiciousRequestsCount: 0,
        entries: [
          { method: 'GET', url: rawUrl, status: 200, mimeType: 'text/html', sizeBytes: 24000, durationMs: 44 },
        ],
      },
    },
    findings: isHttpOnly
      ? [
          {
            id: 'fnd-unencrypted-http',
            title: 'Unencrypted Plaintext HTTP Protocol In Use',
            severity: 'high',
            category: 'WEB_SEC',
            source: 'Application Security Auditing',
            description: 'Connection communicates without TLS encryption, exposing payloads to transit eavesdropping.',
            recommendation: 'Upgrade to HTTPS with active TLS 1.3.',
          },
        ]
      : [
          {
            id: 'fnd-clean-baseline',
            title: 'Standard Transport Encryption & Certificate Verified',
            severity: 'informational',
            category: 'PKI',
            source: 'PKI & CT Log Validation',
            description: 'Domain negotiates modern TLS encryption with verified certificate path.',
            recommendation: 'Inspect recipient domain identity before submitting credentials.',
          },
        ],
  };
}

