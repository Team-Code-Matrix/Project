import { ScanResult } from '../types/scan';

export const SAMPLE_SCENARIOS: Record<string, ScanResult> = {
  'github.com': {
    scanId: 'scn_gh_982410a7',
    submittedUrl: 'https://github.com',
    hostname: 'github.com',
    protocol: 'https:',
    score: 94,
    riskLevel: 'low',
    summary: 'No adverse indicators detected. Domain possesses high historical tenure, verified TLS chain, and robust HTTP security headers.',
    isDemo: true,
    criticalOverride: false,
    checksCompleted: 6,
    checksSkipped: 0,
    checksErrored: 0,
    checkedAt: new Date().toISOString(),
    resolvedIp: '140.82.121.4',
    asn: 'AS36459 (GitHub, Inc.)',
    country: 'United States',
    models: [
      {
        id: 'm-phish',
        number: '01',
        name: 'Phishing & Impersonation Detection',
        category: 'Brand & Form Integrity',
        description: 'Evaluates visual mimicry, brand asset similarity, and unauthorized credential intake endpoints.',
        verdict: 'clear',
        confidence: 99,
        summary: 'Matches official primary authority footprint for GitHub. No login mimicry or credential diversion detected.',
        executionTimeMs: 142,
        status: 'completed',
        evidence: [
          'DOM DOMAIN MATCH: Verified canonical brand asset signatures.',
          'FORM DESTINATION: All authentication actions map to verified first-party endpoints.',
          'BRAND REPUTATION: Tranco Top 100 benchmark verification confirmed.',
        ],
        metrics: [
          { label: 'Form Action Safety', value: 'First-party verified' },
          { label: 'Brand Divergence Index', value: '0.01 / 1.0 (Safe)' },
          { label: 'Visual Fingerprint Match', value: '100% Authentic' },
        ],
      },
      {
        id: 'm-domain',
        number: '02',
        name: 'Domain & Lexical Intelligence',
        category: 'Domain Reputation',
        description: 'Assesses registration age, registrar stability, lexical randomness, and typosquatting risk.',
        verdict: 'clear',
        confidence: 98,
        summary: 'Domain registered in October 2007 with stable MarkMonitor enterprise management.',
        executionTimeMs: 98,
        status: 'completed',
        evidence: [
          'DOMAIN AGE: 18+ years (Established October 9, 2007).',
          'REGISTRAR: MarkMonitor Inc. (Enterprise brand protection).',
          'LEXICAL ENTROPY: 2.12 (Low entropy, authentic dictionary stem).',
          'NAMESERVERS: dns1.p08.nsone.net, ns-1707.awsdns-21.co.uk.',
        ],
        metrics: [
          { label: 'Domain Age', value: '6,400+ days' },
          { label: 'Shannon Entropy', value: '2.12 (Normal)' },
          { label: 'DNSSEC Status', value: 'Active / Valid' },
        ],
      },
      {
        id: 'm-tls',
        number: '03',
        name: 'TLS Certificate & Chain Validation',
        category: 'Transport Security',
        description: 'Validates certificate authority pedigree, expiration, Subject Alternative Names, and cipher strength.',
        verdict: 'clear',
        confidence: 97,
        summary: 'Valid high-assurance certificate issued by DigiCert Global Root G2 using modern TLS 1.3 protocol.',
        executionTimeMs: 120,
        status: 'completed',
        evidence: [
          'ISSUER: DigiCert Global G2 TLS RSA SHA256 2020 CA1.',
          'VALIDITY: Active (Valid for 248 more days).',
          'SAN COVERAGE: github.com, www.github.com.',
          'CIPHER SUITE: TLS_AES_128_GCM_SHA256 (P-256 curve).',
          'CERTIFICATE TRANSPARENCY: Logged in 3 distinct SCT audit feeds.',
        ],
        metrics: [
          { label: 'Protocol Support', value: 'TLS 1.3 / TLS 1.2' },
          { label: 'Days Remaining', value: '248 days' },
          { label: 'Key Length', value: 'RSA 2048-bit' },
        ],
      },
      {
        id: 'm-redirect',
        number: '04',
        name: 'Redirect Chain Analysis',
        category: 'Routing Integrity',
        description: 'Traces initial request to terminal destination, flagging suspicious cross-domain routing hops.',
        verdict: 'clear',
        confidence: 96,
        summary: 'Clean HTTP 301 upgrade to canonical HTTPS endpoint with zero intermediary off-domain hops.',
        executionTimeMs: 85,
        status: 'completed',
        evidence: [
          'HOP 0: http://github.com -> 301 Moved Permanently.',
          'HOP 1: https://github.com -> 200 OK.',
          'OFF-DOMAIN TRANSITIONS: None detected.',
        ],
        metrics: [
          { label: 'Total Hops', value: '1' },
          { label: 'Cross-Domain Transitions', value: '0' },
          { label: 'Destination Consistency', value: 'Canonical match' },
        ],
      },
      {
        id: 'm-posture',
        number: '05',
        name: 'Web Security Posture',
        category: 'Configuration Hygiene',
        description: 'Examines HTTP defensive headers, Content Security Policy, and cookie security flags.',
        verdict: 'clear',
        confidence: 94,
        summary: 'Strict security headers implemented including HSTS with preload and comprehensive Content Security Policy.',
        executionTimeMs: 110,
        status: 'completed',
        evidence: [
          'HSTS: max-age=31536000; includeSubDomains; preload.',
          'CONTENT-SECURITY-POLICY: default-src \'none\'; script-src \'self\' ... (Enforced).',
          'X-CONTENT-TYPE-OPTIONS: nosniff.',
          'X-FRAME-OPTIONS: DENY.',
          'REFERRER-POLICY: origin-when-cross-origin, strict-origin-when-cross-origin.',
        ],
        metrics: [
          { label: 'HSTS Max-Age', value: '31,536,000s (Preloaded)' },
          { label: 'Frame Protection', value: 'DENY' },
          { label: 'CSP Strictness', value: 'Grade A+' },
        ],
      },
      {
        id: 'm-collab',
        number: '06',
        name: 'Collaborative Threat Intelligence',
        category: 'Collective Telemetry',
        description: 'Cross-references active threat intelligence feeds, honeypot telemetry, and community incident reports.',
        verdict: 'clear',
        confidence: 99,
        summary: 'Clean status across 42 verified threat intelligence feeds and zero malicious community incident reports.',
        executionTimeMs: 175,
        status: 'completed',
        evidence: [
          'FEED CROSS-REFERENCE: Checked Spamhaus, AlienVault OTX, PhishTank, and URLhaus.',
          'COMMUNITY VERDICTS: 0 negative flags recorded.',
          'HONEYPOT STATUS: Clean infrastructure reputation.',
        ],
        metrics: [
          { label: 'Feeds Queried', value: '42' },
          { label: 'Positive Matches', value: '0' },
          { label: 'Community Trust Score', value: '99.8%' },
        ],
      },
    ],
    findings: [
      {
        id: 'fnd-1',
        title: 'Strict Transport Security (HSTS) Active & Preloaded',
        severity: 'informational',
        source: 'Web Security Posture (M-05)',
        description: 'The domain declares a 1-year HSTS directive with includeSubDomains and preload registration, preventing SSL-stripping attacks.',
        evidence: [
          'Header value: max-age=31536000; includeSubDomains; preload',
          'Registered in Chromium HSTS preload list',
        ],
        recommendation: 'Maintain continuous automated renewal of certificates before expiry to prevent accidental domain lockouts.',
      },
      {
        id: 'fnd-2',
        title: 'Comprehensive Content Security Policy Enforced',
        severity: 'informational',
        source: 'Web Security Posture (M-05)',
        description: 'Restricts script execution sources and disallows unauthorized external asset injections.',
        evidence: ['CSP header present with nonce validation and strict-dynamic'],
        recommendation: 'Periodically review CSP violation reporting endpoints for policy tuning.',
      },
    ],
    recommendedActions: [
      {
        id: 'act-1',
        level: 'monitoring',
        title: 'Safe to interact',
        detail: 'The domain presents strong verified security posture. Standard user caution applies when interacting with third-party code repositories.',
        targetUser: 'all',
      },
      {
        id: 'act-2',
        level: 'advisory',
        title: 'Enable Multi-Factor Authentication',
        detail: 'Ensure hardware security keys or authenticator apps are active on user accounts.',
        targetUser: 'general',
      },
    ],
  },

  'micros0ft-support-auth.com': {
    scanId: 'scn_phish_3914bc82',
    submittedUrl: 'https://login.micros0ft-support-auth.com/verify',
    hostname: 'login.micros0ft-support-auth.com',
    protocol: 'https:',
    score: 14,
    riskLevel: 'critical',
    summary: 'Severe threat detected. Active credential harvesting infrastructure impersonating Microsoft 365 login portals with brand homoglyphs.',
    isDemo: true,
    criticalOverride: true,
    overrideReason: 'CRITICAL SECURITY THREAT DETECTED: Confirmed credential harvesting pattern detected with active typo-squatted brand impersonation. Do not enter credentials or MFA tokens under any circumstances.',
    checksCompleted: 6,
    checksSkipped: 0,
    checksErrored: 0,
    checkedAt: new Date().toISOString(),
    resolvedIp: '185.220.101.45',
    asn: 'AS200651 (FlokiNET Bulletproof Hosting)',
    country: 'Seychelles',
    models: [
      {
        id: 'm-phish',
        number: '01',
        name: 'Phishing & Impersonation Detection',
        category: 'Brand & Form Integrity',
        description: 'Evaluates visual mimicry, brand asset similarity, and unauthorized credential intake endpoints.',
        verdict: 'malicious',
        confidence: 99,
        summary: 'Targeted visual and DOM replica of Microsoft login. Form posts password and MFA tokens to off-domain webhook.',
        executionTimeMs: 165,
        status: 'completed',
        evidence: [
          'CLONE DETECTED: 98.4% DOM structural match with Microsoft Entra ID authentication page.',
          'HARVESTING ACTION: POST action points to external unauthenticated receiver at /api/dump-creds.',
          'HOTLINKED ASSETS: Unauthorized fetching of official Microsoft SVG logos and CSS styles.',
        ],
        metrics: [
          { label: 'Form Action Safety', value: 'EXPOSED HARVESTER', state: 'alert' },
          { label: 'Brand Divergence Index', value: '0.94 / 1.0 (Critical)', state: 'alert' },
          { label: 'Visual Fingerprint Match', value: 'Targeted Clone', state: 'alert' },
        ],
      },
      {
        id: 'm-domain',
        number: '02',
        name: 'Domain & Lexical Intelligence',
        category: 'Domain Reputation',
        description: 'Assesses registration age, registrar stability, lexical randomness, and typosquatting risk.',
        verdict: 'malicious',
        confidence: 98,
        summary: 'Domain registered 3 days ago. Employs numeral zero "0" to substitute letter "o" (typo-squatting attack).',
        executionTimeMs: 112,
        status: 'completed',
        evidence: [
          'TYPOSQUATTING: Levenshtein distance 1 to "microsoft.com" using zero substitution.',
          'DOMAIN LIFESPAN: 72 hours old (Registered via Privacy Protect, LLC).',
          'BULLETPROOF HOSTING: Nameservers hosted on known non-compliant autonomous system.',
        ],
        metrics: [
          { label: 'Domain Age', value: '3 days old', state: 'alert' },
          { label: 'Typosquatting Match', value: 'microsoft.com', state: 'alert' },
          { label: 'Whois Privacy Proxy', value: 'High-anonymity shielded', state: 'warn' },
        ],
      },
      {
        id: 'm-tls',
        number: '03',
        name: 'TLS Certificate & Chain Validation',
        category: 'Transport Security',
        description: 'Validates certificate authority pedigree, expiration, Subject Alternative Names, and cipher strength.',
        verdict: 'suspicious',
        confidence: 88,
        summary: 'Automated Domain Validation certificate issued 48 hours ago. HTTPS presence does NOT imply organizational authenticity.',
        executionTimeMs: 95,
        status: 'completed',
        evidence: [
          'ISSUER: Let\'s Encrypt Authority E6 (Automated ephemeral DV cert).',
          'VALIDITY: Created 48 hours ago.',
          'CERTIFICATE MISMATCH: Common Name does NOT belong to Microsoft Corporation.',
          'ABUSE PATTERN: Short-lived DV cert deployed over deceptive brand domain.',
        ],
        metrics: [
          { label: 'Validation Type', value: 'Domain Validation (DV)', state: 'warn' },
          { label: 'Cert Age', value: '2 days old', state: 'warn' },
          { label: 'Organization Verified', value: 'None (Unvetted)', state: 'alert' },
        ],
      },
      {
        id: 'm-redirect',
        number: '04',
        name: 'Redirect Chain Analysis',
        category: 'Routing Integrity',
        description: 'Traces initial request to terminal destination, flagging suspicious cross-domain routing hops.',
        verdict: 'suspicious',
        confidence: 91,
        summary: 'Dynamic user-agent cloaking detected. Inspecting crawler receives decoy 404 page while real browsers receive phishing payload.',
        executionTimeMs: 140,
        status: 'completed',
        evidence: [
          'CLOAKING BEHAVIOR: Differing server responses based on automated crawler signatures.',
          'DEVICE FINGERPRINTING: Client-side JS script executes canvas fingerprinting before revealing login inputs.',
        ],
        metrics: [
          { label: 'Cloaking Detected', value: 'Yes (Heuristic)', state: 'alert' },
          { label: 'Device Fingerprinting', value: 'Active', state: 'warn' },
        ],
      },
      {
        id: 'm-posture',
        number: '05',
        name: 'Web Security Posture',
        category: 'Configuration Hygiene',
        description: 'Examines HTTP defensive headers, Content Security Policy, and cookie security flags.',
        verdict: 'suspicious',
        confidence: 89,
        summary: 'Completely devoid of Content Security Policy and defensive frame headers, facilitating clickjacking.',
        executionTimeMs: 105,
        status: 'completed',
        evidence: [
          'MISSING HEADERS: Content-Security-Policy absent.',
          'CLICKJACKING RISK: X-Frame-Options missing.',
          'REFERRER LEAKAGE: Referrer-Policy allows full credential token leak.',
        ],
        metrics: [
          { label: 'CSP Header', value: 'Missing', state: 'alert' },
          { label: 'X-Frame-Options', value: 'Missing', state: 'warn' },
        ],
      },
      {
        id: 'm-collab',
        number: '06',
        name: 'Collaborative Threat Intelligence',
        category: 'Collective Telemetry',
        description: 'Cross-references active threat intelligence feeds, honeypot telemetry, and community incident reports.',
        verdict: 'malicious',
        confidence: 97,
        summary: 'Active critical incident reported across 14 security research feeds and flagged by 28 community users.',
        executionTimeMs: 155,
        status: 'completed',
        evidence: [
          'FEED ALERT: Listed on PhishTank (#8392102) as active credential harvester.',
          'URLHAUS STATUS: Tagged as malware/phish dropper staging node.',
          'COMMUNITY FLAGS: 28 reports filed within past 6 hours.',
        ],
        metrics: [
          { label: 'PhishTank Match', value: 'CONFIRMED PHISH', state: 'alert' },
          { label: 'Community Reports', value: '28 submissions', state: 'alert' },
          { label: 'Takedown In Progress', value: 'Active notice sent' },
        ],
      },
    ],
    findings: [
      {
        id: 'fnd-phish-crit',
        title: 'Active Brand Impersonation (Microsoft 365 Login Harvester)',
        severity: 'critical',
        source: 'Phishing Detection (M-01)',
        description: 'The endpoint renders an illegitimate copy of Microsoft authentication screens, capturing plain-text credentials and 2FA tokens.',
        evidence: [
          'DOM visual structural similarity: 98.4%',
          'Stolen assets hotlinked directly from authentic Microsoft CDNs',
          'Form action targets /api/dump-creds receiver endpoint',
        ],
        recommendation: 'DO NOT enter credentials. If already submitted, immediately navigate to official https://account.microsoft.com and revoke session tokens.',
      },
      {
        id: 'fnd-domain-typo',
        title: 'Typosquatting Homoglyph Domain ("micros0ft" substitution)',
        severity: 'critical',
        source: 'Domain Intelligence (M-02)',
        description: 'The domain deliberately swaps the letter "o" for numerical zero "0" to deceive human observers inspecting links in email or SMS.',
        evidence: [
          'Detected token: micros0ft (Levenshtein distance 1 to microsoft.com)',
          'Registration timestamp: 72 hours ago',
        ],
        recommendation: 'Check URL spelling carefully. Always type corporate addresses directly into the browser address bar.',
      },
      {
        id: 'fnd-tls-dv',
        title: 'Deceptive SSL Certificate (HTTPS Does Not Guarantee Authenticity)',
        severity: 'high',
        source: 'TLS & Certificate Analysis (M-03)',
        description: 'Attackers obtained an automated DV certificate to generate a green browser lock icon, falsely projecting safety to non-technical victims.',
        evidence: [
          'Let\'s Encrypt DV issued 2 days prior to phishing campaign rollout',
          'Certificate holder identity is unverified and anonymous',
        ],
        recommendation: 'Remember: A padlock icon merely proves connection encryption, NOT website legitimacy or identity.',
      },
      {
        id: 'fnd-collab-active',
        title: 'Confirmed Threat Feed Match (Active PhishTank Incident)',
        severity: 'high',
        source: 'Collaborative Intelligence (M-06)',
        description: 'Multiple automated threat telemetry engines independently confirmed active harvesting operations.',
        evidence: ['Feed matches: PhishTank, AlienVault OTX, URLhaus'],
        recommendation: 'Report this domain to your internal IT security department and domain abuse registrar.',
      },
    ],
    recommendedActions: [
      {
        id: 'act-crit-1',
        level: 'essential',
        title: 'Block and Close Immediately',
        detail: 'Do not interact with any form elements, do not click internal buttons, and close this browser tab immediately.',
        targetUser: 'all',
      },
      {
        id: 'act-crit-2',
        level: 'essential',
        title: 'Emergency Credential Reset If Interacted',
        detail: 'If you entered your password or authenticator code on this site, go to official account.microsoft.com via a known bookmark and reset your credentials immediately.',
        targetUser: 'general',
      },
      {
        id: 'act-crit-3',
        level: 'advisory',
        title: 'Submit Community Report',
        detail: 'Help accelerate domain registrar suspension by filing a community threat confirmation report.',
        targetUser: 'all',
      },
    ],
  },

  'bit.ly': {
    scanId: 'scn_redir_7210aa94',
    submittedUrl: 'https://bit.ly/secure-account-verify-302',
    hostname: 'bit.ly',
    protocol: 'https:',
    score: 38,
    riskLevel: 'high',
    summary: 'High risk detected. Shortened URL conceals multi-hop redirect chain resolving to an unrated offshore staging landing page.',
    isDemo: true,
    criticalOverride: false,
    checksCompleted: 6,
    checksSkipped: 0,
    checksErrored: 0,
    checkedAt: new Date().toISOString(),
    resolvedIp: '67.199.248.11',
    asn: 'AS393406 (Bitly, Inc.)',
    country: 'United States',
    models: [
      {
        id: 'm-phish',
        number: '01',
        name: 'Phishing & Impersonation Detection',
        category: 'Brand & Form Integrity',
        description: 'Evaluates visual mimicry, brand asset similarity, and unauthorized credential intake endpoints.',
        verdict: 'suspicious',
        confidence: 84,
        summary: 'Target destination page prompts for financial institution verification without verifiable branding authority.',
        executionTimeMs: 130,
        status: 'completed',
        evidence: [
          'SUSPICIOUS PROMPT: Terminal page demands immediate payment verification.',
          'UNVERIFIED LOGOS: Displays generic bank consortium badges.',
        ],
        metrics: [
          { label: 'Form Action Safety', value: 'Unverified Third-party', state: 'warn' },
          { label: 'Brand Divergence Index', value: '0.78 / 1.0', state: 'warn' },
        ],
      },
      {
        id: 'm-domain',
        number: '02',
        name: 'Domain & Lexical Intelligence',
        category: 'Domain Reputation',
        description: 'Assesses registration age, registrar stability, lexical randomness, and typosquatting risk.',
        verdict: 'suspicious',
        confidence: 88,
        summary: 'Shortener domain bit.ly is legitimate, but terminal destination domain was registered only 11 days ago.',
        executionTimeMs: 110,
        status: 'completed',
        evidence: [
          'INTERMEDIARY HOST: bit.ly (Trusted public shortener).',
          'TERMINAL DOMAIN: auth-card-portal-online.top (11 days old, high-risk TLD .top).',
        ],
        metrics: [
          { label: 'Terminal TLD Risk', value: '.top (Elevated abuse)', state: 'warn' },
          { label: 'Terminal Domain Age', value: '11 days old', state: 'alert' },
        ],
      },
      {
        id: 'm-tls',
        number: '03',
        name: 'TLS Certificate & Chain Validation',
        category: 'Transport Security',
        description: 'Validates certificate authority pedigree, expiration, Subject Alternative Names, and cipher strength.',
        verdict: 'clear',
        confidence: 92,
        summary: 'Intermediate and terminal servers both negotiate valid TLS encryption.',
        executionTimeMs: 85,
        status: 'completed',
        evidence: [
          'BITLY TLS: Cloudflare Inc ECC CA-3 (Valid).',
          'TERMINAL TLS: ZeroSSL TLS CA (Valid for 68 days).',
        ],
        metrics: [
          { label: 'Encryption Standard', value: 'TLS 1.3 Active' },
        ],
      },
      {
        id: 'm-redirect',
        number: '04',
        name: 'Redirect Chain Analysis',
        category: 'Routing Integrity',
        description: 'Traces initial request to terminal destination, flagging suspicious cross-domain routing hops.',
        verdict: 'malicious',
        confidence: 96,
        summary: '3-hop obfuscation chain traversing shortener, cloud tracking bounce, and offshore hosting destination.',
        executionTimeMs: 170,
        status: 'completed',
        evidence: [
          'HOP 0: https://bit.ly/secure-account-verify-302 -> 301 Redirect.',
          'HOP 1: https://click.track-delivery-update.info/r/902 -> 302 Redirect.',
          'HOP 2: https://auth-card-portal-online.top/portal -> 200 OK.',
          'OBFUSCATION LEVEL: High (Cross-jurisdiction routing).',
        ],
        metrics: [
          { label: 'Total Redirect Hops', value: '3 hops', state: 'alert' },
          { label: 'Cross-Domain Transitions', value: '2 distinct hops', state: 'alert' },
          { label: 'Geographic Shifts', value: 'US -> Germany -> Cyprus', state: 'warn' },
        ],
      },
      {
        id: 'm-posture',
        number: '05',
        name: 'Web Security Posture',
        category: 'Configuration Hygiene',
        description: 'Examines HTTP defensive headers, Content Security Policy, and cookie security flags.',
        verdict: 'suspicious',
        confidence: 81,
        summary: 'Terminal endpoint suppresses security headers and forces aggressive browser cache bypass.',
        executionTimeMs: 95,
        status: 'completed',
        evidence: ['Cache-Control: no-store, no-cache, must-revalidate', 'HSTS missing on terminal host'],
        metrics: [
          { label: 'HSTS Protection', value: 'Absent on terminal', state: 'warn' },
        ],
      },
      {
        id: 'm-collab',
        number: '06',
        name: 'Collaborative Threat Intelligence',
        category: 'Collective Telemetry',
        description: 'Cross-references active threat intelligence feeds, honeypot telemetry, and community incident reports.',
        verdict: 'suspicious',
        confidence: 86,
        summary: 'URL pattern matches ongoing SMS phishing (smishing) delivery campaign targeting financial credentials.',
        executionTimeMs: 140,
        status: 'completed',
        evidence: [
          'CAMPAIGN SIGNATURE: Smishing wave impersonating parcel customs delivery fees.',
          'COMMUNITY FLAGS: 9 users reported receipt via SMS link.',
        ],
        metrics: [
          { label: 'Smishing Heuristic', value: 'Match (High)', state: 'warn' },
          { label: 'Community Flags', value: '9 reports', state: 'warn' },
        ],
      },
    ],
    findings: [
      {
        id: 'fnd-redir-hops',
        title: 'Multi-Hop Obfuscated Redirection Chain',
        severity: 'high',
        source: 'Redirect Analysis (M-04)',
        description: 'The short link conceals multiple automated server-side jumps that route the browser to an unvetted destination domain registered 11 days ago.',
        evidence: [
          'Hop 0: bit.ly -> Hop 1: track-delivery-update.info -> Hop 2: auth-card-portal-online.top',
          'Cross-jurisdictional IP relocation across three cloud providers',
        ],
        recommendation: 'Do not follow unexpanded short links from unsolicited messages. Use a short-link previewer or security scanner first.',
      },
      {
        id: 'fnd-tld-risk',
        title: 'Elevated TLD Abuse Profile (.top)',
        severity: 'medium',
        source: 'Domain Intelligence (M-02)',
        description: 'The destination top-level domain (.top) has a statistically elevated frequency of ephemeral phishing campaigns.',
        evidence: ['Registrar: NameSilo LLC, created 11 days prior'],
        recommendation: 'Exercise heightened skepticism on sites operating on high-abuse commercial TLDs.',
      },
    ],
    recommendedActions: [
      {
        id: 'act-bit-1',
        level: 'essential',
        title: 'Avoid Entering Financial Data',
        detail: 'The final destination is not an official banking institution. Refrain from inputting card numbers, account numbers, or OTP codes.',
        targetUser: 'all',
      },
      {
        id: 'act-bit-2',
        level: 'advisory',
        title: 'Verify via Official Institution App',
        detail: 'If you received this link via SMS or email claiming account suspension, log into your banking provider app directly to check alerts.',
        targetUser: 'general',
      },
    ],
  },

  'untrusted-cdn-assets.org': {
    scanId: 'scn_cert_182944b1',
    submittedUrl: 'https://expired-tls.untrusted-cdn-assets.org',
    hostname: 'expired-tls.untrusted-cdn-assets.org',
    protocol: 'https:',
    score: 62,
    riskLevel: 'caution',
    summary: 'Caution warranted. Website security certificate has expired, and critical defensive headers are missing.',
    isDemo: true,
    criticalOverride: false,
    checksCompleted: 6,
    checksSkipped: 0,
    checksErrored: 0,
    checkedAt: new Date().toISOString(),
    resolvedIp: '198.51.100.89',
    asn: 'AS16509 (Amazon.com, Inc.)',
    country: 'Ireland',
    models: [
      {
        id: 'm-phish',
        number: '01',
        name: 'Phishing & Impersonation Detection',
        category: 'Brand & Form Integrity',
        description: 'Evaluates visual mimicry, brand asset similarity, and unauthorized credential intake endpoints.',
        verdict: 'clear',
        confidence: 90,
        summary: 'No active credential intake forms or known brand mimicry assets detected on scanned endpoints.',
        executionTimeMs: 125,
        status: 'completed',
        evidence: ['No password intake inputs found.', 'Static asset delivery structure.'],
        metrics: [{ label: 'Phishing Confidence', value: 'Negative (Low)' }],
      },
      {
        id: 'm-domain',
        number: '02',
        name: 'Domain & Lexical Intelligence',
        category: 'Domain Reputation',
        description: 'Assesses registration age, registrar stability, lexical randomness, and typosquatting risk.',
        verdict: 'clear',
        confidence: 89,
        summary: 'Domain registered 4 years ago with consistent DNS records.',
        executionTimeMs: 90,
        status: 'completed',
        evidence: ['DOMAIN AGE: 4.2 years', 'Registrar: Dynadot Inc.'],
        metrics: [{ label: 'Domain Age', value: '1,530 days' }],
      },
      {
        id: 'm-tls',
        number: '03',
        name: 'TLS Certificate & Chain Validation',
        category: 'Transport Security',
        description: 'Validates certificate authority pedigree, expiration, Subject Alternative Names, and cipher strength.',
        verdict: 'suspicious',
        confidence: 98,
        summary: 'X.509 certificate expired 8 days ago. Browser connections will trigger SSL security warnings.',
        executionTimeMs: 110,
        status: 'completed',
        evidence: [
          'STATUS: Certificate Expired (Validity lapsed 8 days ago).',
          'VALID NOT AFTER: October 30, 2026 23:59:59 GMT.',
          'ISSUER: Sectigo RSA Domain Validation Secure Server CA.',
        ],
        metrics: [
          { label: 'Validity Status', value: 'EXPIRED (8 days)', state: 'alert' },
          { label: 'Self-Signed', value: 'No' },
          { label: 'Revocation Check', value: 'Not revoked' },
        ],
      },
      {
        id: 'm-redirect',
        number: '04',
        name: 'Redirect Chain Analysis',
        category: 'Routing Integrity',
        description: 'Traces initial request to terminal destination, flagging suspicious cross-domain routing hops.',
        verdict: 'clear',
        confidence: 95,
        summary: 'Standard direct response without unexpected redirection.',
        executionTimeMs: 78,
        status: 'completed',
        evidence: ['Direct resolution to static bucket endpoint.'],
        metrics: [{ label: 'Hops', value: '0' }],
      },
      {
        id: 'm-posture',
        number: '05',
        name: 'Web Security Posture',
        category: 'Configuration Hygiene',
        description: 'Examines HTTP defensive headers, Content Security Policy, and cookie security flags.',
        verdict: 'suspicious',
        confidence: 87,
        summary: 'Missing HSTS, Content Security Policy, and Cross-Origin Resource Sharing protections.',
        executionTimeMs: 98,
        status: 'completed',
        evidence: [
          'HSTS Header: Missing',
          'Content-Security-Policy: Missing',
          'Server Header: Exposed (Apache/2.4.41)',
        ],
        metrics: [
          { label: 'Server Version Leak', value: 'Apache/2.4.41', state: 'warn' },
          { label: 'HSTS', value: 'Missing', state: 'warn' },
        ],
      },
      {
        id: 'm-collab',
        number: '06',
        name: 'Collaborative Threat Intelligence',
        category: 'Collective Telemetry',
        description: 'Cross-references active threat intelligence feeds, honeypot telemetry, and community incident reports.',
        verdict: 'clear',
        confidence: 94,
        summary: 'No blacklists or active abuse complaints currently associated with this IP or domain.',
        executionTimeMs: 135,
        status: 'completed',
        evidence: ['0 blacklist records across public threat feeds.'],
        metrics: [{ label: 'Blacklist Count', value: '0 / 42' }],
      },
    ],
    findings: [
      {
        id: 'fnd-cert-exp',
        title: 'Expired TLS/SSL Certificate',
        severity: 'high',
        source: 'TLS & Certificate Analysis (M-03)',
        description: 'The cryptographic certificate securing this web connection has expired. Traffic between client and server is vulnerable to man-in-the-middle interception.',
        evidence: [
          'Not After date: October 30, 2026',
          'Current status: Lapsed 8 days ago',
        ],
        recommendation: 'Site operators must renew the certificate. Users should avoid transmitting sensitive data until renewed.',
      },
      {
        id: 'fnd-header-leak',
        title: 'Web Server Version Disclosure',
        severity: 'low',
        source: 'Web Security Posture (M-05)',
        description: 'The web server discloses exact version software in HTTP response headers (Apache/2.4.41), assisting attackers in targeting known CVEs.',
        evidence: ['Server: Apache/2.4.41 (Ubuntu)'],
        recommendation: 'Configure ServerTokens Prod in web server configuration to suppress banner details.',
      },
    ],
    recommendedActions: [
      {
        id: 'act-cert-1',
        level: 'advisory',
        title: 'Do Not Bypass Browser Warnings',
        detail: 'Browsers warn against visiting sites with expired certificates. Do not click through warnings on public Wi-Fi networks.',
        targetUser: 'general',
      },
      {
        id: 'act-cert-2',
        level: 'monitoring',
        title: 'Notify Site Administrator',
        detail: 'Contact the webmaster regarding certificate renewal.',
        targetUser: 'all',
      },
    ],
  },
};

export function generateDynamicScanResult(rawUrl: string, hostname: string, protocol: 'https:' | 'http:'): ScanResult {
  // Check if we have an exact match or substring in predefined scenarios
  for (const key of Object.keys(SAMPLE_SCENARIOS)) {
    if (hostname.toLowerCase().includes(key.toLowerCase()) || rawUrl.toLowerCase().includes(key.toLowerCase())) {
      const base = SAMPLE_SCENARIOS[key];
      return {
        ...base,
        submittedUrl: rawUrl,
        hostname,
        protocol,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  // Heuristics for arbitrary user URLs
  const isHttpOnly = protocol === 'http:';
  const hasSuspiciousWords = /(verify|login|secure|account|update|banking|wallet|free|crypto|bonus)/i.test(rawUrl);
  const isHighEntropy = hostname.split('.')[0].length > 18 || (hostname.match(/\d/g) || []).length > 4;
  const isLongPath = rawUrl.length > 80;

  let calculatedScore = 85;
  let riskLevel: ScanResult['riskLevel'] = 'low';
  let summary = 'Analyzed through 6 independent security intelligence models. No critical malicious indicators detected in available telemetry.';

  if (isHttpOnly) {
    calculatedScore -= 25;
  }
  if (hasSuspiciousWords) {
    calculatedScore -= 20;
  }
  if (isHighEntropy) {
    calculatedScore -= 18;
  }
  if (isLongPath) {
    calculatedScore -= 10;
  }

  if (calculatedScore >= 80) {
    riskLevel = 'low';
  } else if (calculatedScore >= 60) {
    riskLevel = 'caution';
    summary = 'Moderate risk profile observed. Some configuration anomalies and lexical patterns suggest caution before submitting sensitive data.';
  } else if (calculatedScore >= 30) {
    riskLevel = 'high';
    summary = 'Multiple elevated risk signals detected across domain intelligence and transport security checks.';
  } else {
    riskLevel = 'critical';
    summary = 'Significant malicious indicators flagged across multiple independent models.';
  }

  const scanId = `scn_dyn_${Math.random().toString(36).substring(2, 10)}`;

  return {
    scanId,
    submittedUrl: rawUrl,
    hostname,
    protocol,
    score: calculatedScore,
    riskLevel,
    summary,
    isDemo: true,
    criticalOverride: false,
    checksCompleted: 6,
    checksSkipped: 0,
    checksErrored: 0,
    checkedAt: new Date().toISOString(),
    resolvedIp: '104.21.48.182',
    asn: 'AS13335 (Cloudflare, Inc.)',
    country: 'United States',
    models: [
      {
        id: 'm-phish',
        number: '01',
        name: 'Phishing & Impersonation Detection',
        category: 'Brand & Form Integrity',
        description: 'Evaluates visual mimicry, brand asset similarity, and unauthorized credential intake endpoints.',
        verdict: hasSuspiciousWords ? 'suspicious' : 'clear',
        confidence: 91,
        summary: hasSuspiciousWords
          ? 'URL contains high-value authentication keywords. Elevated review recommended for form actions.'
          : 'No visual or structural imitation of known brand login pages detected.',
        executionTimeMs: 140,
        status: 'completed',
        evidence: [
          `Target path evaluation: ${rawUrl.substring(0, 60)}...`,
          hasSuspiciousWords ? 'Keyword matching: Suspicious auth-related lexical tokens' : 'DOM structural entropy within normal bounds',
        ],
        metrics: [
          { label: 'Brand Divergence Index', value: hasSuspiciousWords ? '0.62 / 1.0' : '0.04 / 1.0' },
          { label: 'Form Intake Safety', value: hasSuspiciousWords ? 'Caution' : 'Clean' },
        ],
      },
      {
        id: 'm-domain',
        number: '02',
        name: 'Domain & Lexical Intelligence',
        category: 'Domain Reputation',
        description: 'Assesses registration age, registrar stability, lexical randomness, and typosquatting risk.',
        verdict: isHighEntropy ? 'suspicious' : 'clear',
        confidence: 93,
        summary: `Domain structure evaluated for ${hostname}. ${isHighEntropy ? 'Elevated lexical entropy and character variance noted.' : 'Standard hierarchical domain naming convention.'}`,
        executionTimeMs: 105,
        status: 'completed',
        evidence: [
          `Hostname: ${hostname}`,
          `Entropy assessment: ${isHighEntropy ? 'High randomness in subdomain/stem' : 'Normal linguistic distribution'}`,
        ],
        metrics: [
          { label: 'Entropy Score', value: isHighEntropy ? '3.89 (High)' : '2.34 (Normal)' },
          { label: 'Punycode Homograph', value: hostname.startsWith('xn--') ? 'Detected' : 'None' },
        ],
      },
      {
        id: 'm-tls',
        number: '03',
        name: 'TLS Certificate & Chain Validation',
        category: 'Transport Security',
        description: 'Validates certificate authority pedigree, expiration, Subject Alternative Names, and cipher strength.',
        verdict: isHttpOnly ? 'error' : 'clear',
        confidence: 95,
        summary: isHttpOnly
          ? 'Unencrypted plain HTTP endpoint. Traffic is transmitted in cleartext without encryption.'
          : 'Valid TLS certificate with active trust path and modern cipher support.',
        executionTimeMs: 115,
        status: 'completed',
        evidence: [
          isHttpOnly
            ? 'Plaintext HTTP connection negotiated without TLS handshake.'
            : 'TLS 1.3 negotiated with valid certificate authority root chain.',
        ],
        metrics: [
          { label: 'Protocol', value: isHttpOnly ? 'HTTP (Insecure)' : 'TLS 1.3' },
          { label: 'Chain Status', value: isHttpOnly ? 'No Encryption' : 'Valid CA Chain' },
        ],
      },
      {
        id: 'm-redirect',
        number: '04',
        name: 'Redirect Chain Analysis',
        category: 'Routing Integrity',
        description: 'Traces initial request to terminal destination, flagging suspicious cross-domain routing hops.',
        verdict: 'clear',
        confidence: 94,
        summary: 'Direct destination resolution verified. No suspicious cross-domain hops detected.',
        executionTimeMs: 80,
        status: 'completed',
        evidence: ['Initial destination resolves directly to primary origin endpoint.'],
        metrics: [{ label: 'Redirect Hops', value: '0 hops' }],
      },
      {
        id: 'm-posture',
        number: '05',
        name: 'Web Security Posture',
        category: 'Configuration Hygiene',
        description: 'Examines HTTP defensive headers, Content Security Policy, and cookie security flags.',
        verdict: isHttpOnly ? 'suspicious' : 'clear',
        confidence: 88,
        summary: isHttpOnly
          ? 'Missing mandatory transport security headers (HSTS).'
          : 'Standard defensive headers detected with partial CSP enforcement.',
        executionTimeMs: 95,
        status: 'completed',
        evidence: [
          isHttpOnly
            ? 'HSTS header omitted due to plaintext protocol.'
            : 'Basic clickjacking and MIME sniffing protections active.',
        ],
        metrics: [
          { label: 'X-Content-Type-Options', value: 'nosniff' },
          { label: 'HSTS Status', value: isHttpOnly ? 'Disabled' : 'Observed' },
        ],
      },
      {
        id: 'm-collab',
        number: '06',
        name: 'Collaborative Threat Intelligence',
        category: 'Collective Telemetry',
        description: 'Cross-references active threat intelligence feeds, honeypot telemetry, and community incident reports.',
        verdict: 'clear',
        confidence: 96,
        summary: 'Queried 42 global threat feeds. No active threat listings or malicious community reports.',
        executionTimeMs: 160,
        status: 'completed',
        evidence: [
          'Feed check across URLhaus, Spamhaus, and AlienVault OTX: 0 alerts.',
          'Community submissions database: Clean status.',
        ],
        metrics: [
          { label: 'Feeds Searched', value: '42 feeds' },
          { label: 'Active Reports', value: '0' },
        ],
      },
    ],
    findings: isHttpOnly
      ? [
          {
            id: 'fnd-dyn-http',
            title: 'Unencrypted HTTP Protocol in Use',
            severity: 'high',
            source: 'TLS & Certificate Analysis (M-03)',
            description: 'The connection does not negotiate SSL/TLS encryption. Anyone on the local network or internet transit path can eavesdrop or tamper with web traffic.',
            evidence: ['Scheme: http://', 'Port: 80'],
            recommendation: 'Do not enter passwords, credit card numbers, or private communications over unencrypted HTTP.',
          },
        ]
      : [
          {
            id: 'fnd-dyn-standard',
            title: 'Standard Transport Encryption Verified',
            severity: 'informational',
            source: 'TLS & Certificate Analysis (M-03)',
            description: 'Communication is protected with active HTTPS encryption against eavesdropping.',
            evidence: ['TLS 1.3 negotiated'],
            recommendation: 'Ensure you still verify the authenticity of the domain before providing authentication credentials.',
          },
        ],
    recommendedActions: [
      {
        id: 'act-dyn-1',
        level: isHttpOnly ? 'essential' : 'monitoring',
        title: isHttpOnly ? 'Upgrade to HTTPS' : 'Inspect Domain Carefully',
        detail: isHttpOnly
          ? 'Check if the site offers an https:// version and never submit sensitive data.'
          : 'Confirm that this domain matches the intended organization you wish to communicate with.',
        targetUser: 'general',
      },
    ],
  };
}

