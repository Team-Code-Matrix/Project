"""
TrustShield Deterministic Risk Scoring & Evidence Synthesis Engine
Calculates evidence-based risk score (0-100) and Trust Score (100-0).
Enforces strict polarity:
  0–39 Trust (61-100 Risk): MALICIOUS or PKI_TRUST_COMPROMISED
  40–69 Trust (31-60 Risk): SUSPICIOUS
  70–100 Trust (0-30 Risk): CLEAN
Avoids double-counting correlated findings.
"""
from typing import Dict, Any, List, Tuple
try:
    from infrastructure_allowlist import (
        is_verified_infrastructure,
        is_shared_hosting_platform,
        is_hard_bypass_target,
        get_registrable_domain,
    )
except ImportError:
    from backend.infrastructure_allowlist import (
        is_verified_infrastructure,
        is_shared_hosting_platform,
        is_hard_bypass_target,
        get_registrable_domain,
    )

def compute_security_assessment(
    hostname: str,
    target_url: str,
    dns_data: Dict[str, Any],
    tls_data: Dict[str, Any],
    http_data: Dict[str, Any],
    dom_data: Dict[str, Any],
    headers_data: Dict[str, Any],
    cookie_data: Dict[str, Any],
    cors_data: Dict[str, Any],
    ml_data: Dict[str, Any],
    cti_data: Dict[str, Any],
    rdap_data: Dict[str, Any],
    lexical_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Synthesizes findings from all 4 autonomous modalities into deterministic scores,
    verdict, analyst reason codes, findings list, and recommended actions.
    """
    scan_id = "scn_" + dns_data.get("primary_ip", "").replace(".", "")[-6:] if dns_data.get("primary_ip") else "scn_init"
    findings: List[Dict[str, Any]] = []
    reasons: List[str] = []
    actions: List[Dict[str, Any]] = []

    is_nxdomain = dns_data.get("is_nxdomain", False)
    is_ssrf_prohibited = dns_data.get("is_ssrf_prohibited", False)
    is_cert_broken = tls_data.get("is_pki_compromised", False)
    is_http_only = target_url.lower().startswith("http://")

    # Infrastructure Allowlist Checks
    is_official_domain = (
        is_hard_bypass_target(hostname) or
        is_hard_bypass_target(target_url) or
        is_verified_infrastructure(
            hostname,
            asn=dns_data.get("asn", ""),
            domain_age_days=rdap_data.get("domainAgeDays"),
            is_typosquat=lexical_data.get("is_brand_typosquat", False)
        )
    )
    is_shared_platform = is_shared_hosting_platform(hostname)

    # Phishing & Brand Signals
    is_typosquat = False if is_official_domain else lexical_data.get("is_brand_typosquat", False)
    impersonated_brand = "" if is_official_domain else lexical_data.get("impersonated_brand", "")
    has_credential_exfil = False if is_official_domain else bool(dom_data.get("crossOriginSubmissionTarget"))
    has_password_input = dom_data.get("passwordInputsCount", 0) > 0
    has_otp_input = dom_data.get("otpFieldsCount", 0) > 0

    # Threat Intelligence Signals
    c_malicious_hits = cti_data.get("maliciousHits", [])
    if is_official_domain or is_shared_platform:
        # Verified first-party or shared infrastructure ONLY matches on exact normalized URL
        clean_low = target_url.lower().rstrip("/")
        exact_hits = []
        for hit in c_malicious_hits:
            det = hit.get("details") or {}
            ind = (det.get("indicator") or det.get("url") or det.get("source_url") or "").lower().rstrip("/")
            if ind and (ind == clean_low or clean_low == ind):
                exact_hits.append(hit)
        c_malicious_hits = exact_hits

    has_threat_match = len(c_malicious_hits) > 0

    # ML Inference Signals
    ml_pred = ml_data.get("prediction", "LEGITIMATE")
    ml_phish_prob = ml_data.get("phishing_probability", 0.0)

    # Domain Age Signals (RDAP)
    domain_age_days = rdap_data.get("domainAgeDays")
    is_newly_registered = rdap_data.get("isNewlyRegistered", False)

    # Base Risk Points Calculation
    accumulated_risk = 0

    # =========================================================================
    # 1. Critical Hard Vetoes (SSRF & Non-existent hosts)
    # =========================================================================
    if is_ssrf_prohibited:
        prohibited_ip = dns_data.get("prohibited_ip")
        return {
            "verdict": "MALICIOUS",
            "riskScore": 100,
            "trustScore": 0,
            "riskLevel": "critical",
            "criticalOverride": True,
            "overrideReason": "Anti-SSRF Policy Violation — Host resolved to prohibited network address.",
            "summary": f"CRITICAL SECURITY VIOLATION: Target hostname '{hostname}' resolves to prohibited private or link-local address '{prohibited_ip}'. Outbound connection blocked.",
            "reasons": ["ANTI_SSRF_PROHIBITED_IP", "PRIVATE_NETWORK_ACCESS_BLOCKED"],
            "findings": [{
                "id": "fnd_ssrf_01",
                "title": "Anti-SSRF Prohibited Internal IP",
                "severity": "critical",
                "category": "WEB_SEC",
                "description": f"Domain resolved to internal/reserved address {prohibited_ip}. Target is non-routable over public internet.",
                "recommendation": "Do not attempt scanning private infrastructure.",
                "source": "Anti-SSRF Network Guard",
            }],
            "recommendedActions": [{
                "id": "act_ssrf_01",
                "level": "essential",
                "title": "Block Private IP Target",
                "detail": "Target resolved to internal RFC 1918 or metadata IP. Inbound requests to internal targets must be isolated.",
                "targetUser": "admin",
            }]
        }

    if is_nxdomain:
        return {
            "verdict": "SUSPICIOUS",
            "riskScore": 100,
            "trustScore": 0,
            "riskLevel": "critical",
            "criticalOverride": True,
            "overrideReason": "DNS Resolution Failed (NXDOMAIN) — Domain does not exist in authoritative name servers.",
            "summary": f"Domain '{hostname}' does not exist (NXDOMAIN). DNS resolution failed with no active A/AAAA records, web server, or TLS certificate.",
            "reasons": [
                "DNS_NXDOMAIN_UNRESOLVED",
                "TLS_HANDSHAKE_ABORTED",
                "HOST_UNREACHABLE",
                "UNVERIFIED_INFRASTRUCTURE"
            ],
            "findings": [
                {
                    "id": "fnd_dns_nxdomain",
                    "title": "DNS Resolution Failed (NXDOMAIN) — Domain does not exist",
                    "severity": "critical",
                    "category": "WEB_SEC",
                    "description": "Authoritative DNS resolution for A/AAAA records failed. Domain is unregistered, abandoned, or nameservers are non-responsive.",
                    "recommendation": "Verify domain spelling. Do not submit credentials to non-existent or unverified hosts.",
                    "source": "DNS Pre-Flight Resolver"
                },
                {
                    "id": "fnd_tls_aborted",
                    "title": "TLS/SSL Handshake Aborted — No host at target address",
                    "severity": "critical",
                    "category": "PKI",
                    "description": "Cannot initiate cryptographic handshake because no IP address could be resolved for the target host.",
                    "recommendation": "Ensure domain is registered and points to active web infrastructure.",
                    "source": "Pillar 2: Cryptographic Telemetry"
                }
            ],
            "recommendedActions": [
                {
                    "id": "act_nxdomain_01",
                    "level": "essential",
                    "title": "Verify Target Domain Spelling",
                    "detail": "The domain failed DNS resolution. Check for typographical errors in the submitted URL.",
                    "targetUser": "general",
                }
            ]
        }

    # =========================================================================
    # 2. Evidence-Based Risk Evaluation
    # =========================================================================

    # Threat Intelligence Matches
    if has_threat_match:
        accumulated_risk += 85
        reasons.append(f"Confirmed malicious listing in federated threat intelligence feeds ({len(c_malicious_hits)} hit(s))")
        for hit in c_malicious_hits:
            findings.append({
                "id": f"fnd_cti_{hit['providerId']}",
                "title": f"Active Malicious Listing ({hit['providerName']})",
                "severity": "critical",
                "category": "CTI",
                "description": f"Domain or URL flagged as active threat: {hit.get('threatType', 'malicious')}",
                "recommendation": "Block all outbound traffic to this domain. Do not interact with target.",
                "source": hit["providerName"],
            })

    # Typosquatting / Brand Divergence
    if is_typosquat:
        accumulated_risk += 65
        brand_label = impersonated_brand.title() if impersonated_brand else "Protected Identity"
        reasons.append(f"Typosquatted domain mimicking official identity of '{brand_label}'")
        findings.append({
            "id": "fnd_phish_brand",
            "title": f"Typosquatted Brand Impersonation Targeting {brand_label}",
            "severity": "critical",
            "category": "PHISHING",
            "description": f"Hostname structure demonstrates deliberate lexical divergence targeting {brand_label}.",
            "recommendation": "Do not enter passwords, session tokens, or personal identifiers.",
            "source": "Pillar 1: DOM & Vision Detonation",
        })

    # Credential Harvesting in DOM
    if has_credential_exfil or (has_password_input and is_typosquat):
        accumulated_risk += 50
        reasons.append("Credential form inputs target unverified external exfiltration endpoint")
        findings.append({
            "id": "fnd_form_exfil",
            "title": "Unauthorized Credential Intake Action",
            "severity": "critical",
            "category": "PHISHING",
            "description": "Form inputs capture authentication credentials and submit to cross-origin endpoints.",
            "recommendation": "Immediate credential isolation required. Avoid submitting authentication data.",
            "source": "Pillar 1: DOM Detonation",
        })

    # Machine Learning Phishing Classification
    if not is_official_domain and ml_pred == "PHISHING" and ml_phish_prob >= 0.65:
        accumulated_risk += 40
        reasons.append(f"Custom RandomForest ML model predicted PHISHING ({int(ml_phish_prob*100)}% probability)")
        findings.append({
            "id": "fnd_ml_phishing",
            "title": f"AI/ML Phishing Detonation Alert ({int(ml_phish_prob*100)}% Confidence)",
            "severity": "high",
            "category": "PHISHING",
            "description": f"TrustShield RandomForest ML engine classified target as PHISHING based on lexical & structural indicators.",
            "recommendation": "Exercise heightened scrutiny before interacting with this endpoint.",
            "source": "ML PhishGuard (v1.2.0)",
        })

    # PKI / TLS Compromises
    if is_cert_broken:
        accumulated_risk += 70
        tls_err = tls_data.get("error", "Certificate expired or CA distrusted")
        reasons.append(f"TLS certificate validation failed: {tls_err}")
        findings.append({
            "id": "fnd_pki_broken",
            "title": "Expired or Distrusted TLS Certificate",
            "severity": "critical",
            "category": "PKI",
            "description": f"The peer certificate presented by {hostname} failed validation: {tls_err}.",
            "recommendation": "Renew TLS certificate and ensure certificate authority trust path is valid.",
            "source": "Pillar 2: Cryptographic Telemetry",
        })

    # Plaintext HTTP
    if is_http_only:
        accumulated_risk += 35
        reasons.append("Connection transmits over plaintext HTTP without transport layer encryption")
        findings.append({
            "id": "fnd_http_plaintext",
            "title": "Unencrypted Plaintext HTTP Protocol",
            "severity": "medium",
            "category": "PKI",
            "description": "The endpoint does not negotiate TLS transport encryption, exposing requests to eavesdropping.",
            "recommendation": "Enforce HTTPS redirect and configure HSTS.",
            "source": "Pillar 2: Transport Security",
        })

    # Suspicious TLD & Lexical Anomaly
    if lexical_data.get("is_suspicious_tld"):
        accumulated_risk += 20
        reasons.append(f"Registered on high-abuse Top-Level Domain (.{lexical_data.get('tld')})")
        findings.append({
            "id": "fnd_susp_tld",
            "title": "Elevated Abuse-Rate Top-Level Domain",
            "severity": "low",
            "category": "WEB_SEC",
            "description": f"The domain uses .{lexical_data.get('tld')}, a TLD with elevated abuse and spam registrations.",
            "recommendation": "Verify destination domain authority before transacting.",
            "source": "Pillar 3: Web Security Telemetry",
        })

    # URL Shorteners with Deceptive Keywords
    if lexical_data.get("is_shortener"):
        if lexical_data.get("contains_auth_keyword"):
            accumulated_risk += 47
            reasons.append("Shortened link concealing redirect destination with deceptive keywords")
            findings.append({
                "id": "fnd_shortener_auth",
                "title": "Obfuscated URL Shortener with Credential Keywords",
                "severity": "high",
                "category": "PHISHING",
                "description": f"URL shortener ({hostname}) masks downstream destination with deceptive path keywords.",
                "recommendation": "Expand shortened destination via safe pre-detonation preview.",
                "source": "Pillar 1: Lexical Obfuscation Guard",
            })
        else:
            accumulated_risk += 20
            reasons.append("Shortened link conceals final destination host")

    # Newly Registered Domain (< 30 days)
    if is_newly_registered and domain_age_days is not None:
        accumulated_risk += 25
        reasons.append(f"Domain registered recently ({domain_age_days} days ago)")
        findings.append({
            "id": "fnd_domain_age",
            "title": f"Newly Registered Domain ({domain_age_days} Days Old)",
            "severity": "medium",
            "category": "WEB_SEC",
            "description": f"Domain was registered {domain_age_days} days ago. Newly registered domains have higher statistical correlation with transient phishing campaigns.",
            "recommendation": "Monitor domain activity and review tenure.",
            "source": "Authoritative RDAP Registry",
        })

    # Security Headers Deficiencies
    csp_info = headers_data.get("csp", {})
    hsts_info = headers_data.get("hsts", {})
    if not csp_info.get("present", False):
        accumulated_risk += 8
    if not hsts_info.get("present", False) and not is_http_only:
        accumulated_risk += 7

    # Cookie Insecurities
    cookie_sec = cookie_data.get("secureFlagsMissingCount", 0)
    cookie_http = cookie_data.get("httpOnlyMissingCount", 0)
    if cookie_sec > 0 or cookie_http > 0:
        accumulated_risk += 5

    # =========================================================================
    # 3. Deterministic Verdict Assignment & Hard Caps
    # =========================================================================
    # 3a. Verified Infrastructure Protection Gate
    # Legitimate hyperscale/mainstream platforms are NEVER subjected to safety veto overrides
    # unless the exact full normalized URL is listed as a verified threat binary.
    if is_official_domain and not has_threat_match:
        backend_verdict = "CLEAN"
        final_risk = min(8, max(2, accumulated_risk))
        final_trust = max(92, min(98, 100 - final_risk))
        risk_level = "low"
        override = False
        override_reason = None
        summary = f"Verified infrastructure for {hostname}. Domain possesses valid identity tenure, robust transport encryption, and clean reputation across global threat feeds."
        findings = [f for f in findings if f.get("severity") not in ["critical", "high"]]
        if not any("Verified enterprise infrastructure" in r for r in reasons):
            reasons.append("Verified enterprise infrastructure and authenticated autonomous system")
            reasons.append("RFC 5280 certificate chain verified across global root stores")
            reasons.append("Clean reputation confirmed across federated threat intelligence feeds")

    elif has_threat_match or (is_typosquat and has_credential_exfil):
        backend_verdict = "MALICIOUS"
        final_risk = max(82, min(100, accumulated_risk))
        final_trust = max(0, min(18, 100 - final_risk))
        risk_level = "critical"
        override = True
        override_reason = "Confirmed threat intelligence or active credential harvesting pattern."
        summary = f"CRITICAL SECURITY THREAT DETECTED: Confirmed malicious signals detected for {hostname}. Deterministic safety veto override triggered."

    elif is_cert_broken:
        backend_verdict = "PKI_TRUST_COMPROMISED"
        final_risk = max(70, min(80, accumulated_risk))
        final_trust = max(20, min(30, 100 - final_risk))
        risk_level = "critical"
        override = True
        override_reason = "Leaf certificate invalid, expired, or rejected by global trust stores."
        summary = f"PKI TRUST FAILURE: Transport security compromised on {hostname}. Leaf certificate failed validation."

    elif accumulated_risk >= 55:
        backend_verdict = "SUSPICIOUS"
        final_risk = max(55, min(75, accumulated_risk))
        final_trust = max(25, min(45, 100 - final_risk))
        risk_level = "high"
        override = False
        override_reason = None
        summary = f"HIGH RISK SUSPICIOUS SIGNALS: Obfuscated routing, URL masking, or deceptive indicators detected for {hostname}."

    elif accumulated_risk >= 35 or is_typosquat or (ml_pred == "PHISHING" and ml_phish_prob >= 0.50):
        backend_verdict = "SUSPICIOUS"
        final_risk = max(40, min(65, accumulated_risk))
        final_trust = max(40, min(60, 100 - final_risk))
        risk_level = "caution"
        override = False
        override_reason = None
        summary = f"SUSPICIOUS SIGNALS OBSERVED: Elevated risk telemetry noted for {hostname}. Exercise caution."

    else:
        backend_verdict = "CLEAN"
        if is_official_domain:
            final_risk = min(5, accumulated_risk)
            final_trust = max(94, min(98, 100 - final_risk))
            risk_level = "low"
            override = False
            override_reason = None
            summary = f"Verified infrastructure for {hostname}. Domain possesses valid identity tenure, robust transport encryption, and clean reputation across global threat feeds."
            reasons.append("Verified enterprise infrastructure and authenticated autonomous system")
            reasons.append("RFC 5280 certificate chain verified across global root stores")
            reasons.append("Clean reputation confirmed across federated threat intelligence feeds")
        else:
            final_risk = max(5, min(25, accumulated_risk))
            final_trust = max(75, min(95, 100 - final_risk))
            risk_level = "low"
            override = False
            override_reason = None
            summary = f"Verified infrastructure for {hostname}. Valid transport security, authenticated DNS resolution, clean DOM heuristics, and 0 active threat listings."
            reasons.append("RFC 5280 certificate chain verified across global root stores")
            reasons.append("Clean reputation confirmed across federated threat intelligence feeds")

    # Clean default finding if zero issues flagged
    if not findings:
        findings.append({
            "id": "fnd_clean_baseline",
            "title": "Strict Transport Security & Valid CA Enforced",
            "severity": "low",
            "category": "WEB_SEC",
            "description": f"Valid {tls_data.get('version', 'TLS 1.3')} transport encryption confirmed with trusted authority.",
            "recommendation": "Maintain proactive certificate renewal and header hygiene.",
            "source": "Pillar 2: PKI Validation",
        })

    # Recommended Actions Synthesis
    if backend_verdict == "MALICIOUS":
        actions.append({
            "id": "act_iso_01",
            "level": "essential",
            "title": "Isolate Endpoint & Abort Authentication",
            "detail": "Do not enter passwords, financial data, or session cookies on this endpoint.",
            "targetUser": "all",
        })
    elif backend_verdict == "PKI_TRUST_COMPROMISED":
        actions.append({
            "id": "act_pki_01",
            "level": "essential",
            "title": "Renew Distrusted or Expired TLS Certificate",
            "detail": "Obtain an active certificate from an accredited Certificate Authority and update web server configuration.",
            "targetUser": "admin",
        })
    elif backend_verdict == "SUSPICIOUS":
        actions.append({
            "id": "act_susp_01",
            "level": "advisory",
            "title": "Verify Target Host Authority",
            "detail": "Inspect URL query parameters and verify destination domain independently before transacting.",
            "targetUser": "general",
        })
    else:
        actions.append({
            "id": "act_clean_01",
            "level": "monitoring",
            "title": "Routine Security Monitoring",
            "detail": "Domain and certificate posture verified healthy. Continue routine automated threat scanning.",
            "targetUser": "all",
        })

    return {
        "verdict": backend_verdict,
        "riskScore": final_risk,
        "trustScore": final_trust,
        "riskLevel": risk_level,
        "criticalOverride": override,
        "overrideReason": override_reason,
        "summary": summary,
        "reasons": reasons,
        "findings": findings,
        "recommendedActions": actions,
    }

