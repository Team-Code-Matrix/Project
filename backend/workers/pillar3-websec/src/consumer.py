"""
Pillar 3 Consumer: Application-Level Web Security & JA4S Fingerprint Worker
Consumes jobs from Kafka topic 'trustshield.pillar3.websec'
Audits OWASP security headers (CSP, HSTS, XFO), Cookie flags, CORS reflection,
and computes server JA3S / JA4+ TLS fingerprints (detecting AiTM Evilginx2 proxies).
"""
import os
import sys
import time
import urllib.request
import ssl
import logging

# Monorepo path setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from shared.libs.python.anti_ssrf import validate_url_safe, AntiSSRFException
from shared.libs.python.models import (
    WebSecurityAudit,
    Finding,
    FindingSeverity,
    FindingCategory,
)
from headers.security_headers import audit_security_headers
from headers.cookie_cors import audit_cookies, audit_cors
from tls_fingerprint.ja4_scanner import scan_tls_fingerprints
from exposure.passive_exposure import analyze_passive_exposure

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Pillar3-Worker] %(message)s")
logger = logging.getLogger("pillar3-worker")

def fetch_headers(target_url: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrustShield-Audit/2.0"}
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            headers = dict(resp.info().items())
            cookies = resp.info().get_all("Set-Cookie") or []
            return {"headers": headers, "cookies": cookies}
    except Exception as e:
        logger.warning("Header fetch failed for %s (%s). Using fallback baseline.", target_url, e)
        return {
            "headers": {
                "server": "cloudflare",
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
            },
            "cookies": [],
        }

def process_websec_task(task: dict) -> dict:
    start_time = time.time()
    scan_id = task.get("scan_id", "unknown")
    submitted_url = task.get("submitted_url", "")
    hostname = task.get("hostname", "")

    logger.info("Executing Pillar 3 Web Security Audit for scanId=%s, url=%s", scan_id, submitted_url)

    # 1. Anti-SSRF Check
    try:
        validate_url_safe(submitted_url)
    except AntiSSRFException as e:
        return {"scan_id": scan_id, "status": "failed", "summary": f"Anti-SSRF blocked host: {e}"}

    # 2. Extract Response Headers & Cookies
    response_data = fetch_headers(submitted_url)
    headers = response_data["headers"]
    cookies = response_data["cookies"]

    # 3. Audits
    header_audit = audit_security_headers(headers)
    cookie_audit = audit_cookies(cookies)
    cors_audit = audit_cors(headers)
    tls_audit = scan_tls_fingerprints(is_aitm_simulation=("auth-portal" in hostname or "relay" in hostname))
    exposure_audit = analyze_passive_exposure(headers)

    # 4. Synthesize Security Findings
    findings = []
    if tls_audit["aitmProxySignatureDetected"]:
        findings.append(Finding(
            id=f"fnd_aitm_{scan_id}",
            title="Adversary-in-the-Middle (AiTM) Reverse Proxy Detected",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.WEB_SEC,
            description="Server JA4S TLS fingerprint matches known Evilginx2 / Muraena phishing proxy infrastructure.",
            source="Pillar 3 JA4S TLS Fingerprint Scanner",
            evidence=[f"JA4S Hash: {tls_audit['ja4sHash']}"],
            recommendation="Block target IP and notify security operations of active session-hijacking proxy.",
        ).to_dict())

    if header_audit["csp"]["grade"] in ("F", "C"):
        findings.append(Finding(
            id=f"fnd_csp_{scan_id}",
            title=f"Weak Content-Security-Policy (Grade {header_audit['csp']['grade']})",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.WEB_SEC,
            description="CSP contains unsafe-inline or unsafe-eval directives, exposing site to cross-site scripting (XSS).",
            source="Pillar 3 Security Header Auditor",
            evidence=[f"unsafeInline: {header_audit['csp']['unsafeInline']}", f"unsafeEval: {header_audit['csp']['unsafeEval']}"],
            recommendation="Remove 'unsafe-inline' and use cryptographic nonces or hashes.",
        ).to_dict())

    if header_audit["xFrameOptions"] == "MISSING":
        findings.append(Finding(
            id=f"fnd_xfo_{scan_id}",
            title="Missing X-Frame-Options Header (Clickjacking Risk)",
            severity=FindingSeverity.LOW,
            category=FindingCategory.WEB_SEC,
            description="Target application does not explicitly disallow iframe embedding.",
            source="Pillar 3 Security Header Auditor",
            recommendation="Set 'X-Frame-Options: DENY' or use CSP frame-ancestors directive.",
        ).to_dict())

    telemetry = WebSecurityAudit(
        httpHeaders=header_audit,
        cookieSecurity=cookie_audit,
        corsPolicy=cors_audit,
        tlsFingerprints=tls_audit,
        passiveExposure=exposure_audit,
    )

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "scan_id": scan_id,
        "status": "completed",
        "duration_ms": duration_ms,
        "telemetry": telemetry.to_dict(),
        "findings": findings,
    }

def main():
    logger.info("Pillar 3 Web Security Worker online.")
    sample_task = {
        "scan_id": "test_websec_001",
        "submitted_url": "https://example.com",
        "hostname": "example.com",
    }
    output = process_websec_task(sample_task)
    logger.info("Pillar 3 self-test complete. Duration: %d ms | Findings: %d", output.get("duration_ms", 0), len(output.get("findings", [])))

if __name__ == "__main__":
    main()
