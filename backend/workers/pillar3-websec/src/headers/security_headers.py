"""
HTTP Security Header Auditor
Audits headers against OWASP Secure Headers baseline:
Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options,
X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy.
"""
from typing import Dict, Any, Tuple

def audit_csp(raw_csp: str) -> Dict[str, Any]:
    if not raw_csp:
        return {
            "present": False,
            "directivesCount": 0,
            "unsafeInline": False,
            "unsafeEval": False,
            "wildcardOrigins": False,
            "grade": "F",
            "rawHeader": "",
        }

    directives = [d.strip() for d in raw_csp.split(";") if d.strip()]
    unsafe_inline = "'unsafe-inline'" in raw_csp
    unsafe_eval = "'unsafe-eval'" in raw_csp
    wildcard_origins = " *" in raw_csp or " *;" in raw_csp

    # Calculate grade
    grade = "A+"
    if unsafe_eval:
        grade = "B"
    if unsafe_inline:
        grade = "C"
    if wildcard_origins:
        grade = "C"
    if unsafe_inline and unsafe_eval:
        grade = "F"

    return {
        "present": True,
        "directivesCount": len(directives),
        "unsafeInline": unsafe_inline,
        "unsafeEval": unsafe_eval,
        "wildcardOrigins": wildcard_origins,
        "grade": grade,
        "rawHeader": raw_csp[:256],
    }

def audit_hsts(raw_hsts: str) -> Dict[str, Any]:
    if not raw_hsts:
        return {
            "present": False,
            "maxAgeSeconds": 0,
            "includeSubdomains": False,
            "preloaded": False,
            "grade": "DEFICIENT",
        }

    max_age = 0
    parts = [p.strip().lower() for p in raw_hsts.split(";")]
    for p in parts:
        if p.startswith("max-age="):
            try:
                max_age = int(p.split("=")[1])
            except ValueError:
                pass

    include_subdomains = "includesubdomains" in parts
    preloaded = "preload" in parts

    grade = "DEFICIENT"
    if max_age >= 31536000 and include_subdomains and preloaded:
        grade = "EXCELLENT"
    elif max_age >= 10886400: # 90+ days
        grade = "ADEQUATE"

    return {
        "present": True,
        "maxAgeSeconds": max_age,
        "includeSubdomains": include_subdomains,
        "preloaded": preloaded,
        "grade": grade,
    }

def audit_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    normalized = {k.lower(): v for k, v in headers.items()}

    csp_header = normalized.get("content-security-policy", "")
    hsts_header = normalized.get("strict-transport-security", "")
    xfo_header = normalized.get("x-frame-options", "MISSING").upper()
    nosniff = normalized.get("x-content-type-options", "").lower() == "nosniff"
    referrer = normalized.get("referrer-policy", "strict-origin-when-cross-origin")
    permissions = normalized.get("permissions-policy")

    return {
        "csp": audit_csp(csp_header),
        "hsts": audit_hsts(hsts_header),
        "xFrameOptions": xfo_header if xfo_header in ("DENY", "SAMEORIGIN", "ALLOW-FROM") else "MISSING",
        "xContentTypeOptionsNosniff": nosniff,
        "referrerPolicy": referrer,
        "permissionsPolicy": permissions,
    }

