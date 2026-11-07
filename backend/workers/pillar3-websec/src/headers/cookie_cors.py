"""
Session Cookie & CORS Policy Inspector
Audits Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes.
Audits Access-Control-Allow-Origin headers for insecure wildcard origins and origin reflection.
"""
from typing import Dict, Any, List

def audit_cookies(raw_cookies: List[str]) -> Dict[str, Any]:
    total_cookies = len(raw_cookies)
    missing_secure = 0
    missing_httponly = 0
    missing_samesite = 0

    for cookie in raw_cookies:
        cookie_lower = cookie.lower()
        if "secure" not in cookie_lower:
            missing_secure += 1
        if "httponly" not in cookie_lower:
            missing_httponly += 1
        if "samesite" not in cookie_lower:
            missing_samesite += 1

    session_safe = (missing_secure == 0 and missing_httponly == 0)

    return {
        "totalCookiesCount": total_cookies,
        "secureFlagsMissingCount": missing_secure,
        "httpOnlyMissingCount": missing_httponly,
        "sameSiteMissingCount": missing_samesite,
        "sessionCookiesSafe": session_safe if total_cookies > 0 else True,
    }

def audit_cors(headers: Dict[str, str], origin_header: str = "https://evil-attacker.com") -> Dict[str, Any]:
    normalized = {k.lower(): v for k, v in headers.items()}
    allow_origin = normalized.get("access-control-allow-origin", "")
    allow_credentials = normalized.get("access-control-allow-credentials", "").lower() == "true"

    wildcard_origin = (allow_origin == "*")
    origin_reflection = (origin_header in allow_origin)

    verdict = "RESTRICTED"
    if wildcard_origin and not allow_credentials:
        verdict = "PERMISSIVE"
    elif (wildcard_origin or origin_reflection) and allow_credentials:
        verdict = "VULNERABLE"

    return {
        "wildcardOrigin": wildcard_origin,
        "originReflection": origin_reflection,
        "credentialsAllowed": allow_credentials,
        "verdict": verdict,
    }

