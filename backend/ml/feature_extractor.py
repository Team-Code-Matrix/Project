"""
TrustShield ML Phishing Engine - Feature Extractor
Extracts 15 deterministic lexical, domain, and transport security features
from any raw URL and optional scan telemetry payload.
"""
import re
import math
import urllib.parse
from typing import Dict, List, Optional, Any

FEATURE_NAMES = [
    "url_length",
    "shannon_entropy",
    "subdomain_count",
    "digit_to_letter_ratio",
    "special_char_count",
    "is_ip_in_url",
    "is_suspicious_tld",
    "is_punycode",
    "brand_keyword_presence",
    "path_depth",
    "query_param_count",
    "is_https",
    "domain_age_indicator",
    "has_form_or_password_input",
    "redirect_count",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "rest",
    "fit", "cam", "live", "club", "online", "site", "vip", "monster",
    "sbs", "click", "casa", "work", "cn", "bid", "loan", "zip", "cc"
}

PROTECTED_BRANDS = {
    "microsoft", "office365", "google", "gmail", "paypal", "apple", "icloud",
    "amazon", "aws", "netflix", "facebook", "instagram", "meta", "whatsapp",
    "bankofamerica", "chase", "wellsfargo", "citibank", "coinbase", "binance",
    "metamask", "ledger", "trezor", "kraken", "github", "gitlab", "dropbox",
    "adobe", "docusign", "twitter", "linkedin", "steam", "telegram", "walmart",
    "ebay", "target", "dhl", "fedex", "usps", "ups"
}

DECEPTIVE_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "account", "banking", "wallet",
    "recover", "recovery", "auth", "authenticate", "portal", "support",
    "billing", "confirm", "validation", "service", "helpdesk", "resolve",
    "webscr", "cmd", "session", "password", "credential", "suspend"
}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(url: str, scan_payload: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Extracts 15 deterministic features from a URL and optional scan telemetry.
    Returns a dictionary of feature names mapped to float values.
    """
    clean_url = url.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.netloc or "").split(":")[0].lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_str = f"{hostname}{path}?{query}".lower()

    # 1. url_length
    url_length = float(len(clean_url))

    # 2. shannon_entropy (of hostname + path)
    entropy_target = hostname + path if path else hostname
    shannon_entropy = calculate_shannon_entropy(entropy_target)

    # 3. subdomain_count
    host_parts = hostname.split(".")
    # If standard domain e.g. example.com -> 0 subdomains, sub.example.com -> 1
    subdomain_count = float(max(0, len(host_parts) - 2))

    # 4. digit_to_letter_ratio
    digit_count = sum(c.isdigit() for c in clean_url)
    letter_count = sum(c.isalpha() for c in clean_url)
    digit_to_letter_ratio = round(digit_count / (letter_count + 1.0), 4)

    # 5. special_char_count (@/-/_/=/?/%/&/+)
    special_chars = set("@-_=?%&+")
    special_char_count = float(sum(c in special_chars for c in clean_url))

    # 6. is_ip_in_url
    is_ip_in_url = 1.0 if IP_REGEX.match(hostname) else 0.0

    # 7. is_suspicious_tld
    tld = host_parts[-1] if len(host_parts) > 1 else ""
    is_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 8. is_punycode
    is_punycode = 1.0 if ("xn--" in hostname) else 0.0

    # 9. brand_keyword_presence
    # Check if a protected brand or deceptive keyword appears on a third-party domain
    brand_present = False
    tokens = re.split(r"[-._/]", full_str)
    tokens = [t for t in tokens if t]

    for token in tokens:
        # Check normalized substitutions (0->o, 1->l, etc.)
        norm = token.replace("0", "o").replace("1", "l").replace("5", "s").replace("vv", "w")
        if token in PROTECTED_BRANDS or norm in PROTECTED_BRANDS:
            # Check if this is the legitimate canonical domain
            is_canonical = (
                hostname == f"{token}.com" or
                hostname == f"www.{token}.com" or
                hostname == f"{token}.org" or
                hostname == f"{token}.net" or
                hostname == f"{token}.io"
            )
            if not is_canonical:
                brand_present = True
                break
        elif token in DECEPTIVE_KEYWORDS:
            brand_present = True
            break

    brand_keyword_presence = 1.0 if brand_present else 0.0

    # 10. path_depth (number of non-empty slash segments)
    path_segments = [p for p in path.split("/") if p]
    path_depth = float(len(path_segments))

    # 11. query_param_count
    if query:
        query_params = [q for q in query.split("&") if q]
        query_param_count = float(len(query_params))
    else:
        query_param_count = 0.0

    # 12. is_https
    is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

    # 13. domain_age_indicator (0.0 = new/low trust, 1.0 = established 365+ days)
    # Extract from scan_payload if provided, else compute based on reputation hints
    domain_age = 0.5  # Neutral default
    if scan_payload:
        if scan_payload.get("is_nxdomain") or scan_payload.get("dnsStatus") == "NXDOMAIN" or not scan_payload.get("is_live", True):
            domain_age = 0.0
        else:
            age_days = scan_payload.get("domainAgeDays") or scan_payload.get("ageDays")
            if age_days is not None:
                domain_age = min(1.0, max(0.0, float(age_days) / 365.0))
            elif scan_payload.get("rdapTenureVerified") or "RDAP_TENURE_VERIFIED" in scan_payload.get("analystReasonCodes", []):
                domain_age = 1.0
            elif scan_payload.get("domainRegisteredDaysAgo", 0) > 180:
                domain_age = 0.9
    else:
        # Heuristic estimation if payload not yet available
        if is_suspicious_tld or is_ip_in_url or is_punycode:
            domain_age = 0.1
        elif hostname in {"google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org"}:
            domain_age = 1.0
        elif any(hostname.endswith(f".{b}.com") or hostname == f"{b}.com" for b in PROTECTED_BRANDS):
            domain_age = 0.95

    # 14. has_form_or_password_input
    has_form = 0.0
    if scan_payload:
        dom_h = scan_payload.get("phishingDetonation", {}).get("domHeuristics", {})
        if dom_h.get("passwordInputsCount", 0) > 0 or dom_h.get("otpFieldsCount", 0) > 0:
            has_form = 1.0
        elif scan_payload.get("hasPasswordInput") or scan_payload.get("hasLoginForm"):
            has_form = 1.0
    else:
        # Check URL tokens for password/login indicators
        if any(kw in full_str for kw in ["password", "login", "signin", "credential", "auth"]):
            has_form = 1.0 if brand_present or not is_https else 0.0

    # 15. redirect_count
    redirect_count = 0.0
    if scan_payload:
        chain = scan_payload.get("phishingDetonation", {}).get("redirectChain", [])
        if chain:
            redirect_count = float(max(0, len(chain) - 1))
        elif "redirectHops" in scan_payload:
            redirect_count = float(scan_payload["redirectHops"])
    else:
        # If url contains redirect parameters like ?next=, ?redirect=, etc.
        if any(param in query for param in ["next=", "redirect=", "url=", "dest=", "return="]):
            redirect_count = 1.0

    return {
        "url_length": url_length,
        "shannon_entropy": shannon_entropy,
        "subdomain_count": subdomain_count,
        "digit_to_letter_ratio": digit_to_letter_ratio,
        "special_char_count": special_char_count,
        "is_ip_in_url": is_ip_in_url,
        "is_suspicious_tld": is_suspicious_tld,
        "is_punycode": is_punycode,
        "brand_keyword_presence": brand_keyword_presence,
        "path_depth": path_depth,
        "query_param_count": query_param_count,
        "is_https": is_https,
        "domain_age_indicator": round(domain_age, 4),
        "has_form_or_password_input": has_form,
        "redirect_count": redirect_count,
    }

def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Converts feature dictionary to a list in exact FEATURE_NAMES order."""
    return [features[name] for name in FEATURE_NAMES]

