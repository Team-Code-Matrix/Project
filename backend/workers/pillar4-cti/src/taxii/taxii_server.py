"""
OASIS TAXII 2.1 Federation Module
Defines TAXII 2.1 endpoints and enforces Canary Allowlist checks against threat feed poisoning.
"""
from typing import Dict, Any, List

CANARY_PROTECTED_DOMAINS = {
    "google.com", "accounts.google.com",
    "microsoft.com", "login.microsoftonline.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "github.com",
    "cloudflare.com",
}

def is_canary_domain_protected(domain: str) -> bool:
    """Verifies that high-trust canary domains cannot be auto-blocked by ingested external feeds."""
    clean = domain.lower().strip()
    return clean in CANARY_PROTECTED_DOMAINS or any(clean.endswith("." + canary) for canary in CANARY_PROTECTED_DOMAINS)

def get_taxii_discovery_root() -> Dict[str, Any]:
    """Returns TAXII 2.1 server discovery root structure."""
    return {
        "title": "TrustShield OASIS TAXII 2.1 Threat Federation",
        "description": "Bi-directional threat intelligence exchange server.",
        "contact": "soc@trustshield.internal",
        "default": "/taxii2/api-root/",
        "api_roots": ["/taxii2/api-root/"],
    }

