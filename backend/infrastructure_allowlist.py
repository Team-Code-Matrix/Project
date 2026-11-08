"""
Trust Shield — Verified First-Party Infrastructure & Shared-Host Allowlist
=============================================================================
Protects legitimate high-reputation shared infrastructure (GitHub, Google,
Cloudflare, Microsoft, AWS, Wikipedia, etc.) against false-positive domain-level
threat blocks caused by user content, login forms, or substring matches.
=============================================================================
"""

import urllib.parse
from typing import Set, Optional

# Trusted mainstream global platforms & registrable domains
TRUSTED_MAINSTREAM_DOMAINS: Set[str] = {
    "github.com",
    "google.com",
    "googleapis.com",
    "cloudflare.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "iana.org",
    "vercel.app",
    "onrender.com",
    "supabase.co",
    "linkedin.com",
    "youtube.com",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "mozilla.org",
    "ubuntu.com",
    "debian.org",
    "oracle.com",
    "ibm.com",
    "chatgpt.com",
    "openai.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "meta.com",
    "netflix.com",
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "stripe.com",
    "anthropic.com",
    "w3.org",
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    "python.org",
    "golang.org",
    "rust-lang.org",
    "nodejs.org",
    "docker.com",
    "kubernetes.io",
}

# Shared platforms and CDNs where individual user file paths might be flagged
# in threat feeds, but the apex domain and normal pages are legitimate.
VERIFIED_SHARED_HOSTS: Set[str] = {
    "github.com",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "gitlab.com",
    "google.com",
    "docs.google.com",
    "drive.google.com",
    "sites.google.com",
    "storage.googleapis.com",
    "cloudflare.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "azurewebsites.net",
    "amazonaws.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "firebaseapp.com",
    "web.app",
    "discord.com",
    "discordapp.com",
    "telegram.org",
    "t.me",
    "wikipedia.org",
    "iana.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "dropbox.com",
    "box.com",
    "sharepoint.com",
    "herokuapp.com",
    "render.com",
    "onrender.com",
}

# Verified reputable ASNs representing global tier-1/cloud hyperscale infrastructure
REPUTABLE_ASNS: Set[str] = {
    "GITHUB",
    "GOOGLE",
    "CLOUDFLARE",
    "MICROSOFT",
    "AMAZON",
    "FASTLY",
    "AKAMAI",
    "META",
    "APPLE",
    "VERISIGN",
    "WIKIMEDIA",
}

# Backwards compatibility alias
VERIFIED_REPUTABLE_DOMAINS: Set[str] = TRUSTED_MAINSTREAM_DOMAINS


def extract_clean_hostname(url_or_hostname: str) -> str:
    """
    Extracts the normalized lowercase hostname without port, path, or leading www.
    """
    if not url_or_hostname:
        return ""
    target = url_or_hostname.strip().lower()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        h = (parsed.hostname or parsed.netloc or "").split(":")[0]
    else:
        h = target.split("/")[0].split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    return h


def is_verified_infrastructure(
    url_or_hostname: str,
    asn: str = "",
    domain_age_days: Optional[int] = None,
    is_typosquat: bool = False,
) -> bool:
    """
    Returns True if the hostname or ASN belongs to verified, reputable,
    first-party infrastructure.
    """
    h = extract_clean_hostname(url_or_hostname)
    if not h:
        return False

    # Check against trusted mainstream domains (exact match or subdomain)
    for d in TRUSTED_MAINSTREAM_DOMAINS:
        if h == d or h.endswith("." + d):
            return True

    # Hyperscale ASN verification with anti-lookalike age protection
    if asn and not is_typosquat:
        asn_upper = asn.upper()
        if any(rep in asn_upper for rep in REPUTABLE_ASNS):
            if domain_age_days is None or domain_age_days > 180:
                return True

    return False


def is_shared_hosting_platform(url_or_hostname: str) -> bool:
    """
    Returns True if the target represents a shared hosting platform, CDN,
    or user-content repository where only exact full URL path matches should be honored.
    """
    h = extract_clean_hostname(url_or_hostname)
    if not h:
        return False

    for s in VERIFIED_SHARED_HOSTS:
        if h == s or h.endswith("." + s):
            return True

    return False
