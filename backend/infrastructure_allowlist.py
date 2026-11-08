"""
Trust Shield — Verified First-Party Infrastructure & Shared-Host Allowlist
=============================================================================
Protects legitimate high-reputation shared infrastructure (GitHub, Google,
Cloudflare, Microsoft, AWS, Wikipedia, etc.) against false-positive domain-level
threat blocks caused by malicious user content or substrings.
=============================================================================
"""

from typing import Set

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

# Major verified reputable global domains that possess established identity tenure
VERIFIED_REPUTABLE_DOMAINS: Set[str] = {
    "github.com",
    "google.com",
    "cloudflare.com",
    "wikipedia.org",
    "iana.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "youtube.com",
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
    "openai.com",
    "anthropic.com",
    "mozilla.org",
    "w3.org",
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    "python.org",
    "golang.org",
    "rust-lang.org",
    "nodejs.org",
    "npmjs.com",
    "docker.com",
    "kubernetes.io",
}

# Verified reputable ASNs representing global tier-1/cloud infrastructure
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

def is_verified_infrastructure(hostname: str, asn: str = "") -> bool:
    """
    Returns True if the hostname or ASN belongs to verified, reputable,
    first-party infrastructure.
    """
    if not hostname:
        return False
    h = hostname.lower().strip()
    if h.startswith("www."):
        h = h[4:]

    for d in VERIFIED_REPUTABLE_DOMAINS:
        if h == d or h.endswith("." + d):
            return True

    if asn:
        asn_upper = asn.upper()
        if any(rep in asn_upper for rep in REPUTABLE_ASNS):
            return True

    return False

def is_shared_hosting_platform(hostname: str) -> bool:
    """
    Returns True if the hostname represents a shared hosting platform, CDN,
    or user-content repository where only exact full URL path matches should be honored.
    """
    if not hostname:
        return False
    h = hostname.lower().strip()
    if h.startswith("www."):
        h = h[4:]

    for s in VERIFIED_SHARED_HOSTS:
        if h == s or h.endswith("." + s):
            return True

    return False
