"""
Trust Shield — Verified First-Party Infrastructure & Shared-Host Allowlist
=============================================================================
Protects legitimate high-reputation shared infrastructure (GitHub, Google,
WhatsApp, Cloudflare, Microsoft, AWS, Wikipedia, etc.) against false-positive
domain-level threat blocks caused by user content, login forms, or substring matches.
=============================================================================
"""

import urllib.parse
from typing import Set, Optional

# Official mainstream platforms guaranteed immunity against false-positive vetoes
HARD_BYPASS_DOMAINS: Set[str] = {
    "github.com",
    "whatsapp.com",
    "google.com",
    "googleapis.com",
    "youtube.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "cloudflare.com",
    "wikipedia.org",
    "iana.org",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "meta.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "reddit.com",
    "netflix.com",
    "spotify.com",
    "discord.com",
    "telegram.org",
    "openai.com",
    "chatgpt.com",
    "vercel.app",
    "onrender.com",
    "supabase.co",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "mozilla.org",
    "ubuntu.com",
    "debian.org",
    "oracle.com",
    "ibm.com",
    "paypal.com",
    "stripe.com",
    "anthropic.com",
    "dropbox.com",
}

TRUSTED_MAINSTREAM_DOMAINS: Set[str] = HARD_BYPASS_DOMAINS

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
    "whatsapp.com",
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

MULTI_PART_TLDS: Set[str] = {
    "co.uk", "org.uk", "me.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in", "gen.in",
    "co.za", "org.za", "net.za",
    "co.jp", "ne.jp", "or.jp",
    "co.nz", "net.nz", "org.nz",
    "com.br", "net.br", "org.br",
    "com.sg", "edu.sg",
    "com.mx", "org.mx",
    "com.tr", "edu.tr",
    "co.kr", "or.kr",
}

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


def get_registrable_domain(hostname: str) -> str:
    """
    Extracts the apex / registrable domain from any hostname.
    e.g.
      'web.whatsapp.com' -> 'whatsapp.com'
      'login.microsoft.com' -> 'microsoft.com'
      'docs.google.co.uk' -> 'google.co.uk'
      'github.com' -> 'github.com'
    """
    if not hostname:
        return ""
    h = extract_clean_hostname(hostname)
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS:
        if len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        return h
    return f"{parts[-2]}.{parts[-1]}"


def is_hard_bypass_target(url_or_hostname: str) -> bool:
    """
    Returns True if target is an official mainstream platform / authentic subdomain
    and NOT a direct executable binary on a raw file hosting platform.
    """
    if not url_or_hostname:
        return False
    target = url_or_hostname.strip().lower()
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    h = (parsed.hostname or parsed.netloc or "").split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    path = parsed.path.lower()

    # Exclude direct raw binary downloads on raw.githubusercontent.com
    if "raw.githubusercontent.com" in h:
        if path.endswith((".exe", ".sh", ".elf", ".bin", ".vbs", ".bat", ".ps1", ".dll", ".apk")):
            return False

    reg_dom = get_registrable_domain(h)
    for d in HARD_BYPASS_DOMAINS:
        if h == d or h.endswith("." + d) or reg_dom == d:
            return True
    return False


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

    if is_hard_bypass_target(h):
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

    reg_dom = get_registrable_domain(h)
    for s in VERIFIED_SHARED_HOSTS:
        if h == s or h.endswith("." + s) or reg_dom == s:
            return True

    return False
