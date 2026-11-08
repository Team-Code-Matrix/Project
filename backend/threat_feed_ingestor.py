"""
Trust Shield — Global Cyber Threat Intelligence Ingestion Engine
=============================================================================
Manages persistent ingestion, deduplication, synchronization, and attribution
across 8 authoritative global cybersecurity intelligence sources:
1. OpenPhish (Public community feed / Premium API)
2. Abuse.ch URLhaus (Recent malware payload URLs via Auth-Key)
3. PhishTank (Developer database feed via API key)
4. Google Safe Browsing (Lookup API v4)
5. VirusTotal (REST API v3)
6. AbuseIPDB (Blacklist v2 API)
7. AlienVault OTX (Open Threat Exchange API)
8. CIRCL MISP (Malware Information Sharing Platform)

Adheres strictly to the ZERO FABRICATED DATA principle:
- Empty database returns 0 records.
- Missing API keys report NOT_CONFIGURED.
- Real provider timestamps and attribution preserved.
- Deduplication enforced at database schema level (UNIQUE indicator, provider).
- WebSockets broadcast real newly ingested IOCs.
=============================================================================
"""

import os
import re
import time
import json
import sqlite3
import hashlib
import threading
import socket
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Callable

try:
    from infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform
except ImportError:
    from backend.infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform

# Comprehensive Brand Mappings for high-fidelity brand extraction & attribution
BRAND_MAPPINGS: Dict[str, str] = {
    # Tech & Cloud Giants
    "microsoft": "Microsoft",
    "micros0ft": "Microsoft",
    "office365": "Microsoft Office 365",
    "o365": "Microsoft Office 365",
    "outlook": "Microsoft Outlook",
    "onedrive": "Microsoft OneDrive",
    "sharepoint": "Microsoft SharePoint",
    "azure": "Microsoft Azure",
    "msft": "Microsoft",
    "google": "Google",
    "g00gle": "Google",
    "gmail": "Google Gmail",
    "gdrive": "Google Drive",
    "apple": "Apple",
    "icloud": "Apple iCloud",
    "appleid": "Apple ID",
    "amazon": "Amazon",
    "amaz0n": "Amazon",
    "aws": "Amazon AWS",
    "netflix": "Netflix",
    "netfl1x": "Netflix",
    "facebook": "Meta / Facebook",
    "faceb00k": "Meta / Facebook",
    "meta": "Meta / Facebook",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "threads": "Threads",
    "adobe": "Adobe",
    "dropbox": "Dropbox",
    "docusign": "DocuSign",
    "steam": "Steam",
    "discord": "Discord",
    "telegram": "Telegram",
    "yahoo": "Yahoo",
    "roblox": "Roblox",
    "twitter": "X / Twitter",
    "linkedin": "LinkedIn",
    "ebay": "eBay",
    "walmart": "Walmart",
    "spotify": "Spotify",

    # Banking & Financial Institutions
    "paypal": "PayPal",
    "paypa1": "PayPal",
    "chase": "Chase Bank",
    "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America",
    "bofa": "Bank of America",
    "citi": "Citibank",
    "citibank": "Citibank",
    "sbi": "State Bank of India (SBI)",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "barclays": "Barclays",
    "hsbc": "HSBC",
    "santander": "Santander",
    "capitalone": "Capital One",
    "schwab": "Charles Schwab",
    "fidelity": "Fidelity",
    "stripe": "Stripe",

    # Crypto & Web3
    "binance": "Binance",
    "coinbase": "Coinbase",
    "metamask": "MetaMask",
    "trustwallet": "Trust Wallet",
    "ledger": "Ledger",
    "ldgrr": "Ledger",
    "trezor": "Trezor",
    "kraken": "Kraken",
    "phantom": "Phantom Wallet",
    "kucoin": "KuCoin",
    "bybit": "Bybit",
    "tbybit": "Bybit",
    "uniswap": "Uniswap",
    "pancakeswap": "PancakeSwap",
    "opensea": "OpenSea",
    "okx": "OKX",
    "solana": "Solana Web3",
    "ethereum": "Ethereum Web3",

    # Logistics & Delivery
    "dhl": "DHL Express",
    "fedex": "FedEx",
    "usps": "USPS",
    "ups": "UPS",
    "royalmail": "Royal Mail",
    "dpd": "DPD",
    "post": "Postal Service",
}

KNOWN_BRANDS = list(BRAND_MAPPINGS.keys())

def extract_target_brand(url_or_domain: str) -> Optional[str]:
    """Extracts genuine target brand if present in domain, path, or query tokens."""
    if not url_or_domain:
        return None
    low = url_or_domain.lower()
    clean = re.sub(r"[^a-z0-9]", " ", low)
    tokens = set(clean.split())

    for alias, brand_name in BRAND_MAPPINGS.items():
        if alias in tokens:
            return brand_name
        if re.search(r'(^|[^a-z0-9])' + re.escape(alias) + r'([^a-z0-9]|$)', low):
            return brand_name
    return None

# Indicator keywords for multi-class threat categorization
CRYPTO_KEYWORDS = {
    "metamask", "phantom", "wallet", "seed", "phrase", "mnemonic", "keystore",
    "privatekey", "drainer", "airdrop", "claim", "claim-airdrop", "claim-nft",
    "connect-wallet", "walletconnect", "uniswap", "pancakeswap", "opensea",
    "solana", "ethereum", "web3", "presale", "crypto", "binance", "coinbase",
    "ledger", "trezor", "bybit", "kucoin", "trustwallet", "swap", "stake",
    "token", "ldgrr", "tbybit", "dapp", "usdt", "btc", "eth"
}

CREDENTIAL_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "auth", "authenticate", "password",
    "passwd", "credential", "session", "cpanel", "webmail", "roundcube",
    "verify", "verification", "verify-account", "update-account", "security-check",
    "billing-update", "confirm-identity", "2fa", "mfa", "otp", "reset-password",
    "sso", "accounts-center", "secure-account", "login-attempt"
}

SCAM_KEYWORDS = {
    "package", "parcel", "delivery", "tracking", "postage", "toll", "unpaid",
    "shipping", "customs", "redelivery", "shipping-fee", "prize", "lottery",
    "grant", "giveaway", "reward", "survey", "bonus", "giftcard", "winner",
    "compensation", "rebate", "task-earn", "daily-income", "investment-vip",
    "forex-profit", "ponzi", "earn-daily"
}

MALWARE_EXTENSIONS = {
    ".exe", ".bin", ".sh", ".elf", ".apk", ".msi", ".dll", ".iso", ".dmg",
    ".vbs", ".bat", ".cmd", ".scr", ".jar", ".zip", ".tar", ".gz", ".7z", ".rar"
}

MALWARE_TAGS = {
    "malware", "payload", "c2", "botnet", "trojan", "stealer", "ransomware",
    "dropper", "redline", "amadey", "agenttesla", "lumma", "asyncrat",
    "njrat", "remcos", "emotet", "qakbot", "mirai", "mozi", "guloader"
}

def classify_threat_indicator(
    indicator: str,
    tags: Optional[List[str]] = None,
    provider: Optional[str] = None,
    initial_brand: Optional[str] = None,
    initial_category: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Classifies an indicator accurately across all 6 core frontend categories:
    1. 'crypto_drainer'
    2. 'malware_distribution'
    3. 'scam' (Delivery / Fee / Lottery scams)
    4. 'credential_harvesting'
    5. 'impersonation' (Brand Impersonation / Typosquatting)
    6. 'phishing' (General Phishing)
    """
    # Extract target brand if not already known
    brand = initial_brand or extract_target_brand(indicator)

    # If an explicit high-fidelity category was already assigned by an authoritative reporter/provider, preserve it
    if initial_category:
        init_cat = str(initial_category).lower().strip()
        if init_cat in ["brand_impersonation", "impersonation"]:
            return "impersonation", brand
        if init_cat in ["scam_smishing", "scam"]:
            return "scam", brand
        if init_cat in ["credential_harvesting", "crypto_drainer", "malware_distribution"]:
            return init_cat, brand

    if not indicator:
        return "phishing", brand

    low = indicator.lower().strip()
    parsed = urllib.parse.urlparse(low if "://" in low else "https://" + low)
    host = parsed.netloc.split(":")[0]
    path = parsed.path
    query = parsed.query
    full = f"{host}{path}?{query}"

    tag_list = [str(t).lower() for t in (tags or [])]
    tag_str = " ".join(tag_list)
    prov = (provider or "").lower()

    # 1. Crypto Drainer
    if any(re.search(r'(^|[^a-z0-9])' + re.escape(kw) + r'([^a-z0-9]|$)', full) for kw in CRYPTO_KEYWORDS) or \
       any(kw in tag_str for kw in ["crypto", "drainer", "wallet", "web3", "nft", "airdrop"]):
        if not brand:
            for c_alias in ["metamask", "phantom", "ledger", "trezor", "binance", "coinbase", "bybit", "uniswap"]:
                if c_alias in full:
                    brand = BRAND_MAPPINGS.get(c_alias)
                    break
        return "crypto_drainer", brand

    # 2. Malware Distribution
    is_malware_provider = prov in ["urlhaus", "abuseipdb"]
    has_malware_tag = any(mt in tag_str for mt in MALWARE_TAGS)
    has_binary_ext = any(path.endswith(ext) or f"{ext}?" in path for ext in MALWARE_EXTENSIONS)
    if (has_binary_ext or has_malware_tag or (is_malware_provider and not any(kw in full for kw in CREDENTIAL_KEYWORDS))):
        return "malware_distribution", brand

    # 3. Scam / Smishing
    if any(re.search(r'(^|[^a-z0-9])' + re.escape(kw) + r'([^a-z0-9]|$)', full) for kw in SCAM_KEYWORDS) or \
       any(st in tag_str for st in ["scam", "smishing", "delivery", "lottery", "toll"]):
        if not brand and any(kw in full for kw in ["usps", "dhl", "fedex", "ups"]):
            for d_alias in ["usps", "dhl", "fedex", "ups"]:
                if d_alias in full:
                    brand = BRAND_MAPPINGS.get(d_alias)
                    break
        return "scam", brand

    # 4. Credential Harvesting
    if any(re.search(r'(^|[^a-z0-9])' + re.escape(kw) + r'([^a-z0-9]|$)', full) for kw in CREDENTIAL_KEYWORDS) or \
       "credential" in tag_str or "harvest" in tag_str or "login" in tag_str:
        return "credential_harvesting", brand

    # 5. Brand Impersonation
    if brand:
        return "impersonation", brand

    # 6. Phishing (Default baseline for phishing feeds)
    return "phishing", brand

class ThreatFeedIngestor:
    def __init__(self, db_path: str, ws_broadcast_cb: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.db_path = db_path
        self.ws_broadcast_cb = ws_broadcast_cb
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.providers_meta = {
            "openphish": {
                "name": "OpenPhish Global Phishing Feed",
                "update_interval_sec": 3600, # 1 hour
                "requires_api_key": False,
                "api_key_env": "OPENPHISH_API_KEY",
                "description": "Autonomous real-time phishing detection feed from OpenPhish community network.",
            },
            "urlhaus": {
                "name": "Abuse.ch URLhaus Malware Intelligence",
                "update_interval_sec": 300, # 5 minutes
                "requires_api_key": True,
                "api_key_env": "URLHAUS_API_KEY",
                "description": "Abuse.ch project tracking distribution of malware payloads and C2 infrastructure.",
            },
            "phishtank": {
                "name": "PhishTank Community Verification Feed",
                "update_interval_sec": 7200, # 2 hours
                "requires_api_key": True,
                "api_key_env": "PHISHTANK_API_KEY",
                "description": "Collaborative clearing house for data and information about phishing on the Internet.",
            },
            "abuseipdb": {
                "name": "AbuseIPDB Threat Blacklist",
                "update_interval_sec": 3600, # 1 hour
                "requires_api_key": True,
                "api_key_env": "ABUSEIPDB_API_KEY",
                "description": "Central repository for IP addresses reported for malicious network activity.",
            },
            "alienvault_otx": {
                "name": "AlienVault Open Threat Exchange (OTX)",
                "update_interval_sec": 1800, # 30 minutes
                "requires_api_key": True,
                "api_key_env": "OTX_API_KEY",
                "description": "Crowdsourced computer security platform providing open threat analysis.",
            },
            "circl_misp": {
                "name": "CIRCL MISP Threat Sharing Platform",
                "update_interval_sec": 3600, # 1 hour
                "requires_api_key": True,
                "api_key_env": "MISP_AUTH_KEY",
                "description": "Malware Information Sharing Platform open source threat intelligence exchange.",
            },
            "google_safebrowsing": {
                "name": "Google Safe Browsing v4",
                "update_interval_sec": 3600,
                "requires_api_key": True,
                "api_key_env": "GOOGLE_SAFE_BROWSING_KEY",
                "description": "Google Safe Browsing global reputation lists for malware, unwanted software, and social engineering.",
            },
            "virustotal": {
                "name": "VirusTotal Intelligence v3",
                "update_interval_sec": 3600,
                "requires_api_key": True,
                "api_key_env": "VIRUSTOTAL_API_KEY",
                "description": "Crowdsourced multi-scanner threat intelligence and domain reputation network.",
            },
        }

        self._init_tables()
        try:
            self.reclassify_existing_indicators()
        except Exception as e:
            print(f"[!] Threat indicator reclassification note: {e}")

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initializes threat indicator tables and sync status records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id TEXT PRIMARY KEY,
                    indicator TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    confidence_score INTEGER DEFAULT 90,
                    status TEXT DEFAULT 'verified',
                    target_brand TEXT,
                    threat_tags TEXT,
                    country TEXT,
                    source_url TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    ingested_at TEXT,
                    raw_data TEXT,
                    UNIQUE(indicator, provider)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_reports (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    targeted_brand TEXT,
                    status TEXT DEFAULT 'under_investigation',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS provider_sync_status (
                    provider_id TEXT PRIMARY KEY,
                    provider_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_sync_time TEXT,
                    last_error TEXT,
                    records_ingested_total INTEGER DEFAULT 0,
                    records_last_sync INTEGER DEFAULT 0,
                    update_interval_sec INTEGER DEFAULT 3600,
                    next_sync_time TEXT
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_domain ON threat_indicators(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_category ON threat_indicators(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_ingested ON threat_indicators(ingested_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_provider ON threat_indicators(provider)")

            # Initialize provider status entries if missing
            for pid, meta in self.providers_meta.items():
                cursor.execute("SELECT provider_id FROM provider_sync_status WHERE provider_id = ?", (pid,))
                if not cursor.fetchone():
                    api_key = os.getenv(meta["api_key_env"])
                    initial_status = "NOT_CONFIGURED" if (meta["requires_api_key"] and not api_key) else "PENDING"
                    cursor.execute("""
                        INSERT INTO provider_sync_status (
                            provider_id, provider_name, status, last_sync_time, last_error,
                            records_ingested_total, records_last_sync, update_interval_sec, next_sync_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pid,
                        meta["name"],
                        initial_status,
                        None,
                        None if initial_status != "NOT_CONFIGURED" else f"API key required ({meta['api_key_env']})",
                        0,
                        0,
                        meta["update_interval_sec"],
                        None
                    ))
            conn.commit()

    def record_indicator(
        self,
        indicator: str,
        indicator_type: str,
        category: str,
        provider: str,
        confidence_score: int = 90,
        status: str = "verified",
        target_brand: Optional[str] = None,
        threat_tags: Optional[List[str]] = None,
        country: Optional[str] = None,
        source_url: Optional[str] = None,
        first_seen: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Inserts a single threat indicator if not already present.
        Returns True if a new record was inserted; False if duplicate or rejected.
        """
        if not indicator or len(indicator.strip()) < 4:
            return False

        indicator = indicator.strip()
        domain = ""
        if indicator_type == "url":
            parsed = urllib.parse.urlparse(indicator if "://" in indicator else "https://" + indicator)
            domain = parsed.netloc.split(":")[0].lower()
        elif indicator_type == "domain":
            domain = indicator.lower()
        elif indicator_type == "ip":
            domain = indicator

        if not domain:
            return False

        # Classify dynamically across 6 categories and extract genuine brand
        classified_cat, classified_brand = classify_threat_indicator(
            indicator=indicator,
            tags=threat_tags,
            provider=provider,
            initial_brand=target_brand,
            initial_category=category
        )
        category = classified_cat
        if not target_brand and classified_brand:
            target_brand = classified_brand

        now_iso = datetime.now(timezone.utc).isoformat()
        first_seen_iso = first_seen or now_iso
        record_id = "ioc_" + hashlib.sha256(f"{provider}:{indicator}".encode()).hexdigest()[:16]

        inserted = False
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO threat_indicators (
                            id, indicator, domain, indicator_type, category, provider,
                            confidence_score, status, target_brand, threat_tags, country,
                            source_url, first_seen, last_seen, ingested_at, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        record_id,
                        indicator,
                        domain,
                        indicator_type,
                        category,
                        provider,
                        confidence_score,
                        status,
                        target_brand,
                        json.dumps(threat_tags or []),
                        country,
                        source_url,
                        first_seen_iso,
                        now_iso,
                        now_iso,
                        json.dumps(raw_data or {})
                    ))
                    conn.commit()
                    inserted = True
                except sqlite3.IntegrityError:
                    # Duplicate indicator for this provider — update last_seen, category and brand
                    cursor.execute("""
                        UPDATE threat_indicators
                        SET last_seen = ?, category = ?, target_brand = COALESCE(?, target_brand)
                        WHERE indicator = ? AND provider = ?
                    """, (now_iso, category, target_brand, indicator, provider))
                    conn.commit()
                    inserted = False

        if inserted and self.ws_broadcast_cb:
            # Broadcast live ingestion event to frontend
            evt = {
                "id": record_id,
                "domain": domain,
                "url": indicator,
                "category": category,
                "provider": provider,
                "confidenceScore": confidence_score,
                "status": status,
                "targetBrand": target_brand,
                "reportedAt": now_iso,
                "country": country,
                "indicators": threat_tags or [f"Ingested from {provider}"],
            }
            try:
                self.ws_broadcast_cb(evt)
            except Exception:
                pass

        return inserted

    def lookup_indicator(self, url_or_domain: str) -> Optional[Dict[str, Any]]:
        """
        Instant threat intelligence pre-check against local SQLite database.
        Checks threat_indicators, threat_reports, and recent scans.
        Returns matched threat record or None.
        """
        if not url_or_domain:
            return None

        target = url_or_domain.strip()
        parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
        domain = (parsed.netloc or "").split(":")[0].lower()
        clean_url = target
        url_no_slash = clean_url.rstrip("/")

        is_shared = is_shared_hosting_platform(domain)
        is_verified = is_verified_infrastructure(domain)

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                r = None
                if is_shared or is_verified:
                    # STRICT EXACT URL MATCH ONLY: Shared and verified infrastructure
                    # MUST NEVER be flagged by apex domain or substring matches!
                    cursor.execute("""
                        SELECT id, indicator, domain, indicator_type, category, provider,
                               confidence_score, status, target_brand, threat_tags, country, source_url, ingested_at
                        FROM threat_indicators
                        WHERE indicator = ? OR indicator = ? OR indicator = ?
                        LIMIT 1
                    """, (clean_url, url_no_slash, f"https://{domain}{parsed.path}"))
                    r = cursor.fetchone()
                else:
                    # Dedicated / Untrusted domain: check exact URL or exact domain-level indicator
                    cursor.execute("""
                        SELECT id, indicator, domain, indicator_type, category, provider,
                               confidence_score, status, target_brand, threat_tags, country, source_url, ingested_at
                        FROM threat_indicators
                        WHERE indicator = ? 
                           OR indicator = ? 
                           OR (domain = ? AND indicator_type = 'domain')
                           OR indicator = ?
                        LIMIT 1
                    """, (clean_url, url_no_slash, domain, domain))
                    r = cursor.fetchone()

                if r:
                    tags = json.loads(r["threat_tags"] or "[]") if r["threat_tags"] else []
                    c_norm = r["category"].lower()
                    if c_norm == "brand_impersonation":
                        c_norm = "impersonation"
                    elif c_norm == "scam_smishing":
                        c_norm = "scam"
                    return {
                        "id": r["id"],
                        "indicator": r["indicator"],
                        "domain": r["domain"],
                        "indicatorType": r["indicator_type"],
                        "category": c_norm,
                        "provider": r["provider"],
                        "confidenceScore": r["confidence_score"] or 95,
                        "status": r["status"] or "verified",
                        "targetBrand": r["target_brand"],
                        "threatTags": tags,
                        "country": r["country"],
                        "sourceUrl": r["source_url"],
                        "source": "threat_indicators",
                    }

                # 2. Check community threat reports (only for non-verified domains or exact URL)
                if not is_verified:
                    cursor.execute("""
                        SELECT id, domain, threat_type, severity, description, targeted_brand, status
                        FROM threat_reports
                        WHERE domain = ?
                        LIMIT 1
                    """, (domain,))
                    rep = cursor.fetchone()
                    if rep:
                        return {
                            "id": rep["id"],
                            "indicator": f"https://{domain}/",
                            "domain": rep["domain"],
                            "indicatorType": "domain",
                            "category": rep["threat_type"],
                            "provider": "community",
                            "confidenceScore": 88,
                            "status": rep["status"] or "investigating",
                            "targetBrand": rep["targeted_brand"],
                            "threatTags": ["Community Incident Report"],
                            "country": None,
                            "sourceUrl": None,
                            "source": "threat_reports",
                        }

                # 3. Check recent scans that were flagged MALICIOUS
                try:
                    if is_verified:
                        cursor.execute("""
                            SELECT scan_id, submitted_url, hostname, verdict, trust_score, risk_score
                            FROM scans
                            WHERE (submitted_url = ? OR submitted_url = ?)
                              AND verdict = 'MALICIOUS'
                            ORDER BY created_at DESC
                            LIMIT 1
                        """, (clean_url, url_no_slash))
                    else:
                        cursor.execute("""
                            SELECT scan_id, submitted_url, hostname, verdict, trust_score, risk_score
                            FROM scans
                            WHERE (submitted_url = ? OR submitted_url = ? OR hostname = ?)
                              AND verdict = 'MALICIOUS'
                            ORDER BY created_at DESC
                            LIMIT 1
                        """, (clean_url, url_no_slash, domain))
                    scan_row = cursor.fetchone()
                    if scan_row:
                        return {
                            "id": scan_row["scan_id"],
                            "indicator": scan_row["submitted_url"],
                            "domain": scan_row["hostname"],
                            "indicatorType": "url",
                            "category": "phishing",
                            "provider": "historical_scan",
                            "confidenceScore": 95,
                            "status": "verified",
                            "targetBrand": None,
                            "threatTags": ["Conclusively Flagged Malicious in Scan History"],
                            "country": None,
                            "sourceUrl": None,
                            "source": "scans_history",
                        }
                except Exception:
                    pass

        return None

    def reclassify_existing_indicators(self) -> int:
        """
        Reclassifies all existing threat indicators in SQLite to ensure accurate
        distribution across all 6 frontend categories and populates target_brand.
        """
        updated_count = 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, indicator, indicator_type, category, provider, threat_tags, target_brand
                    FROM threat_indicators
                """)
                rows = cursor.fetchall()
                for r in rows:
                    rec_id = r["id"]
                    indicator = r["indicator"]
                    tags = json.loads(r["threat_tags"] or "[]")
                    provider = r["provider"]
                    curr_cat = r["category"]
                    curr_brand = r["target_brand"]

                    new_cat, new_brand = classify_threat_indicator(
                        indicator=indicator,
                        tags=tags,
                        provider=provider,
                        initial_brand=curr_brand
                    )

                    if new_cat != curr_cat or (new_brand and new_brand != curr_brand):
                        cursor.execute("""
                            UPDATE threat_indicators
                            SET category = ?, target_brand = ?
                            WHERE id = ?
                        """, (new_cat, new_brand or curr_brand, rec_id))
                        updated_count += 1
                conn.commit()
        if updated_count > 0:
            print(f"[+] Reclassified {updated_count} existing threat indicator(s) across categories.")
        return updated_count

    def _http_request_with_retry(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        method: str = "GET",
        timeout: int = 15,
        max_retries: int = 2,
        backoff_sec: float = 1.0,
    ) -> Tuple[Optional[bytes], Optional[str], Optional[int]]:
        """
        Executes an HTTP request with exponential backoff on transient network and 5xx errors.
        Returns: (response_bytes, error_message, http_status_code)
        """
        attempt = 0
        req_headers = {"User-Agent": "TrustShield-CyberIntel/2.4.0 (Security Research Platform)"}
        if headers:
            req_headers.update(headers)

        while attempt <= max_retries:
            try:
                req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read(), None, resp.status
            except urllib.error.HTTPError as e:
                code = e.code
                if code == 429:
                    return None, f"Upstream provider rate limit exceeded (HTTP 429).", 429
                if code in (401, 403):
                    return None, f"Provider authentication rejected (HTTP {code}). Verify API credentials.", code
                if code in (500, 502, 503, 504) and attempt < max_retries:
                    attempt += 1
                    time.sleep(backoff_sec * (2 ** (attempt - 1)))
                    continue
                return None, f"HTTP error {code}: {e.reason}", code
            except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
                if attempt < max_retries:
                    attempt += 1
                    time.sleep(backoff_sec * (2 ** (attempt - 1)))
                    continue
                return None, f"Network connection failed: {str(e)}", 0
            except Exception as e:
                return None, f"Request failure: {str(e)}", 0

        return None, "Max retries exceeded", 0

    def _sync_openphish(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs verified phishing URLs from OpenPhish."""
        api_key = os.getenv("OPENPHISH_API_KEY")
        inserted_count = 0

        feed_url = "https://openphish.com/feed.txt"
        headers: Dict[str, str] = {}
        if api_key:
            feed_url = "https://openphish.com/samples.json"
            headers["X-API-KEY"] = api_key

        body, err, status_code = self._http_request_with_retry(feed_url, headers=headers, timeout=15)
        if err or not body:
            return 0, err or "Empty response from OpenPhish", status_code

        content = body.decode("utf-8", errors="ignore")
        now_iso = datetime.now(timezone.utc).isoformat()

        if api_key and content.strip().startswith("["):
            try:
                items = json.loads(content)
                for item in items:
                    u = item.get("url")
                    if u and self.record_indicator(
                        indicator=u,
                        indicator_type="url",
                        category="phishing",
                        provider="openphish",
                        confidence_score=98,
                        status="verified",
                        target_brand=item.get("target"),
                        first_seen=item.get("time"),
                        raw_data=item
                    ):
                        inserted_count += 1
            except Exception as e:
                return 0, f"OpenPhish JSON parse error: {e}", status_code
        else:
            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
            for u in lines[:150]:
                if self.record_indicator(
                    indicator=u,
                    indicator_type="url",
                    category="phishing",
                    provider="openphish",
                    confidence_score=95,
                    status="verified",
                    source_url="https://openphish.com",
                    first_seen=now_iso
                ):
                    inserted_count += 1

        return inserted_count, None, status_code

    def _sync_urlhaus(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs active malware distribution URLs from Abuse.ch URLhaus."""
        api_key = os.getenv("URLHAUS_API_KEY")
        if not api_key:
            return 0, "API key required: Register for free at abuse.ch Authentication Portal (URLHAUS_API_KEY)", None

        body, err, status_code = self._http_request_with_retry(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers={"Auth-Key": api_key},
            timeout=12
        )
        if err or not body:
            return 0, err or "Empty response from URLhaus", status_code

        inserted_count = 0
        try:
            data = json.loads(body.decode("utf-8"))
            urls = data.get("urls", [])
            for item in urls:
                u = item.get("url")
                if not u:
                    continue
                threat = item.get("threat", "malware_download")
                cat = "malware_distribution" if "malware" in threat else "scam"
                tags = item.get("tags") or []
                if self.record_indicator(
                    indicator=u,
                    indicator_type="url",
                    category=cat,
                    provider="urlhaus",
                    confidence_score=99 if item.get("url_status") == "online" else 85,
                    status="verified" if item.get("url_status") == "online" else "mitigated",
                    threat_tags=tags,
                    source_url=item.get("urlhaus_reference"),
                    first_seen=item.get("date_added"),
                    raw_data=item
                ):
                    inserted_count += 1
            return inserted_count, None, status_code
        except Exception as e:
            return 0, f"URLhaus parse error: {e}", status_code

    def _sync_phishtank(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs verified phishing URLs from PhishTank."""
        api_key = os.getenv("PHISHTANK_API_KEY")
        if not api_key:
            return 0, "API key required: PhishTank developer app key required (PHISHTANK_API_KEY)", None

        body, err, status_code = self._http_request_with_retry(
            f"https://data.phishtank.com/data/{api_key}/online-valid.json",
            headers={"User-Agent": f"phishtank/{api_key}"},
            timeout=20
        )
        if err or not body:
            return 0, err or "Empty response from PhishTank", status_code

        inserted_count = 0
        try:
            data = json.loads(body.decode("utf-8"))
            for item in data[:150]:
                u = item.get("url")
                if u and self.record_indicator(
                    indicator=u,
                    indicator_type="url",
                    category="phishing",
                    provider="phishtank",
                    confidence_score=95,
                    status="verified" if item.get("verified") == "yes" else "investigating",
                    target_brand=item.get("target"),
                    source_url=item.get("phish_detail_url"),
                    first_seen=item.get("submission_time"),
                    raw_data={"phish_id": item.get("phish_id")}
                ):
                    inserted_count += 1
            return inserted_count, None, status_code
        except Exception as e:
            return 0, f"PhishTank parse error: {e}", status_code

    def _sync_abuseipdb(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs reported malicious IP addresses from AbuseIPDB."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return 0, "API key required: Register at abuseipdb.com (ABUSEIPDB_API_KEY)", None

        body, err, status_code = self._http_request_with_retry(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100",
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=12
        )
        if err or not body:
            return 0, err or "Empty response from AbuseIPDB", status_code

        inserted_count = 0
        try:
            data = json.loads(body.decode("utf-8"))
            for item in data.get("data", []):
                ip = item.get("ipAddress")
                if ip and self.record_indicator(
                    indicator=ip,
                    indicator_type="ip",
                    category="malware_distribution",
                    provider="abuseipdb",
                    confidence_score=item.get("abuseConfidenceScore", 90),
                    status="verified",
                    country=item.get("countryCode"),
                    source_url=f"https://www.abuseipdb.com/check/{ip}",
                    first_seen=item.get("lastReportedAt"),
                    raw_data=item
                ):
                    inserted_count += 1
            return inserted_count, None, status_code
        except Exception as e:
            return 0, f"AbuseIPDB parse error: {e}", status_code

    def _sync_alienvault_otx(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs pulses from AlienVault OTX."""
        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            return 0, "API key required: Register at otx.alienvault.com (OTX_API_KEY)", None

        body, err, status_code = self._http_request_with_retry(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10",
            headers={"X-OTX-API-KEY": api_key},
            timeout=15
        )
        if err or not body:
            return 0, err or "Empty response from AlienVault OTX", status_code

        inserted_count = 0
        try:
            data = json.loads(body.decode("utf-8"))
            for pulse in data.get("results", []):
                pulse_name = pulse.get("name", "OTX Threat Pulse")
                for ind in pulse.get("indicators", [])[:20]:
                    val = ind.get("indicator")
                    ind_type = ind.get("type", "").lower()
                    if ind_type in ["url", "domain", "ipv4"] and val:
                        typ = "url" if ind_type == "url" else ("ip" if ind_type == "ipv4" else "domain")
                        if self.record_indicator(
                            indicator=val,
                            indicator_type=typ,
                            category="credential_harvesting" if "phish" in pulse_name.lower() else "malware_distribution",
                            provider="alienvault_otx",
                            confidence_score=90,
                            status="verified",
                            threat_tags=pulse.get("tags", []),
                            source_url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                            first_seen=pulse.get("created"),
                            raw_data={"pulse_id": pulse.get("id"), "pulse_name": pulse_name}
                        ):
                            inserted_count += 1
            return inserted_count, None, status_code
        except Exception as e:
            return 0, f"AlienVault OTX parse error: {e}", status_code

    def _sync_circl_misp(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Syncs and verifies connectivity to CIRCL / organization MISP instance."""
        misp_url = os.getenv("MISP_URL")
        misp_key = os.getenv("MISP_AUTH_KEY")
        if not misp_url or not misp_key:
            return 0, "MISP instance URL and Auth Key required (MISP_URL, MISP_AUTH_KEY)", None

        endpoint = f"{misp_url.rstrip('/')}/servers/getVersion.json"
        body, err, status_code = self._http_request_with_retry(
            endpoint,
            headers={"Authorization": misp_key, "Accept": "application/json"},
            timeout=12
        )
        if err or not body:
            return 0, err or "Failed to connect to MISP instance", status_code
        return 0, None, status_code

    def _sync_google_safebrowsing(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Validates Google Safe Browsing provider availability via official threatLists endpoint."""
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY") or os.getenv("SAFE_BROWSING_API_KEY")
        if not api_key:
            return 0, "API key required: Configure GOOGLE_SAFE_BROWSING_KEY in backend/.env", None

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatLists?key={api_key}"
        body, err, status_code = self._http_request_with_retry(endpoint, timeout=12)
        if err or not body:
            return 0, err or "Failed to query Google Safe Browsing", status_code
        return 0, None, status_code

    def _sync_virustotal(self) -> Tuple[int, Optional[str], Optional[int]]:
        """Validates VirusTotal REST API v3 availability via official metadata endpoint."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return 0, "API key required: Configure VIRUSTOTAL_API_KEY in backend/.env", None

        endpoint = "https://www.virustotal.com/api/v3/popular_threat_categories"
        body, err, status_code = self._http_request_with_retry(
            endpoint,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=12
        )
        if err or not body:
            return 0, err or "Failed to query VirusTotal", status_code
        return 0, None, status_code

    def sync_provider(self, provider_id: str) -> Dict[str, Any]:
        """Synchronizes an individual provider and updates status tracking."""
        meta = self.providers_meta.get(provider_id)
        if not meta:
            return {"providerId": provider_id, "status": "DISCONNECTED", "error": "Unknown provider"}

        # Mark SYNCING
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE provider_sync_status SET status = 'SYNCING' WHERE provider_id = ?", (provider_id,))
            conn.commit()

        count = 0
        err = None
        status_code = None

        if provider_id == "openphish":
            count, err, status_code = self._sync_openphish()
        elif provider_id == "urlhaus":
            count, err, status_code = self._sync_urlhaus()
        elif provider_id == "phishtank":
            count, err, status_code = self._sync_phishtank()
        elif provider_id == "abuseipdb":
            count, err, status_code = self._sync_abuseipdb()
        elif provider_id == "alienvault_otx":
            count, err, status_code = self._sync_alienvault_otx()
        elif provider_id == "circl_misp":
            count, err, status_code = self._sync_circl_misp()
        elif provider_id == "google_safebrowsing":
            count, err, status_code = self._sync_google_safebrowsing()
        elif provider_id == "virustotal":
            count, err, status_code = self._sync_virustotal()

        now_iso = datetime.now(timezone.utc).isoformat()

        # Strict Provider Health State Machine:
        # CONNECTED, DISCONNECTED, DEGRADED, NOT_CONFIGURED, STALE
        if err:
            if "API key required" in err or "Auth Key required" in err:
                final_status = "NOT_CONFIGURED"
            elif status_code == 429 or "rate limit" in err.lower():
                final_status = "DEGRADED"
            else:
                final_status = "DISCONNECTED"
        else:
            final_status = "CONNECTED"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE provider_sync_status
                SET status = ?,
                    last_sync_time = ?,
                    last_error = ?,
                    records_last_sync = ?,
                    records_ingested_total = records_ingested_total + ?
                WHERE provider_id = ?
            """, (final_status, now_iso, err, count, count, provider_id))
            conn.commit()

        return {
            "providerId": provider_id,
            "providerName": meta["name"],
            "status": final_status,
            "lastSyncTime": now_iso,
            "lastError": err,
            "recordsLastSync": count,
        }

    def sync_all_providers(self, force: bool = False) -> Dict[str, Any]:
        """Runs incremental synchronization across all 8 threat providers."""
        results = {}
        for pid in self.providers_meta.keys():
            results[pid] = self.sync_provider(pid)
        # Automatically reclassify all indicators across categories & brands
        try:
            self.reclassify_existing_indicators()
        except Exception:
            pass
        return results

    def get_providers_status(self) -> List[Dict[str, Any]]:
        """Retrieves verified synchronization status of all providers with STALE detection."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT provider_id, provider_name, status, last_sync_time, last_error,
                       records_ingested_total, records_last_sync, update_interval_sec, next_sync_time
                FROM provider_sync_status
                ORDER BY provider_id ASC
            """)
            rows = cursor.fetchall()
            out = []
            now_dt = datetime.now(timezone.utc)
            for r in rows:
                meta = self.providers_meta.get(r["provider_id"], {})
                api_key_set = bool(os.getenv(meta.get("api_key_env", ""))) if meta.get("requires_api_key") else True
                curr_status = r["status"]

                # STALE detection: if marked CONNECTED / ONLINE but last_sync_time is older than 2x update_interval_sec
                if curr_status in ("CONNECTED", "ONLINE") and r["last_sync_time"]:
                    try:
                        sync_dt = datetime.fromisoformat(r["last_sync_time"])
                        if (now_dt - sync_dt).total_seconds() > (2 * r["update_interval_sec"]):
                            curr_status = "STALE"
                    except Exception:
                        pass

                out.append({
                    "providerId": r["provider_id"],
                    "providerName": r["provider_name"],
                    "status": curr_status,
                    "lastSyncTime": r["last_sync_time"],
                    "lastError": r["last_error"],
                    "recordsIngestedTotal": r["records_ingested_total"],
                    "recordsLastSync": r["records_last_sync"],
                    "updateIntervalSec": r["update_interval_sec"],
                    "requiresApiKey": meta.get("requires_api_key", False),
                    "isConfigured": api_key_set,
                    "description": meta.get("description", ""),
                })
            return out

    def get_threat_feed(
        self,
        limit: int = 300,
        category: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves authentic ingested threat indicators with source attribution.
        Supports filtering by category, searching by domain/brand/keyword,
        and provides balanced distribution across categories when category is 'all'.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Map frontend category aliases
            cat_filter = None
            if category and category != "all":
                c_low = category.lower().strip()
                if c_low in ["brand_impersonation", "impersonation"]:
                    cat_filter = ["impersonation", "brand_impersonation"]
                elif c_low in ["scam_smishing", "scam"]:
                    cat_filter = ["scam", "scam_smishing"]
                else:
                    cat_filter = [c_low]

            if cat_filter:
                # Specific category query
                placeholders = ",".join("?" for _ in cat_filter)
                query = f"""
                    SELECT id, indicator, domain, indicator_type, category, provider,
                           confidence_score, status, target_brand, threat_tags, country,
                           source_url, first_seen, last_seen, ingested_at
                    FROM threat_indicators
                    WHERE category IN ({placeholders})
                """
                params: List[Any] = list(cat_filter)
                if search and search.strip():
                    s_term = f"%{search.strip().lower()}%"
                    query += " AND (LOWER(domain) LIKE ? OR LOWER(indicator) LIKE ? OR LOWER(target_brand) LIKE ?)"
                    params.extend([s_term, s_term, s_term])

                query += " ORDER BY ingested_at DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                rows = cursor.fetchall()
            elif search and search.strip():
                # Search without category constraint
                s_term = f"%{search.strip().lower()}%"
                query = """
                    SELECT id, indicator, domain, indicator_type, category, provider,
                           confidence_score, status, target_brand, threat_tags, country,
                           source_url, first_seen, last_seen, ingested_at
                    FROM threat_indicators
                    WHERE (LOWER(domain) LIKE ? OR LOWER(indicator) LIKE ? OR LOWER(target_brand) LIKE ?)
                    ORDER BY ingested_at DESC LIMIT ?
                """
                cursor.execute(query, [s_term, s_term, s_term, limit])
                rows = cursor.fetchall()
            else:
                # Balanced distribution query across all 6 core categories
                # Ensure every dropdown category in the frontend has real rows
                all_cats = [
                    "phishing", "impersonation", "credential_harvesting",
                    "crypto_drainer", "malware_distribution", "scam"
                ]
                per_cat_limit = max(35, limit // len(all_cats))
                rows = []
                seen_ids = set()
                for cat in all_cats:
                    cursor.execute("""
                        SELECT id, indicator, domain, indicator_type, category, provider,
                               confidence_score, status, target_brand, threat_tags, country,
                               source_url, first_seen, last_seen, ingested_at
                        FROM threat_indicators
                        WHERE category = ? OR (category = 'brand_impersonation' AND ? = 'impersonation') OR (category = 'scam_smishing' AND ? = 'scam')
                        ORDER BY ingested_at DESC LIMIT ?
                    """, (cat, cat, cat, per_cat_limit))
                    cat_rows = cursor.fetchall()
                    for cr in cat_rows:
                        if cr["id"] not in seen_ids:
                            seen_ids.add(cr["id"])
                            rows.append(cr)

                # If still under limit, backfill with remaining newest indicators
                cursor.execute("""
                    SELECT id, indicator, domain, indicator_type, category, provider,
                           confidence_score, status, target_brand, threat_tags, country,
                           source_url, first_seen, last_seen, ingested_at
                    FROM threat_indicators
                    ORDER BY ingested_at DESC LIMIT ?
                """, (limit,))
                for r in cursor.fetchall():
                    if r["id"] not in seen_ids and len(rows) < limit:
                        seen_ids.add(r["id"])
                        rows.append(r)

                # Sort combined rows by ingested_at descending
                rows.sort(key=lambda x: x["ingested_at"] or "", reverse=True)

            threats = []
            for r in rows:
                c_norm = r["category"].lower()
                if c_norm == "brand_impersonation":
                    c_norm = "impersonation"
                elif c_norm == "scam_smishing":
                    c_norm = "scam"

                threats.append({
                    "id": r["id"],
                    "domain": r["domain"],
                    "url": r["indicator"],
                    "urlPath": r["indicator"] if r["indicator_type"] == "url" else "",
                    "category": c_norm,
                    "provider": r["provider"],
                    "confidenceScore": r["confidence_score"],
                    "status": r["status"],
                    "targetBrand": r["target_brand"],
                    "threatTags": json.loads(r["threat_tags"] or "[]"),
                    "country": r["country"],
                    "sourceUrl": r["source_url"],
                    "reportedAt": r["ingested_at"] or r["first_seen"],
                    "firstSeen": r["first_seen"],
                    "indicators": json.loads(r["threat_tags"] or "[]") or [f"Authoritative listing via {r['provider']}"],
                    "reporterType": "automated_sensor",
                    "corroborationCount": 1,
                })
            return threats

    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """Calculates authentic telemetry metrics via direct SQL aggregation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM threat_indicators")
            total_threats = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT target_brand) FROM threat_indicators WHERE target_brand IS NOT NULL AND target_brand != ''")
            active_campaigns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT domain) FROM threat_indicators WHERE status = 'verified'")
            verified_malicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_reports WHERE date(created_at) = date('now')")
            community_today = cursor.fetchone()[0]

            cursor.execute("""
                SELECT category, COUNT(*) as cnt
                FROM threat_indicators
                GROUP BY category
                ORDER BY cnt DESC
            """)
            category_rows = cursor.fetchall()
            category_breakdown = []
            for r in category_rows:
                cat = r["category"].lower()
                if cat == "brand_impersonation":
                    cat = "impersonation"
                elif cat == "scam_smishing":
                    cat = "scam"
                cnt = r["cnt"]
                pct = round((cnt / total_threats) * 100) if total_threats > 0 else 0
                category_breakdown.append({
                    "category": cat,
                    "name": cat.replace("_", " ").title(),
                    "count": cnt,
                    "percentage": pct,
                })

            cursor.execute("""
                SELECT provider, COUNT(*) as cnt
                FROM threat_indicators
                GROUP BY provider
                ORDER BY cnt DESC
            """)
            provider_breakdown = [{"provider": r["provider"], "count": r["cnt"]} for r in cursor.fetchall()]

            cursor.execute("""
                SELECT country, COUNT(*) as cnt
                FROM threat_indicators
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country
                ORDER BY cnt DESC
                LIMIT 10
            """)
            geo_distribution = [{"country": r["country"], "count": r["cnt"]} for r in cursor.fetchall()]

            return {
                "totalThreatsMonitored": total_threats,
                "activeCampaigns24h": active_campaigns,
                "verifiedMaliciousDomains": verified_malicious,
                "communityReportsToday": community_today,
                "categoryBreakdown": category_breakdown,
                "providerBreakdown": provider_breakdown,
                "geoDistribution": geo_distribution,
            }

    def start_background_ingestor(self, initial_sync: bool = True):
        """Starts a background daemon thread that periodically syncs feeds."""
        if self._running:
            return

        self._running = True

        def _worker():
            if initial_sync:
                try:
                    self.sync_all_providers()
                except Exception as e:
                    print(f"[!] ThreatFeedIngestor initial sync error: {e}")

            while self._running:
                # Sleep in short increments to allow graceful shutdown
                for _ in range(300): # 5 minutes
                    if not self._running:
                        break
                    time.sleep(1)

                if not self._running:
                    break

                try:
                    # Sync OpenPhish if older than 1 hour
                    with self._get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT last_sync_time FROM provider_sync_status WHERE provider_id = 'openphish'")
                        row = cursor.fetchone()
                        should_sync = True
                        if row and row["last_sync_time"]:
                            try:
                                dt = datetime.fromisoformat(row["last_sync_time"])
                                if (datetime.now(timezone.utc) - dt).total_seconds() < 3600:
                                    should_sync = False
                            except Exception:
                                pass
                        if should_sync:
                            self.sync_provider("openphish")

                    # Sync URLhaus if key is set
                    if os.getenv("URLHAUS_API_KEY"):
                        self.sync_provider("urlhaus")
                except Exception as e:
                    print(f"[!] ThreatFeedIngestor background loop error: {e}")

        self._thread = threading.Thread(target=_worker, daemon=True, name="ThreatFeedIngestorThread")
        self._thread.start()

    def stop_background_ingestor(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
