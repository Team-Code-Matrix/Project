"""
TrustShield OpenPhish Autonomous Feed Provider
Audits target URLs against OpenPhish real-time phishing feed telemetry.
"""
import os
import time
import requests
import urllib.parse
from typing import Dict, Any, Set
from providers.base_provider import BaseThreatProvider
try:
    from infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform
except ImportError:
    from backend.infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform

_FEED_CACHE: Set[str] = set()
_LAST_FEED_FETCH = 0.0
_FEED_LOCK = False

class OpenPhishProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 3.5):
        api_key = os.getenv("OPENPHISH_API_KEY", "").strip()
        super().__init__(name="OpenPhish Global Feed", provider_id="openphish", is_configured=True)
        self.api_key = api_key
        self.timeout = timeout

    def _refresh_community_feed_if_needed(self):
        global _FEED_CACHE, _LAST_FEED_FETCH, _FEED_LOCK
        now = time.time()
        # Refresh feed at most once every 30 minutes
        if now - _LAST_FEED_FETCH < 1800 and _FEED_CACHE:
            return

        feed_url = "https://openphish.com/feed.txt"
        try:
            resp = requests.get(
                feed_url,
                headers={"User-Agent": "TrustShield-Feed-Ingester/2.4"},
                timeout=self.timeout
            )
            if resp.ok and resp.text:
                lines = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
                _FEED_CACHE = set(lines)
                _LAST_FEED_FETCH = now
        except Exception:
            pass

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        # If premium API key configured, use premium endpoint
        if self.api_key:
            # Query premium REST endpoint
            try:
                resp = requests.post(
                    "https://api.openphish.com/v1/url",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"url": target_url},
                    timeout=self.timeout
                )
                if resp.ok:
                    data = resp.json()
                    if data.get("phishing"):
                        return self.build_result(
                            "MALICIOUS",
                            is_malicious=True,
                            threat_type="phishing",
                            confidence=99,
                            details=data
                        )
                    return self.build_result("NO_MATCH", is_malicious=False, confidence=90)
                elif resp.status_code == 429:
                    return self.build_result("RATE_LIMITED", error="OpenPhish rate limit reached")
            except Exception as e:
                return self.build_result("ERROR", error=f"OpenPhish API error: {e}")

        # Community Feed Mode
        try:
            self._refresh_community_feed_if_needed()
            norm_target = target_url.strip().lower()
            norm_no_slash = norm_target.rstrip("/")

            is_match = (norm_target in _FEED_CACHE) or (norm_no_slash in _FEED_CACHE)
            # Only perform apex host-level check for dedicated unverified hosts; NEVER for shared/verified infrastructure
            if not is_match and not is_shared_hosting_platform(hostname) and not is_verified_infrastructure(hostname):
                h_lower = hostname.lower()
                for feed_entry in _FEED_CACHE:
                    try:
                        p_entry = urllib.parse.urlparse(feed_entry)
                        if p_entry.netloc.lower() == h_lower:
                            is_match = True
                            break
                    except Exception:
                        pass

            if is_match:
                return self.build_result(
                    "MALICIOUS",
                    is_malicious=True,
                    threat_type="phishing",
                    confidence=95,
                    details={"feed": "OpenPhish Community Telemetry Feed", "matched": target_url}
                )

            return self.build_result(
                "NO_MATCH",
                is_malicious=False,
                confidence=85,
                details={"feedEntriesCached": len(_FEED_CACHE), "message": "Target not present in active OpenPhish feed"}
            )
        except Exception as e:
            return self.build_result("ERROR", error=f"OpenPhish check error: {str(e)}")

