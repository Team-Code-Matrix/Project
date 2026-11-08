"""
TrustShield Google Safe Browsing Provider (v4 Lookup API)
Queries Google Safe Browsing threat database for confirmed phishing, malware, and social engineering listings.
If GOOGLE_SAFE_BROWSING_API_KEY is omitted, cleanly reports UNCONFIGURED status.
"""
import os
import requests
from typing import Dict, Any
from providers.base_provider import BaseThreatProvider

class GoogleSafeBrowsingProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 3.5):
        api_key = (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("SAFE_BROWSING_API_KEY") or "").strip()
        is_configured = bool(api_key)
        super().__init__(name="Google Safe Browsing", provider_id="google_safe_browsing", is_configured=is_configured)
        self.api_key = api_key
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_result(
                "UNCONFIGURED",
                error="Google Safe Browsing API key not configured (set GOOGLE_SAFE_BROWSING_API_KEY in .env)"
            )

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "trustshield-engine",
                "clientVersion": "2.4.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}]
            }
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout)
            if resp.status_code == 400 or resp.status_code == 403:
                return self.build_result(
                    "ERROR",
                    error=f"Google Safe Browsing authentication failed: HTTP {resp.status_code} (verify API key)"
                )
            if resp.status_code == 429:
                return self.build_result(
                    "RATE_LIMITED",
                    error="Google Safe Browsing quota exceeded / rate limited"
                )
            if not resp.ok:
                return self.build_result(
                    "UNAVAILABLE",
                    error=f"Google Safe Browsing returned HTTP {resp.status_code}"
                )

            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                first_match = matches[0]
                threat_type = first_match.get("threatType", "SOCIAL_ENGINEERING")
                platform = first_match.get("platformType", "ANY_PLATFORM")
                return self.build_result(
                    "MALICIOUS",
                    is_malicious=True,
                    threat_type=threat_type.lower(),
                    confidence=99,
                    details={
                        "threatType": threat_type,
                        "platformType": platform,
                        "cacheDuration": first_match.get("cacheDuration"),
                    }
                )

            return self.build_result(
                "NO_MATCH",
                is_malicious=False,
                confidence=95,
                details={"message": "No active threat match in Google Safe Browsing index"}
            )

        except requests.Timeout:
            return self.build_result("UNAVAILABLE", error=f"Google Safe Browsing query timed out after {self.timeout}s")
        except Exception as e:
            return self.build_result("ERROR", error=f"Google Safe Browsing query error: {str(e)}")

