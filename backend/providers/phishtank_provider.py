"""
TrustShield PhishTank Threat Provider
Queries PhishTank verified phishing database to identify confirmed phishing websites.
"""
import os
import requests
from typing import Dict, Any
from providers.base_provider import BaseThreatProvider

class PhishTankProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 3.5):
        api_key = os.getenv("PHISHTANK_API_KEY", "").strip()
        super().__init__(name="PhishTank Community Feed", provider_id="phishtank", is_configured=True)
        self.api_key = api_key
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        api_endpoint = "https://checkurl.phishtank.com/checkurl/"
        data = {
            "url": target_url,
            "format": "json",
        }
        if self.api_key:
            data["app_key"] = self.api_key

        headers = {
            "User-Agent": "phishtank/trustshield-scanner-2.4"
        }

        try:
            resp = requests.post(api_endpoint, data=data, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return self.build_result("RATE_LIMITED", error="PhishTank API rate limit exceeded")
            if not resp.ok:
                return self.build_result("UNAVAILABLE", error=f"PhishTank returned HTTP {resp.status_code}")

            res_json = resp.json()
            results = res_json.get("results", {})
            in_database = results.get("in_database", False)
            valid = results.get("valid", False)
            verified = results.get("verified", False)

            if in_database and valid and verified:
                return self.build_result(
                    "MALICIOUS",
                    is_malicious=True,
                    threat_type="phishing",
                    confidence=99,
                    details={
                        "phishId": results.get("phish_id"),
                        "phishDetailUrl": results.get("phish_detail_page"),
                        "verifiedAt": results.get("verified_at"),
                        "target": results.get("target"),
                    }
                )
            elif in_database and not verified:
                return self.build_result(
                    "MALICIOUS",
                    is_malicious=True,
                    threat_type="unverified_phishing",
                    confidence=70,
                    details={
                        "phishId": results.get("phish_id"),
                        "message": "Listed in PhishTank submission queue; verification pending",
                    }
                )
            else:
                return self.build_result(
                    "NO_MATCH",
                    is_malicious=False,
                    confidence=85,
                    details={"message": "Target URL is not listed in PhishTank verified phishing database"}
                )

        except requests.Timeout:
            return self.build_result("UNAVAILABLE", error=f"PhishTank request timed out after {self.timeout}s")
        except Exception as e:
            return self.build_result("ERROR", error=f"PhishTank query error: {str(e)}")

