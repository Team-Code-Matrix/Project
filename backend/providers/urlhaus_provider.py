"""
TrustShield Abuse.ch URLhaus Provider
Queries official URLhaus database for active malware payloads, botnet C2s, and malicious URL listings.
"""
import os
import requests
from typing import Dict, Any
from providers.base_provider import BaseThreatProvider
try:
    from infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform
except ImportError:
    from backend.infrastructure_allowlist import is_verified_infrastructure, is_shared_hosting_platform

class URLhausProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 3.5):
        api_key = os.getenv("URLHAUS_API_KEY", "").strip()
        super().__init__(name="Abuse.ch URLhaus", provider_id="urlhaus", is_configured=True)
        self.api_key = api_key
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        try:
            from infrastructure_allowlist import (
                is_verified_infrastructure,
                is_hard_bypass_target,
                is_shared_hosting_platform,
            )
        except ImportError:
            try:
                from backend.infrastructure_allowlist import (
                    is_verified_infrastructure,
                    is_hard_bypass_target,
                    is_shared_hosting_platform,
                )
            except ImportError:
                def is_verified_infrastructure(h): return False
                def is_hard_bypass_target(h): return False
                def is_shared_hosting_platform(h): return False

        if is_hard_bypass_target(hostname):
            clean_low = target_url.lower()
            if not any(clean_low.endswith(ext) for ext in [".exe", ".sh", ".elf", ".bin", ".vbs", ".bat", ".ps1", ".apk", ".dll"]):
                return self.build_result(
                    "NO_MATCH",
                    is_malicious=False,
                    confidence=98,
                    details={"message": "Target is verified official infrastructure; bypassed URLhaus host query"}
                )

        api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {
            "User-Agent": "TrustShield-Intelligence-Gateway/2.4",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            # Query by full URL first
            resp = requests.post(api_endpoint, data={"url": target_url}, headers=headers, timeout=self.timeout)
            if resp.ok:
                data = resp.json()
                q_status = data.get("query_status", "")
                if q_status == "ok":
                    # Confirmed active malware/phishing URL in URLhaus
                    threat = data.get("threat", "malware")
                    url_status = data.get("url_status", "active")
                    tags = data.get("tags") or []
                    return self.build_result(
                        "MALICIOUS",
                        is_malicious=True,
                        threat_type=threat,
                        confidence=98,
                        details={
                            "urlhausId": data.get("id"),
                            "urlStatus": url_status,
                            "threat": threat,
                            "tags": tags,
                            "dateAdded": data.get("date_added"),
                            "reporter": data.get("reporter"),
                            "payloads": data.get("payloads", []),
                        }
                    )
                elif q_status == "no_results":
                    # For verified infrastructure or shared hosts (e.g. github.com, google.com), NEVER query by apex domain
                    if is_shared_hosting_platform(hostname) or is_verified_infrastructure(hostname):
                        return self.build_result(
                            "NO_MATCH",
                            is_malicious=False,
                            confidence=95,
                            details={"message": "Target URL is not listed in URLhaus; host is verified shared infrastructure"}
                        )

                    # Host query fallback to check if domain is a dedicated malware dropper host
                    host_resp = requests.post(
                        "https://urlhaus-api.abuse.ch/v1/host/",
                        data={"host": hostname},
                        headers=headers,
                        timeout=self.timeout
                    )
                    if host_resp.ok:
                        h_data = host_resp.json()
                        if h_data.get("query_status") == "ok":
                            return self.build_result(
                                "MALICIOUS",
                                is_malicious=True,
                                threat_type="malware_host",
                                confidence=95,
                                details={
                                    "urlCount": h_data.get("url_count", 0),
                                    "firstSeen": h_data.get("firstseen"),
                                    "threat": "Known malware distribution host",
                                }
                            )
                    return self.build_result(
                        "NO_MATCH",
                        is_malicious=False,
                        confidence=90,
                        details={"message": "Target URL and host not listed in Abuse.ch URLhaus threat database"}
                    )
                else:
                    return self.build_result("NO_MATCH", details={"queryStatus": q_status})

            if resp.status_code == 429:
                return self.build_result("RATE_LIMITED", error="URLhaus API rate limit exceeded")

            return self.build_result("UNAVAILABLE", error=f"URLhaus returned HTTP {resp.status_code}")

        except requests.Timeout:
            return self.build_result("UNAVAILABLE", error=f"URLhaus request timed out after {self.timeout}s")
        except Exception as e:
            return self.build_result("ERROR", error=f"URLhaus query error: {str(e)}")

