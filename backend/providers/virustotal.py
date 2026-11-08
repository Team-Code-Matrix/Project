"""
TrustShield VirusTotal Provider (v3 REST API)
Queries VirusTotal federated multi-antivirus scanning engines (70+ security vendors).
If VIRUSTOTAL_API_KEY is omitted, cleanly reports UNCONFIGURED status.
"""
import os
import base64
import requests
from typing import Dict, Any
from providers.base_provider import BaseThreatProvider

class VirusTotalProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 4.0):
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        is_configured = bool(api_key)
        super().__init__(name="VirusTotal Multi-Engine", provider_id="virustotal", is_configured=is_configured)
        self.api_key = api_key
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_result(
                "UNCONFIGURED",
                error="VirusTotal API key not configured (set VIRUSTOTAL_API_KEY in .env)"
            )

        # In VirusTotal v3 API, URL identifier is SHA256 or base64 without padding
        url_id = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "TrustShield-VT-Auditor/2.4"
        }

        try:
            resp = requests.get(endpoint, headers=headers, timeout=self.timeout)
            if resp.status_code == 404:
                return self.build_result(
                    "NO_MATCH",
                    is_malicious=False,
                    confidence=80,
                    details={"message": "Target URL has not been analyzed or indexed in VirusTotal"}
                )
            if resp.status_code == 401 or resp.status_code == 403:
                return self.build_result(
                    "ERROR",
                    error="VirusTotal API authentication rejected (check VIRUSTOTAL_API_KEY)"
                )
            if resp.status_code == 429:
                return self.build_result(
                    "RATE_LIMITED",
                    error="VirusTotal daily or per-minute API quota exceeded"
                )
            if not resp.ok:
                return self.build_result(
                    "UNAVAILABLE",
                    error=f"VirusTotal returned HTTP {resp.status_code}"
                )

            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count = stats.get("harmless", 0)
            undetected_count = stats.get("undetected", 0)
            total_engines = sum(stats.values()) or 70

            reputation = attributes.get("reputation", 0)
            categories = attributes.get("categories", {})

            if malicious_count >= 2:
                return self.build_result(
                    "MALICIOUS",
                    is_malicious=True,
                    threat_type="multi_engine_malicious",
                    confidence=min(99, 70 + (malicious_count * 3)),
                    details={
                        "maliciousEnginesCount": malicious_count,
                        "suspiciousEnginesCount": suspicious_count,
                        "totalEnginesCount": total_engines,
                        "reputation": reputation,
                        "categories": categories,
                        "stats": stats,
                    }
                )
            elif malicious_count == 1 or suspicious_count >= 2:
                return self.build_result(
                    "MALICIOUS" if malicious_count == 1 else "NO_MATCH",
                    is_malicious=(malicious_count == 1),
                    threat_type="suspicious_telemetry",
                    confidence=60,
                    details={
                        "maliciousEnginesCount": malicious_count,
                        "suspiciousEnginesCount": suspicious_count,
                        "totalEnginesCount": total_engines,
                        "stats": stats,
                    }
                )
            else:
                return self.build_result(
                    "NO_MATCH",
                    is_malicious=False,
                    confidence=95,
                    details={
                        "maliciousEnginesCount": 0,
                        "harmlessEnginesCount": harmless_count,
                        "totalEnginesCount": total_engines,
                        "stats": stats,
                    }
                )

        except requests.Timeout:
            return self.build_result("UNAVAILABLE", error=f"VirusTotal query timed out after {self.timeout}s")
        except Exception as e:
            return self.build_result("ERROR", error=f"VirusTotal query error: {str(e)}")

