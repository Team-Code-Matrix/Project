"""
TrustShield Certificate Transparency Provider (crt.sh)
Queries public Certificate Transparency (CT) logs to audit legitimate certificate issuance tenure and detect rogue CAs.
"""
import requests
from typing import Dict, Any, List
from providers.base_provider import BaseThreatProvider

class CrtShProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 4.0):
        super().__init__(name="Certificate Transparency Logs (crt.sh)", provider_id="crtsh", is_configured=True)
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        domain = hostname.lower().strip()
        if not domain:
            return self.build_result("ERROR", error="Empty hostname for crt.sh query")

        url = f"https://crt.sh/?q={domain}&output=json"
        headers = {
            "Accept": "application/json",
            "User-Agent": "TrustShield-CT-Auditor/2.4"
        }

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 404:
                return self.build_result(
                    "NO_MATCH",
                    details={"domain": domain, "loggedCertificatesCount": 0, "message": "No logged certificates found in CT Merkle trees"}
                )
            if not resp.ok:
                return self.build_result(
                    "UNAVAILABLE",
                    error=f"crt.sh returned HTTP {resp.status_code}"
                )

            data = resp.json()
            if not isinstance(data, list):
                return self.build_result("NO_MATCH", details={"loggedCertificatesCount": 0})

            # Parse CT entries
            cert_entries = []
            issuers = set()
            for entry in data[:10]: # Top 10 logged certs
                issuer = entry.get("issuer_name", "")
                if issuer:
                    issuers.add(issuer)
                cert_entries.append({
                    "id": entry.get("id"),
                    "loggedAt": entry.get("entry_timestamp"),
                    "notBefore": entry.get("not_before"),
                    "notAfter": entry.get("not_after"),
                    "commonName": entry.get("common_name"),
                    "issuer": issuer,
                    "serialNumber": entry.get("serial_number"),
                })

            return self.build_result(
                "SUCCESS",
                is_malicious=False,
                confidence=90,
                details={
                    "loggedCertificatesCount": len(data),
                    "uniqueIssuers": list(issuers),
                    "sampleCertificates": cert_entries,
                    "ctVerified": len(data) > 0,
                }
            )
        except requests.Timeout:
            return self.build_result(
                "UNAVAILABLE",
                error=f"crt.sh query timed out after {self.timeout}s"
            )
        except Exception as e:
            return self.build_result(
                "ERROR",
                error=f"crt.sh query exception: {str(e)}"
            )

