"""
TrustShield RDAP / WHOIS Provider (RFC 7482)
Queries authoritative ICANN RDAP endpoints for genuine domain registration, registrar, creation/expiration dates, and tenure.
Never invents domain age when RDAP is unavailable.
"""
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from providers.base_provider import BaseThreatProvider

class RdapProvider(BaseThreatProvider):
    def __init__(self, timeout: float = 4.0):
        super().__init__(name="Authoritative RDAP Registry", provider_id="rdap", is_configured=True)
        self.timeout = timeout

    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        # Extract root domain or registered domain from hostname
        domain = hostname.lower().strip()
        if not domain or domain.startswith("xn--") and "." not in domain:
            return self.build_result("ERROR", error="Invalid hostname for RDAP query")

        # Strip www. prefix for root domain lookup
        lookup_domain = domain[4:] if domain.startswith("www.") else domain
        # If subdomain exists, attempt root domain extraction
        parts = lookup_domain.split(".")
        if len(parts) > 2:
            # Common 2-level TLDs (co.uk, com.au, etc.)
            two_level_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "net.in", "co.nz", "co.jp"}
            if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_level_tlds:
                lookup_domain = ".".join(parts[-3:])
            else:
                lookup_domain = ".".join(parts[-2:])

        rdap_url = f"https://rdap.org/domain/{lookup_domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "TrustShield-Security-Auditor/2.4 (RDAP Client)"
        }

        try:
            resp = requests.get(rdap_url, headers=headers, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 404:
                return self.build_result(
                    "NO_MATCH",
                    details={"domain": lookup_domain, "message": "Domain registration not found in authoritative RDAP registry (NXDOMAIN/Unregistered)"}
                )
            if resp.status_code == 429:
                return self.build_result(
                    "RATE_LIMITED",
                    error="RDAP registry rate limit reached. Query throttled by authoritative registry."
                )
            if not resp.ok:
                return self.build_result(
                    "UNAVAILABLE",
                    error=f"RDAP registry returned HTTP {resp.status_code}"
                )

            data = resp.json()

            # Parse Events (registration, expiration, last change)
            events = data.get("events", [])
            created_date = None
            expiration_date = None
            updated_date = None

            for ev in events:
                action = ev.get("eventAction", "").lower()
                date_str = ev.get("eventDate", "")
                if action in ("registration", "created"):
                    created_date = date_str
                elif action in ("expiration", "expiry"):
                    expiration_date = date_str
                elif action in ("last changed", "last update", "updated"):
                    updated_date = date_str

            # Parse Registrar
            registrar_name = None
            entities = data.get("entities", [])
            for ent in entities:
                roles = [r.lower() for r in ent.get("roles", [])]
                if "registrar" in roles or "sponsoring registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and item and item[0] == "fn":
                                registrar_name = item[3]
                                break
                    if not registrar_name:
                        registrar_name = ent.get("handle")

            # Parse Nameservers
            nameservers = []
            for ns in data.get("nameservers", []):
                ns_name = ns.get("ldhName")
                if ns_name:
                    nameservers.append(ns_name.lower())

            # Parse Domain Status
            status_list = data.get("status", [])

            # Compute Genuine Domain Age
            domain_age_days = None
            is_newly_registered = False
            if created_date:
                try:
                    # Clean ISO format
                    clean_dt = created_date.replace("Z", "+00:00")
                    c_dt = datetime.fromisoformat(clean_dt)
                    now_dt = datetime.now(timezone.utc)
                    domain_age_days = max(0, (now_dt - c_dt).days)
                    is_newly_registered = domain_age_days < 30
                except Exception:
                    pass

            return self.build_result(
                "SUCCESS",
                is_malicious=False,
                confidence=95,
                details={
                    "domain": lookup_domain,
                    "registrar": registrar_name or "ICANN Accredited Registrar",
                    "createdDate": created_date,
                    "expirationDate": expiration_date,
                    "updatedDate": updated_date,
                    "domainAgeDays": domain_age_days,
                    "isNewlyRegistered": is_newly_registered,
                    "nameservers": nameservers,
                    "status": status_list,
                }
            )
        except requests.Timeout:
            return self.build_result(
                "UNAVAILABLE",
                error=f"RDAP query timed out after {self.timeout}s"
            )
        except Exception as e:
            return self.build_result(
                "ERROR",
                error=f"RDAP query error: {str(e)}"
            )

