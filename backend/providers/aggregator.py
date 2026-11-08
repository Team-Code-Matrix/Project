"""
TrustShield Threat Intelligence Aggregator
Executes all configured threat intelligence and domain analysis providers concurrently.
Aggregates genuine provider telemetry without fabrication.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
from providers.rdap_provider import RdapProvider
from providers.crtsh_provider import CrtShProvider
from providers.urlhaus_provider import URLhausProvider
from providers.phishtank_provider import PhishTankProvider
from providers.openphish_provider import OpenPhishProvider
from providers.google_safebrowsing import GoogleSafeBrowsingProvider
from providers.virustotal import VirusTotalProvider

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.providers = [
            RdapProvider(),
            CrtShProvider(),
            URLhausProvider(),
            PhishTankProvider(),
            OpenPhishProvider(),
            GoogleSafeBrowsingProvider(),
            VirusTotalProvider(),
        ]

    def audit_target(self, target_url: str, hostname: str, timeout: float = 6.0) -> Dict[str, Any]:
        """
        Queries all threat intelligence providers in parallel with timeout enforcement.
        Returns aggregated results dictionary.
        """
        results: Dict[str, Any] = {}
        malicious_hits: List[Dict[str, Any]] = []
        configured_count = 0
        active_queries_count = 0

        with ThreadPoolExecutor(max_workers=len(self.providers)) as executor:
            future_to_provider = {
                executor.submit(p.query, target_url, hostname): p
                for p in self.providers
            }

            for future in as_completed(future_to_provider, timeout=timeout):
                p = future_to_provider[future]
                try:
                    res = future.result()
                    results[p.provider_id] = res
                    if p.is_configured:
                        configured_count += 1
                    active_queries_count += 1

                    if res.get("isMalicious"):
                        malicious_hits.append(res)
                except Exception as exc:
                    results[p.provider_id] = p.build_result("ERROR", error=str(exc))

        # Fill any missing providers that timed out
        for p in self.providers:
            if p.provider_id not in results:
                results[p.provider_id] = p.build_result("UNAVAILABLE", error="Provider query timed out")

        is_any_malicious = len(malicious_hits) > 0
        highest_confidence = max([h.get("confidence", 0) for h in malicious_hits], default=0)

        return {
            "isMalicious": is_any_malicious,
            "maliciousHitCount": len(malicious_hits),
            "maliciousHits": malicious_hits,
            "highestConfidence": highest_confidence,
            "providers": results,
            "rdap": results.get("rdap", {}).get("details", {}),
            "crtsh": results.get("crtsh", {}).get("details", {}),
            "totalProvidersQueried": len(self.providers),
            "configuredProvidersCount": configured_count,
        }

