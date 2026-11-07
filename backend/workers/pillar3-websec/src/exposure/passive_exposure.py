"""
Passive Exposure & Outdated Component Matcher
Inspects server banners, identifies exposed administrative/git endpoints,
and matches versions against known CVE advisories.
"""
from typing import Dict, Any, List

KNOWN_VULNERABLE_BANNERS = {
    "apache/2.4.49": {
        "cveId": "CVE-2021-41773",
        "severity": "CRITICAL",
        "summary": "Path traversal and remote code execution in Apache HTTP Server 2.4.49.",
    },
    "nginx/1.18.0": {
        "cveId": "CVE-2021-23017",
        "severity": "HIGH",
        "summary": "1-byte memory overwrite in resolver component leading to DoS.",
    },
    "openssl/1.0.1": {
        "cveId": "CVE-2014-0160",
        "severity": "CRITICAL",
        "summary": "Heartbleed memory disclosure vulnerability in TLS heartbeat extension.",
    },
}

def analyze_passive_exposure(
    headers: Dict[str, str],
    exposed_endpoints_found: List[str] = None,
) -> Dict[str, Any]:
    """
    Identifies banner leakage, exposed sensitive configuration files, and CVE matches.
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    server_banner = normalized.get("server")
    powered_by = normalized.get("x-powered-by")

    matched_cves = []
    if server_banner:
        banner_clean = server_banner.lower().strip()
        for vuln_banner, cve_info in KNOWN_VULNERABLE_BANNERS.items():
            if vuln_banner in banner_clean:
                matched_cves.append({
                    "cveId": cve_info["cveId"],
                    "component": server_banner,
                    "severity": cve_info["severity"],
                    "summary": cve_info["summary"],
                })

    return {
        "serverBanner": server_banner,
        "xPoweredBy": powered_by,
        "exposedFilesObserved": exposed_endpoints_found if exposed_endpoints_found else [],
        "matchedCves": matched_cves,
    }

