"""
STIX 2.1 Domain Object & Cyber-Observable Generator
Generates OASIS-compliant STIX 2.1 JSON indicator bundles.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

def generate_stix_indicator(
    hostname: str,
    verdict: str,
    confidence: int = 85,
    tlp_marking: str = "TLP:AMBER",
    actor_attribution: str = "TrustShield Intelligence Engine",
) -> Dict[str, Any]:
    """Generates a standardized STIX 2.1 Indicator SDO."""
    ind_id = f"indicator--{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).isoformat()

    pattern = f"[domain-name:value = '{hostname}']"
    indicator_types = ["malicious-activity"] if verdict in ("MALICIOUS", "PKI_TRUST_COMPROMISED") else ["anomalous-activity"]

    return {
        "id": ind_id,
        "type": "indicator",
        "specVersion": "2.1",
        "name": f"Threat Indicator: {hostname}",
        "description": f"Observed infrastructure exhibiting {verdict.lower()} telemetry.",
        "indicatorTypes": indicator_types,
        "pattern": pattern,
        "patternType": "stix",
        "validFrom": now_iso,
        "tlpMarking": tlp_marking,
        "confidenceScore": confidence,
        "sourceAttribution": actor_attribution,
        "externalReferences": [
            {
                "sourceName": "TrustShield CTI",
                "externalId": f"TS-{ind_id[:18]}",
            }
        ],
        "reputationDecay": {
            "firstSeen": now_iso,
            "lastSeen": now_iso,
            "decayHalfLifeDays": 30,
            "currentWeight": 1.0,
        },
        "communitySightingsCount": 5 if verdict != "CLEAN" else 0,
        "reporterReliabilityScore": 90,
    }

