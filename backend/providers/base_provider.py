"""
TrustShield Threat Intelligence - Base Provider Interface
Defines standard schema, rate limiting, and error handling contracts for all external threat providers.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class BaseThreatProvider(ABC):
    """
    Abstract base class for all threat intelligence and domain analysis providers.
    Standardized provider statuses:
      - SUCCESS: Provider completed query with findings (or confirmed benign).
      - NO_MATCH: Target checked; not found in threat database.
      - MALICIOUS: Confirmed malicious listing in threat feed.
      - UNCONFIGURED: Required API credentials not provided in environment.
      - UNAVAILABLE: Provider endpoint unreachable or timed out.
      - RATE_LIMITED: Provider API quota or rate limit exceeded.
      - ERROR: Malformed response or unhandled provider exception.
    """

    def __init__(self, name: str, provider_id: str, is_configured: bool = True):
        self.name = name
        self.provider_id = provider_id
        self.is_configured = is_configured

    @abstractmethod
    def query(self, target_url: str, hostname: str) -> Dict[str, Any]:
        """
        Executes query against external threat provider.
        Must return standard dictionary conforming to provider response schema.
        """
        pass

    def build_result(
        self,
        status: str,
        is_malicious: bool = False,
        threat_type: Optional[str] = None,
        confidence: int = 0,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Standardized provider response builder."""
        return {
            "providerId": self.provider_id,
            "providerName": self.name,
            "status": status,
            "isMalicious": is_malicious,
            "threatType": threat_type,
            "confidence": confidence,
            "details": details or {},
            "error": error,
            "sourceAttribution": source or self.name,
            "retrievedAt": datetime.now(timezone.utc).isoformat(),
        }

