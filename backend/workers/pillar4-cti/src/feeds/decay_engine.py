"""
Crowdsourced Consensus & Reputation Time-Decay Engine
Applies exponential half-life decay curves to indicators so remediated domains recover over time.
W(t) = W_0 * (0.5)^(delta_days / half_life)
"""
import math
from datetime import datetime, timezone
from typing import Dict, Any

def compute_reputation_decay(
    first_seen_iso: str,
    last_seen_iso: str,
    half_life_days: float = 30.0,
    initial_weight: float = 1.0,
) -> float:
    """
    Calculates dynamic confidence weight between 0.0 and 1.0 based on elapsed time since last seen.
    """
    try:
        last_dt = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        delta_days = max(0.0, (now_dt - last_dt).total_seconds() / 86400.0)

        # Exponential decay formula
        current_weight = initial_weight * math.pow(0.5, delta_days / half_life_days)
        return round(max(0.05, min(1.0, current_weight)), 3)
    except Exception:
        return initial_weight

