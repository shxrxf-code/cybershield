from __future__ import annotations
from typing import Dict, Any, List
import math

RISK_LEVELS = [
    (0, 19, "low"),
    (20, 39, "moderate"),
    (40, 69, "high"),
    (70, 89, "critical"),
    (90, 100, "severe"),
]

def score_to_level(score: int) -> str:
    for lo, hi, lvl in RISK_LEVELS:
        if lo <= score <= hi:
            return lvl
    if score < 0:
        return "low"
    return "severe"

def compute_risk_score(features: Dict[str, Any], weights: Dict[str, float] | None = None) -> Dict[str, Any]:
    weights = weights or {
        "phishing_indicators": 25.0,
        "malware_signatures": 30.0,
        "new_domain": 15.0,
        "suspicious_redirects": 10.0,
        "ip_reputation": 8.0,
        "behavior_anomaly": 12.0,
    }
    reasons: List[str] = []
    explain: Dict[str, float] = {}
    total = 0.0
    for k, w in weights.items():
        v = features.get(k)
        if isinstance(v, bool) and v:
            contrib = w
            total += contrib
            explain[k] = round(contrib, 2)
            reasons.append(f"{k.replace('_', ' ').title()} detected")
        elif isinstance(v, (int, float)) and v > 0:
            contrib = min(w * float(v), w)
            total += contrib
            explain[k] = round(contrib, 2)
            if contrib > 0:
                reasons.append(f"{k.replace('_', ' ').title()} elevated")
    score = int(max(0, min(100, round(total))))
    level = score_to_level(score)
    confidence = min(0.95, 0.4 + (score / 100.0) * 0.55)
    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "explainability": explain,
        "confidence": round(confidence, 3),
        "sources": ["deterministic_rules", "ai_engine_stub"],
    }
