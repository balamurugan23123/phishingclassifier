"""Scoring engine and verdict bands."""

from __future__ import annotations

from typing import Any, Dict, List

VERDICT_BANDS = [
    (0, 24, "Clean"),
    (25, 49, "Suspicious"),
    (50, 74, "Likely Malicious"),
    (75, 100, "Malicious"),
]

MAX_SCORE = 100


def verdict_for(score: int) -> str:
    for lo, hi, name in VERDICT_BANDS:
        if lo <= score <= hi:
            return name
    return "Malicious" if score >= MAX_SCORE else "Clean"


def score_result(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate risk score and verdict from fired signals."""
    raw = sum(s["weight"] for s in signals)
    score = min(raw, MAX_SCORE)
    return {
        "score": score,
        "raw_weight_total": raw,
        "capped": raw > MAX_SCORE,
        "verdict": verdict_for(score),
        "signal_count": len(signals),
        "top_signals": sorted(
            ({"id": s["id"], "weight": s["weight"], "reason": s["reason"]}
             for s in signals),
            key=lambda s: -s["weight"],
        )[:3],
    }
