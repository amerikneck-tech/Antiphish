"""Weighted scoring: combine heuristic signals + ML probability -> 0..100."""
from __future__ import annotations

import numpy as np

# Signal cap: sum of weights saturates; we compress with diminishing returns.
def score_signals(signals: list[dict], ml_prob: float, n_urls: int = 1) -> tuple[float, list[dict], str]:
    total_w = sum(s["weight"] for s in signals)
    # Diminishing returns: 100 * (1 - exp(-k * total_w))
    heuristic = 100.0 * (1 - np.exp(-0.035 * total_w))
    ml_component = 100.0 * ml_prob
    # Heuristics weighted a bit higher when URL-level signals are strong
    final = 0.55 * heuristic + 0.45 * ml_component

    if final < 30:
        level = "LOW"
    elif final < 60:
        level = "SUSPICIOUS"
    elif final < 85:
        level = "HIGH"
    else:
        level = "CRITICAL"
    return round(max(0.0, min(final, 100.0)), 1), signals, level
