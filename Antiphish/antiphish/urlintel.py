"""External URL reputation: VirusTotal + Urlscan.io clients.

Uses `requests` (add to requirements). Falls back gracefully to None results
when offline or when API keys are missing, so the detector never breaks.
"""
from __future__ import annotations

import requests

from .config import VIRUSTOTAL_API_KEY, URLSCAN_API_KEY


def virustotal_report(url: str, timeout: int = 10) -> dict | None:
    """VirusTotal URL LOOKUP (GET /urls/{id}) -> {'malicious', 'suspicious'} or None.

    Lookup only - the URL is never submitted for scanning, because e-mail links
    often contain personal tokens (password-reset / magic links) that would
    then become visible to VirusTotal community users."""
    if not VIRUSTOTAL_API_KEY:
        return None
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=timeout,
        )
        if r.status_code == 404:
            return None  # never seen by VT
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)}
    except Exception:
        return None


def urlscan_report(url: str, timeout: int = 10) -> dict | None:
    """Return {'malicious': bool, 'score': int} or None."""
    if not URLSCAN_API_KEY:
        return None
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{url}"'},
            headers={"API-Key": URLSCAN_API_KEY},
            timeout=timeout,
        )
        r.raise_for_status()
        results = r.json().get("results", [])
        if not results:
            return None
        top = max(results, key=lambda x: x.get("score", 0))
        verdicts = (top.get("verdicts") or {}).get("overall", {})
        return {"malicious": bool(verdicts.get("malicious")),
                "score": top.get("score", 0)}
    except Exception:
        return None


def url_reputation(url: str) -> list[dict]:
    """Combine both feeds into detector signal dicts."""
    signals = []
    vt = virustotal_report(url)
    if vt:
        if vt["malicious"] >= 3:
            signals.append({"signal": "url_vt_malicious", "weight": 45,
                            "detail": f"VirusTotal: {vt['malicious']} engines flag this URL"})
        elif vt["malicious"] >= 1:
            signals.append({"signal": "url_vt_flagged", "weight": 30,
                            "detail": f"VirusTotal: {vt['malicious']} engine(s) flag this URL"})
        if vt["suspicious"] >= 2:
            signals.append({"signal": "url_vt_suspicious", "weight": 15,
                            "detail": f"VirusTotal: {vt['suspicious']} engines suspicious"})
    us = urlscan_report(url)
    if us and us["malicious"]:
        signals.append({"signal": "url_urlscan_malicious", "weight": 40,
                        "detail": f"urlscan.io marks this URL malicious (score {us['score']})"})
    return signals
