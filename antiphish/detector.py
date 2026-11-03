"""Main orchestrator: pass an email dict (or parsed .eml content) -> verdict."""
from __future__ import annotations

import json
import os

from .checks import (check_url, check_sender, check_auth, check_display_name,
                     check_freemail_sender, check_attachments, extract_urls)
from .features import analyze_text
from .model import load_model, train
from .scorer import score_signals
from .config import THRESHOLDS

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "model.joblib")
_model = None


def _get_model():
    global _model
    if _model is None:
        path = os.path.abspath(_MODEL_PATH)
        _model = load_model(path) if os.path.exists(path) else train()
    return _model


def analyze_email(email: dict, use_url_intel: bool = True, use_llm: bool = False) -> dict:
    """email: dict with keys
    subject, body, sender, reply_to (optional),
    spf/dkim/dmarc (optional: 'pass'|'fail'|'none'),
    urls (optional), attachments (optional list),
    claimed_role (optional: 'it'|'billing'|'ceo'|'support')
    """
    subject = email.get("subject", "")
    body = email.get("body", "")
    text = f"{subject} {body}".strip()

    signals = []
    signals += analyze_text(text)
    signals += check_sender(email.get("sender", ""), email.get("reply_to"))
    signals += check_display_name(email.get("sender", ""))
    signals += check_freemail_sender(email.get("sender", ""), email.get("claimed_role"))
    signals += check_auth(email.get("spf"), email.get("dkim"), email.get("dmarc"))
    signals += check_attachments(email.get("attachments"))

    # content-level attachment scan (PDF text, embedded URLs, VT hash)
    payloads = email.get("attachment_data") or {}
    if payloads:
        from .attachment_scan import scan_attachment
        model = _get_model()
        for fname, data in payloads.items():
            signals += scan_attachment(fname, data, model=model)

    urls = email.get("urls") or extract_urls(body + " " + subject)
    url_signals = []
    for u in urls:
        url_signals += check_url(u)
    if use_url_intel and urls:
        from .urlintel import url_reputation
        for u in urls[:3]:  # limit API calls
            url_signals += url_reputation(u)
    signals += url_signals

    if use_llm:
        from .llm_judge import judge_email
        signals += judge_email(subject, body, email.get("sender", ""))

    model = _get_model()
    ml_prob = float(model.predict_proba([text])[0][1])

    score, signals, level = score_signals(signals, ml_prob)

    return {
        "score": score,
        "level": level,
        "thresholds": THRESHOLDS,
        "ml_phishing_probability": round(ml_prob, 3),
        "urls_found": urls,
        "signals": sorted(signals, key=lambda s: -s["weight"]),
        "verdict": _verdict_text(level),
    }


def analyze_eml(path: str, use_url_intel: bool = True) -> dict:
    """Analyze a raw .eml file directly."""
    from .email_parser import parse_eml
    return analyze_email(parse_eml(path), use_url_intel=use_url_intel)


def _verdict_text(level: str) -> str:
    return {
        "LOW": "No strong phishing indicators detected. Normal caution applies.",
        "SUSPICIOUS": "Some suspicious patterns detected. Verify the sender before clicking any links.",
        "HIGH": "Likely phishing. Do not click links or open attachments. Report to IT security.",
        "CRITICAL": "Almost certainly phishing. Block the sender, report the message, and do not interact.",
    }[level]


def export_json(result: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
