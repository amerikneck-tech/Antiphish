"""Main orchestrator: pass an email dict (or parsed .eml content) -> verdict."""
from __future__ import annotations

import json
import os

from .checks import (check_url, check_urls_aggregated, registrable_domain,
                     _extract_addr, check_sender, check_auth, check_display_name,
                     check_freemail_sender, check_attachments, extract_urls)
from .features import analyze_text
from .model import load_model, train
from .scorer import score_signals
from .config import THRESHOLDS

from .config import MODEL_PATH as _MODEL_PATH
_model = None
import threading as _threading
_model_lock = _threading.Lock()


def _get_model():
    global _model
    if _model is not None:
        return _model
    with _model_lock:
        if _model is not None:
            return _model
        path = os.path.abspath(_MODEL_PATH)
        if os.path.exists(path):
            try:
                _model = load_model(path)
            except Exception as e:  # tampered/missing hash/version mismatch
                import logging
                logging.getLogger("antiphish").warning(
                    "Model not loaded (%s) - retraining a fresh model", e)
                from .model import save_model
                _model = train()
                save_model(_model, path)
        else:
            # no model file yet: train once and SAVE it, so the next start is instant
            from .model import save_model
            _model = train()
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                save_model(_model, path)
            except OSError:
                pass
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
    attachment_findings: list[str] = []
    if payloads:
        from .attachment_scan import (analyze_attachment, analyze_attachment_isolated,
                                      passwords_from_text)
        from .config import ATTACHMENT_SANDBOX
        passwords = passwords_from_text(text)  # "zip password: 1234" in the body
        for fname, data in payloads.items():
            if ATTACHMENT_SANDBOX:
                sigs, findings = analyze_attachment_isolated(fname, data, passwords=passwords)
            else:
                sigs, findings = analyze_attachment(fname, data, model=_get_model(),
                                                    passwords=passwords)
            signals += sigs
            attachment_findings += findings

    urls = email.get("urls") or extract_urls(body + " " + subject)
    url_signals = check_urls_aggregated(urls, email.get("sender", ""))
    if use_url_intel and urls:
        from .urlintel import url_reputation
        for u in urls[:3]:  # limit API calls
            url_signals += url_reputation(u)
    signals += url_signals

    if use_llm:
        from .llm_judge import judge_email
        att_sigs = [f"{x['signal']}: {x['detail']}" for x in signals
                    if x["signal"].startswith(("attachment", "archive", "office", "pdf",
                                               "html", "svg", "qr", "rtf", "calendar"))]
        llm_sigs = judge_email(subject, body, email.get("sender", ""),
                               attachment_report="\n".join(att_sigs + attachment_findings),
                               context=_llm_context(email, urls, signals))
        strong = _strong_signals(signals)          # all strong evidence (LLM excluded)
        # corroboration must be TECHNICAL: text heuristics read the same words the
        # LLM reads, so counting them would double-count one piece of evidence
        technical = [n for n in strong if not n.startswith("text_")]
        authed = _authenticated_aligned(email)
        for ls in llm_sigs:
            ls = dict(ls)
            if ls["weight"] < 0 and strong:
                # prompt-injection guard: "clean" can't cancel hard evidence
                ls["weight"] = 0
                ls["detail"] += f" [ignored: conflicts with {strong[0]}]"
            elif ls["weight"] > 0 and not technical:
                # LLM alone, no technical corroboration -> tie-breaker only
                cap = 8 if authed else 15
                if ls["weight"] > cap:
                    ls["weight"] = cap
                    ls["detail"] += (" [uncorroborated: sender authenticated, weight capped]"
                                     if authed else " [uncorroborated: weight capped]")
            ls.pop("red_flags", None); ls.pop("confidence", None)
            signals.append(ls)

    model = _get_model()
    ml_prob = float(model.predict_proba([text])[0][1])

    # Legitimate bulk sender (newsletter): authenticated + aligned to From
    # domain + has List-Unsubscribe + NO strong phishing signal.
    # Passing DMARC alone is NOT trusted (most modern phishing passes it).
    bulk = _legit_bulk_sender(email, signals)
    if bulk:
        signals.append(bulk)
        ml_prob *= 0.4   # starter ML model over-flags marketing language

    score, signals, level = score_signals(signals, ml_prob)

    # Hard evidence overrides the text-based ML blend: an .exe in a zip is
    # dangerous no matter how innocent the email text looks.
    hard = [x for x in signals if x["signal"] in HARD_EVIDENCE]
    if hard and score < 90:
        score = max(score, 90.0)
        level = "CRITICAL"
        signals.append({"signal": "hard_evidence_override", "weight": 0,
                        "detail": f"Score raised to CRITICAL due to: {hard[0]['signal']}"})

    return {
        "score": score,
        "level": level,
        "thresholds": THRESHOLDS,
        "ml_phishing_probability": round(ml_prob, 3),
        "urls_found": urls,
        "attachment_findings": attachment_findings,
        "signals": sorted(signals, key=lambda s: -s["weight"]),
        "verdict": _verdict_text(level),
    }


HARD_EVIDENCE = {
    "attachment_executable", "attachment_type_mismatch", "attachment_double_extension",
    "attachment_rtlo_trick", "attachment_vt_malicious", "url_vt_malicious",
    "url_urlscan_malicious", "html_smuggling", "office_remote_template", "office_dde",
    "archive_zip_bomb",
}

STRONG_SIGNALS = {
    "text_credential_ask", "text_threat", "url_ip_host", "url_brand_spoof", "url_punycode",
    "url_at_symbol", "sender_displayname_spoof", "sender_mixed_alphabet", "reply_to_mismatch",
    "url_vt_malicious", "url_vt_flagged", "url_urlscan_malicious", "attachment_risky",
}
STRONG_PREFIXES = ("attachment_", "archive_", "office_", "pdf_", "html_", "svg_",
                   "qr_", "rtf_", "auth_")


def _authenticated_aligned(email: dict) -> bool:
    if (email.get("dmarc") or "").lower() != "pass":
        return False
    from_dom = registrable_domain(_extract_addr(email.get("sender", "")))
    doms = [email.get("dmarc_from") or ""] + list(email.get("dkim_domains") or [])
    return bool(from_dom) and from_dom in {registrable_domain(d) for d in doms if d}


def _llm_context(email: dict, urls: list[str], signals: list[dict]) -> str:
    """Facts from our own scanner, so the LLM doesn't judge text in a vacuum."""
    from .checks import domain_of
    from_dom = registrable_domain(_extract_addr(email.get("sender", "")))
    lines = [f"- From domain: {from_dom or 'unknown'}",
             f"- Authentication: SPF={email.get('spf') or '?'} DKIM={email.get('dkim') or '?'} "
             f"DMARC={email.get('dmarc') or '?'}; aligned with From domain: "
             f"{'YES' if _authenticated_aligned(email) else 'NO/unknown'}",
             f"- List-Unsubscribe header (bulk/newsletter): "
             f"{'yes' if email.get('list_unsubscribe') else 'no'}"]
    doms = []
    for u in urls:
        d = registrable_domain(domain_of(u))
        if d and d not in doms:
            doms.append(d)
    if doms:
        tagged = [f"{d} ({'same as sender' if d == from_dom else 'other'})" for d in doms[:8]]
        lines.append("- Link domains: " + ", ".join(tagged))
    else:
        lines.append("- Link domains: none")
    tech = [f"{x['signal']}" for x in signals if x["weight"] >= 10][:8]
    lines.append("- Scanner red flags: " + (", ".join(tech) if tech else "none"))
    return "\n".join(lines)


def _strong_signals(signals: list[dict]) -> list[str]:
    out = []
    for sg in signals:
        n = sg["signal"]
        if sg["weight"] <= 0 or n == "auth_all_pass":
            continue
        if n in STRONG_SIGNALS or n.startswith(STRONG_PREFIXES):
            out.append(n)
    return out


def _legit_bulk_sender(email: dict, signals: list[dict]) -> dict | None:
    if not email.get("list_unsubscribe"):
        return None
    if (email.get("dmarc") or "").lower() != "pass":
        return None
    from_dom = registrable_domain(_extract_addr(email.get("sender", "")))
    aligned_doms = [email.get("dmarc_from") or ""] + list(email.get("dkim_domains") or [])
    if not from_dom or from_dom not in {registrable_domain(d) for d in aligned_doms if d}:
        return None
    for sg in signals:
        n = sg["signal"]
        if n == "auth_all_pass":
            continue
        if n in STRONG_SIGNALS or (n.startswith(STRONG_PREFIXES) and sg["weight"] > 0):
            return None
    return {"signal": "legit_bulk_sender", "weight": -20,
            "detail": f"Authenticated newsletter from {from_dom} (DMARC aligned, List-Unsubscribe, "
                      f"no phishing indicators)"}


def analyze_eml(path: str, use_url_intel: bool = True, use_llm: bool = False) -> dict:
    """Analyze a raw .eml file directly."""
    from .email_parser import parse_eml
    return analyze_email(parse_eml(path), use_url_intel=use_url_intel, use_llm=use_llm)


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
