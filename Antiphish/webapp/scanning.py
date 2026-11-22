"""Scan service shared by the web UI and the forward-to-scan mailbox.

Turns raw input (.eml bytes / pasted source / plain text) into the detector's
email dict, enforces credits + concurrency, stores the result."""
from __future__ import annotations

import email
import email.policy
import logging
import re
import secrets
import threading

from antiphish.detector import analyze_email
from antiphish.email_parser import parse_message, message_from_bytes_robust

from . import config, db

log = logging.getLogger("antiphish.web")
_slots = threading.BoundedSemaphore(max(1, config.SCAN_CONCURRENCY))


class ScanError(Exception):
    """User-facing error (message is shown to the user)."""


_HEADER_RE = re.compile(rb"^(from|subject|received|return-path|message-id|date|to|mime-version)\s*:",
                        re.I | re.M)


def looks_like_raw_email(data: bytes) -> bool:
    head = data[:5000]
    return len(_HEADER_RE.findall(head)) >= 2


def parse_input(data: bytes) -> tuple[dict, bool]:
    """-> (email dict, has_headers). Plain text is analyzed as a body only."""
    if looks_like_raw_email(data):
        msg = message_from_bytes_robust(data)
        return parse_message(msg), True
    text = data.decode("utf-8", errors="replace")
    lines = text.strip().splitlines()
    subject = ""
    if lines and len(lines[0]) < 150:
        subject = lines[0]
    return {"subject": subject, "body": text, "sender": "", "attachments": [],
            "attachment_data": {}}, False


def unwrap_forward(msg) -> tuple[object, str]:
    """For forwarded mail: prefer an attached original (message/rfc822).
    -> (message to analyze, 'attached' | 'inline')."""
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) else inner
            if inner is not None:
                return inner, "attached"
        fn = (part.get_filename() or "").lower()
        if fn.endswith(".eml"):
            payload = part.get_payload(decode=True) or b""
            if looks_like_raw_email(payload):
                return message_from_bytes_robust(payload), "attached"
    return msg, "inline"


def llm_ready() -> bool:
    if not config.WEB_ALLOW_LLM:
        return False
    try:
        from antiphish.llm_judge import llm_status
        return llm_status()[0]
    except Exception:
        return False


def run_scan(user, parsed: dict, source: str, mode: str, has_headers: bool = True,
             note: str = "") -> str:
    """Charge credits, analyze, store. Returns scan id. Raises ScanError."""
    if user["disabled"]:
        raise ScanError("Nalog je deaktiviran.")
    cost = config.COST_AI if mode == "ai" else config.COST_QUICK
    n = db.hit(f"scan:{user['id']}", 3600)
    if n > config.SCANS_PER_HOUR:
        raise ScanError(f"Previše provjera u zadnjih sat vremena (limit {config.SCANS_PER_HOUR}). Pokušaj kasnije.")
    if not db.charge(user["id"], cost):
        raise ScanError(f"Nemaš dovoljno kredita (potrebno {cost}).")
    if not _slots.acquire(timeout=120):
        db.refund(user["id"], cost)
        raise ScanError("Server je trenutno zauzet. Pokušaj ponovo za minut.")
    try:
        result = analyze_email(parsed, use_url_intel=config.WEB_USE_URL_INTEL,
                               use_llm=(mode == "ai"))
    except Exception as e:
        db.refund(user["id"], cost)
        log.exception("scan failed")
        raise ScanError("Analiza nije uspjela. Krediti su vraćeni.") from e
    finally:
        _slots.release()

    result["has_headers"] = has_headers
    result["note"] = note
    result["attachments"] = list(parsed.get("attachments") or [])
    result["auth"] = {k: parsed.get(k) for k in ("spf", "dkim", "dmarc")}
    scan_id = secrets.token_urlsafe(12)
    text = f"{parsed.get('subject', '')}\n{parsed.get('body', '')}".strip()
    db.save_scan(scan_id, user["id"], source, mode, result,
                 parsed.get("subject", ""), parsed.get("sender", ""), text, cost)
    try:
        db.purge_old_text(config.RETAIN_TEXT_HOURS)
    except Exception:
        pass
    return scan_id
