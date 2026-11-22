"""Forward-to-scan mailbox worker.

Users forward a suspicious mail (best: AS ATTACHMENT) to e.g. scan@yourdomain.com.
This worker polls that mailbox over IMAP, analyzes the original, and replies
with a plain-text report via SMTP.

    python -m webapp.mail_intake

Safety:
* only registered users (From address = account e-mail) get a scan; others are
  ignored silently (no backscatter / no free scanning for strangers)
* the forwarding message must not FAIL SPF/DMARC (prevents spoofed From)
* loop protection: ignores auto-replies, bounces and our own reports
* reports contain defanged links only
"""
from __future__ import annotations

import email
import email.policy
import imaplib
import json
import logging
import os
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import make_msgid, parseaddr

from antiphish.email_parser import parse_message, message_from_bytes_robust

from . import config, db, scanning, security
from .explain import explain_signal, level_info

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] intake: %(message)s")
log = logging.getLogger("antiphish.intake")

STATE_PATH = os.path.join(config.DATA_DIR, "intake_state.json")
REPORT_TAG = "[AntiPhish]"


def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(st: dict):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, STATE_PATH)


def _auth_failed(msg) -> bool:
    """True when the receiving server says the FORWARDER's mail failed SPF/DMARC."""
    auth = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or [])).lower()
    if not auth:
        return False  # header not present -> cannot judge (logged by caller)
    return bool(re.search(r"\bdmarc\s*=\s*fail\b", auth)) or (
        bool(re.search(r"\bspf\s*=\s*fail\b", auth)) and not re.search(r"\bdkim\s*=\s*pass\b", auth))


def _is_automated(msg) -> bool:
    if (msg.get("Auto-Submitted") or "no").lower() != "no":
        return True
    if msg.get("X-Autoreply") or msg.get("X-Autorespond") or msg.get("List-Id"):
        return True
    if (msg.get("Precedence") or "").lower() in ("bulk", "junk", "list", "auto_reply"):
        return True
    frm = parseaddr(msg.get("From", ""))[1].lower()
    if frm.startswith(("mailer-daemon", "postmaster", "noreply", "no-reply")):
        return True
    if frm == config.INTAKE_USER.lower():
        return True
    return REPORT_TAG in (msg.get("Subject") or "")


def build_report(res: dict, subject: str, sender: str, scan_id: str, mode_note: str) -> str:
    name, _cls, advice = level_info(res["level"])
    lines = [
        f"AntiPhish rezultat: {name.upper()} ({res['score']:.0f}/100)",
        "",
        advice,
        "",
        f"Naslov:     {security.defang_all(subject or '-')}",
        f"Pošiljalac: {security.defang_all(sender or '-')}",
    ]
    if mode_note:
        lines += ["", f"NAPOMENA: {mode_note}"]
    pos = [s for s in res.get("signals", []) if s["weight"] > 0][:8]
    neg = [s for s in res.get("signals", []) if s["weight"] < 0][:4]
    if pos:
        lines += ["", "Zašto je sumnjivo:"]
        for s in pos:
            lines.append(f"  +{s['weight']:<3} {explain_signal(s['signal']) or s['signal']}")
            lines.append(f"        {security.defang_all(s['detail'])[:200]}")
    if neg:
        lines += ["", "Šta ide u prilog legitimnosti:"]
        for s in neg:
            lines.append(f"  {s['weight']:<4} {explain_signal(s['signal']) or s['signal']}")
    if res.get("attachment_findings"):
        lines += ["", "Prilozi:"] + [f"  - {security.defang_all(f)[:200]}" for f in res["attachment_findings"][:10]]
    if res.get("urls_found"):
        lines += ["", "Linkovi u mailu (onesposobljeni - NE otvaraj):"]
        lines += [f"  - {security.defang_all(u)[:150]}" for u in res["urls_found"][:8]]
    lines += ["", f"Detaljan izvještaj i feedback: {config.BASE_URL}/r/{scan_id}",
              "", "Linkovi u ovom izvještaju su namjerno onesposobljeni (hxxp, [.]).",
              "AntiPhish beta – pomoćni alat, ne garantuje 100% zaštitu."]
    return "\n".join(lines)


def _send(to_addr: str, subject: str, body: str, in_reply_to: str | None):
    msg = EmailMessage()
    msg["From"] = config.INTAKE_USER
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=config.INTAKE_USER.split("@")[-1] or None)
    msg["Auto-Submitted"] = "auto-replied"          # RFC 3834: prevents reply loops
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if config.INTAKE_SMTP_PORT == 465:
        with smtplib.SMTP_SSL(config.INTAKE_SMTP_HOST, config.INTAKE_SMTP_PORT, context=ctx, timeout=30) as s:
            s.login(config.INTAKE_USER, config.INTAKE_PASSWORD)
            s.send_message(msg)
    else:
        with smtplib.SMTP(config.INTAKE_SMTP_HOST, config.INTAKE_SMTP_PORT, timeout=30) as s:
            s.starttls(context=ctx)
            s.login(config.INTAKE_USER, config.INTAKE_PASSWORD)
            s.send_message(msg)


def process_message(raw: bytes, send=_send) -> str:
    """Handle one incoming message. Returns a status string (for logs/tests)."""
    outer = message_from_bytes_robust(raw)
    from_addr = parseaddr(outer.get("From", ""))[1].lower()
    if _is_automated(outer):
        return "ignored:automated"
    user = db.get_user_by_email(from_addr)
    if not user:
        log.info("ignored mail from unregistered address %s", from_addr)
        return "ignored:unknown-sender"
    if _auth_failed(outer):
        log.warning("ignored mail claiming to be %s: SPF/DMARC failed (spoofed?)", from_addr)
        return "ignored:auth-failed"
    if not outer.get_all("Authentication-Results"):
        log.info("no Authentication-Results header on mail from %s - accepting", from_addr)

    inner, how = scanning.unwrap_forward(outer)
    if how == "attached":
        parsed = parse_message(inner)
        note, has_headers = "", True
    else:
        parsed = parse_message(outer)
        # analyze the forwarded content, not the forwarder's own identity
        parsed["sender"] = _forwarded_from(parsed.get("body", "")) or ""
        parsed["reply_to"] = None
        for k in ("spf", "dkim", "dmarc", "dmarc_from"):
            parsed[k] = None
        parsed["dkim_domains"], parsed["list_unsubscribe"] = [], False
        parsed["subject"] = re.sub(r"^\s*(fwd?|fw|wg|tr|vs|i)\s*:\s*", "", parsed.get("subject", ""),
                                   flags=re.I)
        note = ("Mail je proslijeđen kao običan tekst – zaglavlja originala (pravi pošiljalac, "
                "SPF/DKIM/DMARC) nisu dostupna. Za potpunu analizu proslijedi ga KAO PRILOG "
                "(Gmail: označi mail → ⋮ → 'Forward as attachment').")
        has_headers = False
    mode = "ai" if config.INTAKE_USE_LLM and scanning.llm_ready() else "quick"
    try:
        scan_id = scanning.run_scan(user, parsed, "email", mode, has_headers, note)
    except scanning.ScanError as e:
        send(from_addr, f"{REPORT_TAG} Provjera nije izvršena", f"{e}\n\n{config.BASE_URL}",
             outer.get("Message-ID"))
        return "error:" + str(e)
    row = db.get_scan(scan_id)
    res = json.loads(row["result_json"])
    name = level_info(res["level"])[0]
    body = build_report(res, parsed.get("subject", ""), parsed.get("sender", ""), scan_id, note)
    send(from_addr, f"{REPORT_TAG} {name} ({res['score']:.0f}/100): {parsed.get('subject', '')[:80]}",
         body, outer.get("Message-ID"))
    return f"scanned:{res['level']}"


def _forwarded_from(body: str) -> str | None:
    """Pick the original sender out of an inline-forward header block."""
    m = re.search(r"^\s*(?:From|Od|Från|Von|De)\s*:\s*(.+)$", body or "", flags=re.I | re.M)
    return m.group(1).strip()[:200] if m else None


def poll_once(mail, state: dict) -> int:
    mail.select("INBOX")
    typ, data = mail.response("UIDVALIDITY")
    validity = (data[0].decode() if data and isinstance(data[0], bytes) else str(data[0] if data else "0"))
    if state.get("uidvalidity") != validity:
        # first start: skip existing mail, only handle new arrivals
        typ, d = mail.uid("SEARCH", None, "ALL")
        uids = d[0].split() if typ == "OK" and d and d[0] else []
        state.update({"uidvalidity": validity, "last_uid": int(uids[-1]) if uids else 0})
        return 0
    typ, d = mail.uid("SEARCH", None, f"UID {state['last_uid'] + 1}:*")
    uids = [u for u in (d[0].split() if typ == "OK" and d and d[0] else []) if int(u) > state["last_uid"]]
    n = 0
    for uid in uids:
        try:
            typ, md = mail.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((p[1] for p in (md or []) if isinstance(p, tuple)), None)
            if raw:
                status = process_message(raw)
                log.info("UID %s -> %s", uid.decode(), status)
                n += 1
        except Exception:
            log.exception("failed to process UID %s", uid)
        state["last_uid"] = max(int(uid), state["last_uid"])
    return n


def run():
    if not (config.INTAKE_USER and config.INTAKE_PASSWORD):
        raise SystemExit("Set INTAKE_USER and INTAKE_PASSWORD (the scan@ mailbox) in .env")
    db.init()
    log.info("Intake mailbox %s via %s - polling every %ss", config.INTAKE_USER,
             config.INTAKE_IMAP_HOST, config.INTAKE_POLL_SECONDS)
    state = _load_state()
    mail = None
    while True:
        try:
            if mail is None:
                mail = imaplib.IMAP4_SSL(config.INTAKE_IMAP_HOST, config.INTAKE_IMAP_PORT, timeout=30)
                mail.login(config.INTAKE_USER, config.INTAKE_PASSWORD)
            poll_once(mail, state)
            _save_state(state)
        except (imaplib.IMAP4.abort, OSError) as e:
            log.warning("IMAP connection problem (%s) - reconnecting", e)
            mail = None
        except Exception:
            log.exception("intake loop error")
            mail = None
        time.sleep(config.INTAKE_POLL_SECONDS)


if __name__ == "__main__":
    run()
