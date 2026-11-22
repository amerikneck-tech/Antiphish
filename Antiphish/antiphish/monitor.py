"""Live inbox monitor: watches an IMAP mailbox, analyzes each new email,
and raises a desktop notification when the risk level is high enough.

Setup (Gmail example):
  1. Enable 2FA on the account
  2. Google Account -> Security -> App passwords -> generate one
  3. set IMAP_HOST=imap.gmail.com IMAP_USER=you@gmail.com IMAP_PASSWORD=xxxx
  4. python -m antiphish.monitor

Outlook/365: IMAP_HOST=imap-mail.outlook.com (may need app password / OAuth soon)
"""
from __future__ import annotations

import getpass
import imaplib
import json
import logging
import os
import re
import time

from .config import (IMAP_HOST, IMAP_USER, IMAP_PASSWORD, POLL_SECONDS,
                     NOTIFY_MIN_SCORE, MONITOR_USE_LLM, QUARANTINE_ENABLED,
                     QUARANTINE_MIN_SCORE, QUARANTINE_FOLDER, INITIAL_SCAN)
from .detector import analyze_email
from .email_parser import parse_message

from logging.handlers import RotatingFileHandler

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[RotatingFileHandler("antiphish_alerts.log", encoding="utf-8",
                                                  maxBytes=5 * 1024 * 1024, backupCount=3),
                              logging.StreamHandler()])
log = logging.getLogger("antiphish.monitor")

LEVEL_ORDER = ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]


def _notify(title: str, message: str):
    """Desktop notification; falls back to log only."""
    try:
        from plyer import notification
        notification.notify(title=title, message=message, timeout=8,
                            app_name="AntiPhish")
    except Exception:
        log.info("NOTIFY: %s | %s", title, message)


def should_alert(level: str, score: float = 100.0,
                 min_score: int = NOTIFY_MIN_SCORE) -> bool:
    """Alert when score >= min_score (default 70 = HIGH and above)."""
    return score >= min_score


STATE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data",
                                          "monitor_state.json"))


def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: dict):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)


def _uidvalidity(mail) -> str:
    try:
        typ, data = mail.response("UIDVALIDITY")
        if data and data[0]:
            return data[0].decode() if isinstance(data[0], bytes) else str(data[0])
    except Exception:
        pass
    return "0"


def _quarantine(mail, uid: bytes) -> bool:
    """Move a message out of INBOX into the quarantine folder.
    Uses IMAP MOVE (RFC 6851) when available, else COPY + flag \\Deleted.
    Gmail: the folder appears as a label; the mail leaves the inbox."""
    try:
        mail.create(QUARANTINE_FOLDER)  # harmless if it already exists
    except Exception:
        pass
    try:
        caps = getattr(mail, "capabilities", ()) or ()
        if "MOVE" in caps:
            typ, _ = mail.uid("MOVE", uid, QUARANTINE_FOLDER)
            return typ == "OK"
        typ, _ = mail.uid("COPY", uid, QUARANTINE_FOLDER)
        if typ != "OK":
            return False
        mail.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if "UIDPLUS" in caps:
            mail.uid("EXPUNGE", uid)   # only removes THIS message
        return True
    except Exception as e:
        log.error("Quarantine failed for UID %s: %s", uid, e)
        return False


def _process(mail, uid: bytes, raw: bytes) -> dict:
    from .email_parser import message_from_bytes_robust
    parsed = parse_message(message_from_bytes_robust(raw))
    result = analyze_email(parsed, use_llm=MONITOR_USE_LLM)
    sender = parsed.get("sender", "?")
    subject = parsed.get("subject", "?")
    top3 = ", ".join(f"{x['signal']}({x['weight']:+})" for x in result["signals"][:3])
    log.info("New mail from=%s subject=%s -> %s (%s) ml=%.2f | %s",
             sender, subject, result["level"], result["score"],
             result["ml_phishing_probability"], top3)
    atts = parsed.get("attachments") or []
    if atts:
        att_sigs = [x for x in result["signals"] if x["signal"].startswith(
            ("attachment", "archive", "office", "pdf", "html", "svg", "qr", "rtf", "calendar"))]
        log.info("   attachments scanned (%d): %s", len(atts), ", ".join(atts)[:200])
        for x in att_sigs[:5]:
            log.info("     -> %s(%+d): %s", x["signal"], x["weight"], x["detail"][:160])
        if not att_sigs:
            log.info("     -> no suspicious content found in attachments")
    moved = False
    if QUARANTINE_ENABLED and result["score"] >= QUARANTINE_MIN_SCORE:
        moved = _quarantine(mail, uid)
        if moved:
            log.warning("   QUARANTINED -> moved to folder '%s'", QUARANTINE_FOLDER)
    if should_alert(result["level"], result["score"]):
        top = result["signals"][0]["detail"] if result["signals"] else ""
        extra = f"\nMoved to {QUARANTINE_FOLDER}" if moved else ""
        _notify(f"AntiPhish: {result['level']} ({result['score']})",
                f"{subject}\nFrom: {sender}\n{top}{extra}"[:240])
    result["quarantined"] = moved
    return result


def check_once(mail: imaplib.IMAP4_SSL, state: dict | None = None,
               account: str = "default") -> int:
    """Analyze every NEW message (read or unread) since the last run.

    * Tracks IMAP UIDs in data/monitor_state.json -> a mail you already opened
      on your phone is still scanned; nothing is scanned twice.
    * Fetches with BODY.PEEK[] -> the mail is NOT marked as read.
    """
    persist = state is None
    state = _load_state() if state is None else state
    mail.select("INBOX")
    validity = _uidvalidity(mail)
    acc = state.get(account) or {}
    if acc.get("uidvalidity") != validity:
        acc = {"uidvalidity": validity, "last_uid": None}

    if acc.get("last_uid") is None:
        # first run: scan only the newest INITIAL_SCAN messages
        typ, data = mail.uid("SEARCH", None, "ALL")
        uids = (data[0].split() if typ == "OK" and data and data[0] else [])
        uids = uids[-INITIAL_SCAN:] if INITIAL_SCAN > 0 else []
        if not uids:
            all_uids = data[0].split() if typ == "OK" and data and data[0] else []
            acc["last_uid"] = int(all_uids[-1]) if all_uids else 0
    else:
        typ, data = mail.uid("SEARCH", None, f"UID {acc['last_uid'] + 1}:*")
        uids = [u for u in (data[0].split() if typ == "OK" and data and data[0] else [])
                if int(u) > acc["last_uid"]]  # 'N:*' returns the last mail if none newer

    count = 0
    for uid in uids:
        try:
            typ, msg_data = mail.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((p[1] for p in (msg_data or []) if isinstance(p, tuple)), None)
            if typ == "OK" and raw:
                _process(mail, uid, raw)
                count += 1
        except Exception as e:
            log.error("Failed to analyze message UID %s: %s", uid, e)
        acc["last_uid"] = max(int(uid), acc.get("last_uid") or 0)
    state[account] = acc
    if persist:
        _save_state(state)
    return count


KEYRING_SERVICE = "antiphish-imap"


def _keyring_get(user: str) -> str | None:
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, user)
    except Exception:
        return None


def _save_env(host: str, user: str, password: str):
    """Host/user -> .env ; password -> OS credential store (Windows Credential
    Manager / macOS Keychain / Secret Service). Plain-text only as last resort."""
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    stored_securely = False
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, user, password)
        stored_securely = keyring.get_password(KEYRING_SERVICE, user) == password
    except Exception:
        stored_securely = False
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"IMAP_HOST={host}\nIMAP_USER={user}\n")
        if not stored_securely:
            f.write(f"IMAP_PASSWORD={password}\n")
    if stored_securely:
        print(f"Saved host/user to {path}; password stored in the OS credential manager.")
    else:
        print(f"WARNING: secure credential store unavailable (pip install keyring) - "
              f"password saved in plain text to {path}. Do NOT commit this file!")


def _wizard() -> tuple[str, str, str]:
    """Interactive setup: email -> auto-detect provider -> password -> test -> save."""
    from .providers import detect, guess_hosts

    print("=== AntiPhish setup wizard ===")
    email = input("Your email address: ").strip()
    while "@" not in email:
        email = input("That doesn't look like an email. Try again: ").strip()

    info = detect(email)
    if info:
        print(f"Detected provider: {info['name']}  (IMAP: {info['host']}:{info['port']})")
        if info.get("hint"):
            print(info["hint"])
        host = info["host"]
    else:
        domain = email.split("@", 1)[1]
        candidates = guess_hosts(email)
        print(f"Unknown provider '{domain}'. Best guess: {candidates[0]}")
        host = input(f"IMAP server [{candidates[0]}]: ").strip() or candidates[0]

    for attempt in range(3):
        password = getpass.getpass("Password / app password (hidden input): ")
        print("Testing connection...", end=" ", flush=True)
        try:
            mail = _connect(host, email, password)
            mail.logout()
            print("OK!")
        except Exception as e:
            print(f"FAILED ({e})")
            if attempt < 2:
                print("Check the password/app-password and try again.")
                continue
            raise SystemExit("Could not connect. Check provider settings (IMAP enabled?).")
        break

    save = input("Save these settings for next time? [Y/n]: ").strip().lower()
    if save in ("", "y", "yes"):
        _save_env(host, email, password)
    return host, email, password


def _resolve_credentials() -> tuple[str, str, str]:
    if IMAP_HOST and IMAP_USER and IMAP_PASSWORD:
        return IMAP_HOST, IMAP_USER, IMAP_PASSWORD
    if IMAP_HOST and IMAP_USER:
        pw = _keyring_get(IMAP_USER)
        if pw:
            return IMAP_HOST, IMAP_USER, pw
    print("(Tip: you can skip this wizard by setting IMAP_HOST/IMAP_USER/IMAP_PASSWORD)")
    return _wizard()


def _connect(host: str, user: str, password: str, port: int = 993):
    """Connect with a hard timeout so a blocked network can never hang forever."""
    import socket
    socket.setdefaulttimeout(30)
    mail = imaplib.IMAP4_SSL(host, port)
    mail.login(user, password)
    return mail


def run():
    host, user, password = _resolve_credentials()
    log.info("Connecting to %s as %s ...", host, user)
    try:
        from .urlintel import VIRUSTOTAL_API_KEY
        vt_state = "ON" if VIRUSTOTAL_API_KEY else "OFF (no key)"
    except Exception:
        vt_state = "?"
    try:
        mail = _connect(host, user, password)
        llm_state = "OFF (MONITOR_USE_LLM=0)"
        if MONITOR_USE_LLM:
            from .llm_judge import llm_status
            ok, llm_state = llm_status()
            if not ok:
                log.warning("Qwen AI judge requested but NOT available: %s", llm_state)
        log.info("Connected. Polling every %ds. VirusTotal: %s. LLM judge: %s. Alert score >= %d. "
                 "Quarantine: %s. Ctrl+C to stop.",
                 POLL_SECONDS, vt_state, llm_state, NOTIFY_MIN_SCORE,
                 f"ON (score >= {QUARANTINE_MIN_SCORE} -> '{QUARANTINE_FOLDER}')"
                 if QUARANTINE_ENABLED else "OFF")
    except Exception as e:
        raise SystemExit(f"Connection failed: {e}\n"
                         f"Check: app password correct? IMAP enabled? 2FA on?")
    try:
        while True:
            try:
                check_once(mail, account=f"{user}@{host}")
            except imaplib.IMAP4.abort:
                log.warning("Connection lost, reconnecting...")
                mail = _connect(host, user, password)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    finally:
        try:
            from .attachment_scan import shutdown_sandbox
            shutdown_sandbox()
        except Exception:
            pass
        try:
            mail.logout()
        except Exception:
            pass
if __name__ == "__main__":
    run()
