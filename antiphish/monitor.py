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
import logging
import os
import time

from .config import (IMAP_HOST, IMAP_USER, IMAP_PASSWORD, POLL_SECONDS,
                     NOTIFY_MIN_SCORE, MONITOR_USE_LLM)
from .detector import analyze_email
from .email_parser import parse_message

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler("antiphish_alerts.log", encoding="utf-8"),
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


def check_once(mail: imaplib.IMAP4_SSL) -> int:
    """Fetch and analyze unseen emails once. Returns number processed."""
    mail.select("INBOX")
    typ, data = mail.search(None, "UNSEEN")
    if typ != "OK":
        return 0
    count = 0
    for num in data[0].split():
        try:
            typ, msg_data = mail.fetch(num, "(RFC822)")
            if typ != "OK":
                continue
            import email as email_mod
            import email.policy
            msg = email_mod.message_from_bytes(msg_data[0][1], policy=email.policy.default)
            parsed = parse_message(msg)
            result = analyze_email(parsed, use_llm=MONITOR_USE_LLM)
            sender = parsed.get("sender", "?")
            subject = parsed.get("subject", "?")
            log.info("New mail from=%s subject=%s -> %s (%s)",
                     sender, subject, result["level"], result["score"])
            if should_alert(result["level"], result["score"]):
                top = result["signals"][0]["detail"] if result["signals"] else ""
                _notify(f"AntiPhish: {result['level']} ({result['score']})",
                        f"{subject}\nFrom: {sender}\n{top}"[:240])
            count += 1
        except Exception as e:
            log.error("Failed to analyze message %s: %s", num, e)
    return count


def _save_env(host: str, user: str, password: str):
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"IMAP_HOST={host}\nIMAP_USER={user}\nIMAP_PASSWORD={password}\n")
    print(f"Saved to {path} (do NOT commit this file to git!)")


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
        log.info("Connected. Polling every %ds. VirusTotal: %s. LLM judge: %s. Alert score >= %d. Ctrl+C to stop.",
                 POLL_SECONDS, vt_state, "ON" if MONITOR_USE_LLM else "OFF", NOTIFY_MIN_SCORE)
    except Exception as e:
        raise SystemExit(f"Connection failed: {e}\n"
                         f"Check: app password correct? IMAP enabled? 2FA on?")
    try:
        while True:
            try:
                check_once(mail)
            except imaplib.IMAP4.abort:
                log.warning("Connection lost, reconnecting...")
                mail = _connect(host, user, password)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    finally:
        try:
            mail.logout()
        except Exception:
            pass
if __name__ == "__main__":
    run()
