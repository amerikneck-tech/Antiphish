"""Email provider database + IMAP server auto-detection.

detect(email)   -> known provider config or None
guess_hosts(domain) -> candidate IMAP hosts for unknown providers
"""
from __future__ import annotations

_GMAIL = {"name": "Gmail", "host": "imap.gmail.com", "port": 993,
          "hint": "Gmail needs an APP PASSWORD (not your regular password):\n"
                  "  myaccount.google.com -> Security -> 2-Step Verification (ON)\n"
                  "  -> search 'App passwords' -> generate -> copy the 16-char code"}
_OUTLOOK = {"name": "Outlook / Hotmail", "host": "imap-mail.outlook.com", "port": 993,
            "hint": "If login fails, create an app password:\n"
                    "  account.microsoft.com -> Security -> Advanced security options\n"
                    "  -> 'Create a new app password'"}
_YAHOO = {"name": "Yahoo", "host": "imap.mail.yahoo.com", "port": 993,
          "hint": "Yahoo needs an app password:\n"
                  "  login.yahoo.com -> Account Security -> 'Generate app password'"}

PROVIDERS = {
    "gmail.com": _GMAIL, "googlemail.com": _GMAIL,
    "outlook.com": _OUTLOOK, "hotmail.com": _OUTLOOK, "live.com": _OUTLOOK,
    "msn.com": _OUTLOOK,
    "yahoo.com": _YAHOO, "ymail.com": _YAHOO, "rocketmail.com": _YAHOO,
    "icloud.com": {"name": "iCloud", "host": "imap.mail.me.com", "port": 993,
                   "hint": "iCloud needs an app-specific password:\n"
                           "  appleid.apple.com -> Sign-In and Security -> App-Specific Passwords"},
    "me.com": {"name": "iCloud", "host": "imap.mail.me.com", "port": 993,
               "hint": "iCloud needs an app-specific password (appleid.apple.com)."},
    "mac.com": {"name": "iCloud", "host": "imap.mail.me.com", "port": 993,
                "hint": "iCloud needs an app-specific password (appleid.apple.com)."},
    "aol.com": {"name": "AOL", "host": "imap.aol.com", "port": 993,
                "hint": "AOL needs an app password: help.aol.com -> 'Manage app passwords'"},
    "gmx.com": {"name": "GMX", "host": "imap.gmx.com", "port": 993,
                "hint": "GMX: enable IMAP in Settings -> POP3/IMAP first."},
    "gmx.net": {"name": "GMX", "host": "imap.gmx.com", "port": 993,
                "hint": "GMX: enable IMAP in Settings -> POP3/IMAP first."},
    "zoho.com": {"name": "Zoho Mail", "host": "imap.zoho.com", "port": 993,
                 "hint": "Zoho: create an app password in myaccount.zoho.com."},
    "proton.me": {"name": "Proton Mail", "host": "127.0.0.1", "port": 1143,
                  "hint": "Proton requires the Proton Mail Bridge app running locally\n"
                          "(https://proton.me/mail/bridge) - it exposes IMAP on 127.0.0.1:1143."},
    "protonmail.com": {"name": "Proton Mail", "host": "127.0.0.1", "port": 1143,
                       "hint": "Proton requires the Proton Mail Bridge app running locally."},
    "seznam.cz": {"name": "Seznam", "host": "imap.seznam.cz", "port": 993, "hint": ""},
}


def detect(email: str) -> dict | None:
    """Match an email address to a known provider."""
    if "@" not in (email or ""):
        return None
    domain = email.split("@", 1)[1].strip().lower()
    return PROVIDERS.get(domain)


def guess_hosts(email_or_domain: str) -> list[str]:
    """Candidate IMAP hosts for an unknown provider, most likely first."""
    d = email_or_domain.lower().split("@")[-1]
    return [f"imap.{d}", f"mail.{d}", f"imap.{d.split('.', 1)[-1]}" if '.' in d else d]
