"""Password hashing (scrypt, stdlib), CSRF tokens, URL defanging."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (_N, _R, _P, base64.b64encode(salt).decode(),
                                       base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n),
                              r=int(r), p=int(p), dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


# a dummy hash so unknown-user logins take as long as real ones (no user enumeration)
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str) -> str | None:
    if len(password or "") < 10:
        return "Lozinka mora imati najmanje 10 znakova."
    return None


def new_csrf() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(session_token: str | None, form_token: str | None) -> bool:
    return bool(session_token and form_token and hmac.compare_digest(session_token, form_token))


def defang(text: str) -> str:
    """Make URLs/domains non-clickable for display: http -> hxxp, '.' -> '[.]' in hosts."""
    if not text:
        return text
    def _url(m):
        u = m.group(0)
        u = re.sub(r"^http", "hxxp", u, flags=re.I)
        scheme, sep, rest = u.partition("://")
        if sep:
            host, slash, path = rest.partition("/")
            return f"{scheme}://{host.replace('.', '[.]')}{slash}{path}"
        return u
    return re.sub(r"https?://[^\s<>\"')\]]+", _url, text, flags=re.I)


_BARE_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)


def defang_all(text: str) -> str:
    """For PLAIN-TEXT e-mail reports: mail clients auto-link bare domains
    ('paypa1-secure.tk'), so defang those too, not only http(s) URLs."""
    if not text:
        return text
    text = defang(text)
    return _BARE_DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]"), text)
