"""Heuristic signal extraction for phishing detection.

Every check returns a (signal_name, weight, hit: bool, detail) tuple family
that feeds into the weighted scorer in scorer.py.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".click",
    ".link", ".live", ".cam", ".rest", ".icu", ".buzz",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

TRUSTED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "dhl",
    "fedex", "usps", "dropbox", "facebook", "instagram", "whatsapp",
    "linkedin", "adobe", "steam", "binance", "revolut", "nordea",
    "swedbank", "handelsbanken", "seb", "skatteverket", "försäkringskassan",
]

CREDENTIAL_WORDS = ["login", "logga", "signin", "sign in", "verify", "verifiera",
                    "account", "konto", "password", "lösenord", "credential", "confirm", "bekräfta"]


def domain_of(url: str) -> str:
    try:
        if "://" not in url:
            url = "http://" + url
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", text)


def check_url(url: str) -> list[dict]:
    """Return list of hit signals for a single URL."""
    signals = []
    raw = url.strip().lower()
    if raw.startswith("www."):
        raw = "http://" + raw
    elif "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return signals

    host = parsed.netloc.lower()
    bare_host = host.split(":")[0]

    def add(name, weight, detail):
        signals.append({"signal": name, "weight": weight, "detail": detail})

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", bare_host):
        add("url_ip_host", 25, f"URL uses a raw IP address instead of a domain: {bare_host}")
    if bare_host.count(".") >= 3:
        add("url_many_subdomains", 8, f"Many subdomains: {bare_host}")
    # real trick: https://paypal.com@evil.tk  ('@' before the host). An address
    # inside a tracking-link PATH (.../click/user@mail.com) is normal.
    if "@" in parsed.netloc:
        add("url_at_symbol", 20, "URL contains @ symbol (hides the real destination)")
    if host.split(".")[-1] == "ly" or any(bare_host.endswith(s) for s in SHORTENERS):
        add("url_shortener", 10, f"URL shortener: {bare_host}")
    tld_hit = next((t for t in SUSPICIOUS_TLDS if bare_host.endswith(t)), None)
    if tld_hit:
        add("url_suspicious_tld", 12, f"Suspicious TLD {tld_hit}: {bare_host}")
    if parsed.scheme == "http":
        add("url_no_https", 8, "Plain HTTP instead of HTTPS")
    if len(url) > 90:
        add("url_very_long", 5, f"Unusually long URL ({len(url)} characters)")
    if "xn--" in bare_host:
        add("url_punycode", 20, "Punycode (homograph attack): " + bare_host)
    m = re.search(r"([a-z0-9-]+)\.[a-z]{2,}$", bare_host)
    if m and bare_host.count("-") >= 2:
        add("url_many_dashes", 8, f"Multiple dashes in domain: {bare_host}")

    # Brand spoofing: brand word present but not on official domain
    for brand in TRUSTED_BRANDS:
        if brand in bare_host.replace("-", "").replace(".", ""):
            official = brand in ("skatteverket", "försäkringskassan") and bare_host.endswith(".se")
            if brand not in bare_host or not official and not bare_host.endswith(f".{brand}.com") and f"{brand}." not in bare_host:
                add("url_brand_spoof", 30, f"Brand '{brand}' in a suspicious domain: {bare_host}")
                break
    return signals


def _extract_addr(header_value: str) -> str:
    """Pull the bare email address out of 'Name <addr@dom.com>' or 'addr@dom'."""
    m = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", header_value or "")
    return m.group(0).lower() if m else ""


def check_sender(sender: str, reply_to: str | None = None) -> list[dict]:
    """Sender / header heuristics."""
    signals = []
    s = (sender or "").lower()

    def add(name, weight, detail):
        signals.append({"signal": name, "weight": weight, "detail": detail})

    if re.search(r"\b(urgent|hitno|akut)\b", s):
        add("sender_urgent_word", 10, "Word 'urgent' in sender display name")
    if any(w in s for w in ("noreply", "no-reply", "support", "security", "alert", "billing")):
        add("sender_generic_role", 4, "Generic role address instead of a person")
    if re.search(r"[а-яА-Я]", s):
        add("sender_mixed_alphabet", 15, "Mixed alphabets in sender address (spoofing)")

    if reply_to and sender:
        # compare organisations, not hosts: emails.perfume.com == perfume.com
        sd = registrable_domain(_extract_addr(sender))
        rd = registrable_domain(_extract_addr(reply_to))
        if sd and rd and sd != rd:
            add("reply_to_mismatch", 18, f"Reply-To domain ({rd}) differs from From domain ({sd})")
    return signals


def check_auth(spf: str | None, dkim: str | None, dmarc: str | None) -> list[dict]:
    """Authentication results (values like 'pass'/'fail'/'none')."""
    signals = []
    def add(name, weight, detail):
        signals.append({"signal": name, "weight": weight, "detail": detail})

    if all(v and v.lower() == "pass" for v in (spf, dkim, dmarc)):
        add("auth_all_pass", -15,
            "SPF, DKIM and DMARC all passed - strong sign of a legitimate sender")

    for name, val in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc)):
        if val and val.lower() == "fail":
            add(f"auth_{name}_fail", 30 if name == "dmarc" else 22,
                f"{name.upper()} authentication failed")
        elif val and val.lower() in ("none", "neutral"):
            add(f"auth_{name}_missing", 8, f"{name.upper()} not configured")
    return signals


def check_display_name(sender: str) -> list[dict]:
    """'PayPal Support <paypal@gmail.com>' style spoofing."""
    import re as _re
    signals = []
    m = _re.match(r"^(.*?)\s*<([^>]+)>", sender or "")
    if not m:
        return signals
    display, addr = m.group(1).lower(), m.group(2).lower()
    from .config import FREEMAIL_DOMAINS
    from urllib.parse import urlparse
    domain = addr.split("@")[-1]
    for brand in TRUSTED_BRANDS:
        if brand in display and brand not in domain:
            if domain in FREEMAIL_DOMAINS or not domain.endswith(".se") and "." in domain:
                signals.append({"signal": "sender_displayname_spoof", "weight": 28,
                                "detail": f"Display name '{display.strip()}' claims a brand but address is {addr}"})
                break
    return signals


def check_freemail_sender(sender: str, claimed_role: str | None = None) -> list[dict]:
    """Freemail domain used where a corporate sender is expected."""
    from .config import FREEMAIL_DOMAINS
    signals = []
    addr = (sender or "").lower()
    if "@" in addr:
        domain = addr.split("@")[-1]
        if domain in FREEMAIL_DOMAINS and claimed_role in ("it", "billing", "ceo", "support"):
            signals.append({"signal": "sender_freemail_role", "weight": 20,
                            "detail": f"{claimed_role} mail sent from freemail domain {domain}"})
    return signals


def check_attachments(attachments: list[str]) -> list[dict]:
    """Dangerous attachment types."""
    signals = []
    risky_ext = (".html", ".htm", ".exe", ".scr", ".js", ".vbs", ".iso", ".zip",
                 ".rar", ".7z", ".docm", ".xlsm")
    risky_names = ("invoice", "faktura", "payment", "scan", "dokument", "document",
                   "remittance", "shipment")
    for name in attachments or []:
        n = name.lower()
        if n.endswith(risky_ext):
            w = 20
            detail = f"Potentially dangerous attachment type: {name}"
            if any(k in n for k in risky_names):
                w = 28
                detail = f"Risky attachment with bait name: {name}"
            signals.append({"signal": "attachment_risky", "weight": w, "detail": detail})
    return signals


_MULTI_TLD_SECOND = {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}


def registrable_domain(host_or_addr: str) -> str:
    """Approximate eTLD+1: mail.footshop.eu -> footshop.eu, reply.ebay.co.uk -> ebay.co.uk."""
    h = (host_or_addr or "").lower().strip().split("@")[-1].split(":")[0].strip(".>")
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in _MULTI_TLD_SECOND and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# weak URL signals: normal for newsletters / tracking links
WEAK_URL_SIGNALS = {"url_many_subdomains", "url_very_long", "url_no_https", "url_many_dashes"}


def check_urls_aggregated(urls: list[str], sender: str = "") -> list[dict]:
    """Check all URLs but count each signal type ONCE.

    A newsletter with 40 tracking links must not score 40x 'long URL'.
    Weak signals on links that belong to the sender's own domain are ignored.
    """
    sender_dom = registrable_domain(_extract_addr(sender)) if sender else ""
    best: dict[str, dict] = {}
    counts: dict[str, int] = {}
    for u in urls:
        url_dom = registrable_domain(domain_of(u))
        same_org = bool(sender_dom) and url_dom == sender_dom
        for sig in check_url(u):
            if same_org and sig["signal"] in WEAK_URL_SIGNALS:
                continue
            name = sig["signal"]
            counts[name] = counts.get(name, 0) + 1
            if name not in best or sig["weight"] > best[name]["weight"]:
                best[name] = dict(sig)
    out = []
    for name, sig in best.items():
        if counts[name] > 1:
            sig["detail"] += f" (+{counts[name] - 1} more link(s))"
        out.append(sig)
    return out
