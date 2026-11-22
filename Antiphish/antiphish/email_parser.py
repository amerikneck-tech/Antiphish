"""Parse real .eml files (stdlib only) into the dict format detector expects."""
from __future__ import annotations

import email
import email.policy
import re
from email.header import decode_header, make_header


def _decode(s: str | None) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    import html as h
    return re.sub(r"\s+", " ", h.unescape(html)).strip()


def parse_eml(path: str) -> dict:
    """Parse an .eml file -> email dict ready for analyze_email()."""
    with open(path, "rb") as f:
        raw = f.read()
    return parse_message(message_from_bytes_robust(raw))


def message_from_bytes_robust(raw: bytes):
    """Parse raw email bytes, repairing broken line endings first.

    .eml files saved by Windows tools in text mode often contain '\r\r\n'
    (CRLF converted to CR+CRLF), which breaks MIME boundaries so attachments
    disappear - exactly what an attacker would like. Normalize to CRLF.
    """
    while b"\r\r\n" in raw:
        raw = raw.replace(b"\r\r\n", b"\r\n")
    return email.message_from_bytes(raw, policy=email.policy.default)


def parse_message(msg) -> dict:
    """Parse an email.message.Message -> email dict for analyze_email()."""

    subject = _decode(msg.get("Subject"))
    sender = _decode(msg.get("From"))
    reply_to = _decode(msg.get("Reply-To")) or None

    # Authentication results (common headers)
    auth = (msg.get("Authentication-Results") or "").lower()
    def auth_status(key):
        m = re.search(rf"\b{key}\s*=\s*(\w+)", auth)
        return m.group(1) if m else None

    m = re.search(r"header\.from\s*=\s*([\w.-]+)", auth)
    dmarc_from = m.group(1) if m else None
    dkim_domains = re.findall(r"dkim\s*=\s*pass[^;]*?header\.(?:d|i)\s*=\s*@?([\w.-]+)", auth)
    list_unsub = bool(msg.get("List-Unsubscribe"))

    spf = auth_status("spf")
    dkim = auth_status("dkim")
    dmarc = auth_status("dmarc")

    bodies, attachments, payloads = [], [], {}
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            cdisp = (part.get_content_disposition() or "").lower()
            fname = part.get_filename()
            ctype = part.get_content_type()
            # attachment = explicit disposition, OR any named non-text part
            # (attackers often mark payloads as "inline" to dodge scanners)
            is_att = cdisp == "attachment" or (
                fname and ctype not in ("text/plain", "text/html")) or ctype == "message/rfc822"
            if is_att:
                fname = fname or ("attached.eml" if ctype == "message/rfc822" else "unnamed")
                base, n = fname, 2
                while fname in payloads:          # keep duplicates apart
                    fname = f"{base} ({n})"; n += 1
                attachments.append(fname)
                try:
                    if ctype == "message/rfc822":
                        inner = part.get_payload()
                        inner = inner[0] if isinstance(inner, list) else inner
                        payloads[fname] = inner.as_bytes()
                    else:
                        payloads[fname] = part.get_payload(decode=True) or b""
                except Exception:
                    pass
            elif ctype == "text/plain":
                try: bodies.append(part.get_content())
                except Exception: pass
            elif ctype == "text/html":
                try: bodies.append(_html_to_text(part.get_content()))
                except Exception: pass
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            bodies.append(_html_to_text(msg.get_content()))
        else:
            bodies.append(msg.get_content())

    return {
        "subject": subject,
        "body": "\n".join(bodies),
        "sender": sender,
        "reply_to": reply_to,
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "dmarc_from": dmarc_from,
        "dkim_domains": dkim_domains,
        "list_unsubscribe": list_unsub,
        "attachments": attachments,
        "attachment_data": payloads,
        "headers_raw": {k: _decode(v) for k, v in msg.items()},
    }
