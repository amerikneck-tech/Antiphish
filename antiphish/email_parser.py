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
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    return parse_message(msg)


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

    spf = auth_status("spf")
    dkim = auth_status("dkim")
    dmarc = auth_status("dmarc")

    bodies, attachments, payloads = [], [], {}
    if msg.is_multipart():
        for part in msg.walk():
            cdisp = (part.get_content_disposition() or "").lower()
            if cdisp == "attachment":
                fname = part.get_filename() or "unnamed"
                attachments.append(fname)
                try:
                    payloads[fname] = part.get_payload(decode=True) or b""
                except Exception:
                    pass
            elif part.get_content_type() == "text/plain":
                bodies.append(part.get_content())
            elif part.get_content_type() == "text/html":
                bodies.append(_html_to_text(part.get_content()))
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
        "attachments": attachments,
        "attachment_data": payloads,
        "headers_raw": {k: _decode(v) for k, v in msg.items()},
    }
