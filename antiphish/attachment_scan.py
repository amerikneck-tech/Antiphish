"""Attachment content scanning: PDF text + embedded URLs + VirusTotal hash check.

Levels:
  1. filename/type heuristics (already in checks.py)
  2. PDF: extract text -> phishing heuristics + ML probability
  3. any attachment: extract URLs from raw bytes -> URL heuristics
  4. SHA256 -> VirusTotal file reputation (hash lookup only, no upload)

Everything degrades gracefully (no pypdf / no VT key / unsupported type).
"""
from __future__ import annotations

import hashlib
import re

from .checks import check_url, extract_urls
from .config import VIRUSTOTAL_API_KEY

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 10 MB cap


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_pdf_text(data: bytes) -> str:
    """Best-effort PDF text extraction. Falls back to raw byte scan."""
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages[:20])
    except Exception:
        # fallback: PDFs often carry plaintext streams - scan raw bytes for URLs/text
        try:
            raw = data.decode("latin-1", errors="ignore")
            raw = re.sub(r"[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]", " ", raw)
            return re.sub(r"\s+", " ", raw)
        except Exception:
            return ""


def vt_file_report(file_hash: str, timeout: int = 10) -> dict | None:
    """VirusTotal hash lookup (no upload). None if unavailable/unknown."""
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        import requests
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=timeout)
        if r.status_code == 404:
            return {"seen": False}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"seen": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "name": r.json()["data"]["attributes"].get("meaningful_name", "")}
    except Exception:
        return None


def scan_attachment(filename: str, data: bytes, model=None) -> list[dict]:
    """Full attachment analysis -> detector signals."""
    signals = []
    name = (filename or "unnamed").lower()

    def add(sig, w, detail):
        signals.append({"signal": sig, "weight": w, "detail": detail})

    if not data or len(data) > MAX_ATTACHMENT_BYTES:
        if len(data or b"") > MAX_ATTACHMENT_BYTES:
            add("attachment_too_large", 5, f"Attachment over 10MB, content not scanned: {filename}")
        return signals

    is_pdf = name.endswith(".pdf") or data[:5] == b"%PDF-"

    # --- VirusTotal hash reputation (any file type) ---
    rep = vt_file_report(sha256(data))
    if rep and rep.get("seen"):
        if rep.get("malicious", 0) >= 3:
            add("attachment_vt_malicious", 50,
                f"VirusTotal: {rep['malicious']} engines flag this file ({filename})")
        elif rep.get("malicious", 0) >= 1:
            add("attachment_vt_flagged", 35,
                f"VirusTotal: {rep['malicious']} engine(s) flag this file ({filename})")
        elif rep.get("suspicious", 0) >= 3:
            add("attachment_vt_suspicious", 12,
                f"VirusTotal: {rep['suspicious']} engines suspicious ({filename})")

    # --- PDF content analysis ---
    text = extract_pdf_text(data) if is_pdf else ""
    if text:
        from .features import analyze_text
        hits = analyze_text(text)
        real_hits = [h for h in hits if h["weight"] >= 10]
        if len(real_hits) >= 2:
            add("pdf_phishing_content", 20,
                f"PDF contains {len(real_hits)} phishing patterns: "
                + "; ".join(h["signal"] for h in real_hits[:3]))
        elif real_hits:
            add("pdf_phishing_content", 10,
                f"PDF contains a phishing pattern: {real_hits[0]['signal']}")
        if model is not None and len(text) > 80:
            prob = float(model.predict_proba([text[:3000]])[0][1])
            if prob >= 0.7:
                add("pdf_ml_phishing", int(15 * prob),
                    f"ML flags PDF text as phishing ({prob:.0%})")

    # --- URLs inside the file (PDF or HTML attachments) ---
    scan_text = text if text else re.sub(r"[^\x20-\x7e]", " ", data[:200000].decode("latin-1", errors="ignore"))
    for url in extract_urls(scan_text)[:5]:
        for sig in check_url(url):
            signals.append({**sig, "weight": min(sig["weight"], 25),
                            "detail": f"[in {filename}] {sig['detail']}"})
    return signals
