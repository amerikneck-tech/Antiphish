"""Deep attachment scanning: archives, Office docs, PDF, HTML/SVG, calendar
invites, images (QR codes) and executables.

Design rules
------------
* NOTHING is ever executed and NOTHING is written to disk - archives are
  opened in memory only (no path-traversal risk).
* Hard limits against zip bombs / recursion: depth, file count, total
  decompressed bytes, compression ratio.
* File type is detected from magic bytes, not trusted from the extension
  (catches "invoice.pdf" that is really an .exe).
* Optional libraries degrade gracefully:
    pypdf        - better PDF text extraction
    py7zr        - .7z archives
    rarfile      - .rar archives (needs unrar/bsdtar on the system)
    opencv-python- QR code decoding in images
    oletools     - VBA macro extraction from legacy .doc/.xls

Public API (backward compatible):
    scan_attachment(filename, data, model=None, passwords=None) -> signals
    analyze_attachment(filename, data, model=None, passwords=None)
        -> (signals, findings)   findings = human-readable lines for the LLM
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile

from .checks import check_url, extract_urls
from .config import VIRUSTOTAL_API_KEY

# ---------------------------------------------------------------- limits
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024      # top-level attachment cap
MAX_MEMBER_BYTES = 20 * 1024 * 1024          # single file inside an archive
MAX_TOTAL_UNPACKED = 50 * 1024 * 1024        # all files of one attachment
MAX_MEMBERS = 100                            # files inspected per attachment
MAX_DEPTH = 3                                # archive-in-archive nesting
MAX_RATIO = 100                              # compression ratio -> zip bomb
MAX_URLS_PER_FILE = 5

EXECUTABLE_EXT = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
                  ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi",
                  ".dll", ".cpl", ".jar", ".reg", ".url", ".appx", ".msix")
DISK_IMAGE_EXT = (".iso", ".img", ".vhd", ".vhdx")
MACRO_EXT = (".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb")
DOC_LIKE_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg",
                ".png", ".jpeg", ".rtf", ".csv")

# common archive passwords placed in phishing mails
_COMMON_PASSWORDS = ["infected", "1234", "12345", "123456", "password", "invoice"]


# ---------------------------------------------------------------- helpers
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_type(data: bytes, name: str = "") -> str:
    """Real file type from magic bytes (falls back to extension)."""
    n = name.lower()
    h = data[:8]
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"  # refined to ooxml later
    if h.startswith(b"%PDF"):
        return "pdf"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"MZ"):
        return "exe"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"  # legacy .doc/.xls/.msg/.msi
    if h.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if h.startswith(b"{\\rtf"):
        return "rtf"
    if h.startswith(b"\x89PNG") or h.startswith(b"\xff\xd8\xff") or h[:4] in (b"GIF8",) \
            or h.startswith(b"BM"):
        return "image"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:2048].decode("latin-1", errors="ignore").lower()
    if "begin:vcalendar" in head:
        return "ics"
    if "<svg" in head:
        return "svg"
    if "<html" in head or "<!doctype html" in head or "<script" in head or "<form" in head:
        return "html"
    # extension fallback
    for ext, t in ((".html", "html"), (".htm", "html"), (".shtml", "html"),
                   (".svg", "svg"), (".ics", "ics"), (".eml", "eml"),
                   (".txt", "text"), (".csv", "text")):
        if n.endswith(ext):
            return t
    if n.endswith(EXECUTABLE_EXT):
        return "script"
    return "unknown"


def _printable(data: bytes, limit: int = 300_000) -> str:
    s = data[:limit].decode("latin-1", errors="ignore")
    return re.sub(r"[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]", " ", s)


def extract_pdf_text(data: bytes) -> str:
    """Best-effort PDF text extraction. Falls back to raw byte scan."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:20])
        # link annotations are not in extract_text - add them from raw bytes
        uris = re.findall(rb"/URI\s*\(([^)]+)\)", data)
        return text + "\n" + " ".join(u.decode("latin-1", "ignore") for u in uris)
    except Exception:
        try:
            return re.sub(r"\s+", " ", _printable(data, len(data)))
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
        attrs = r.json()["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return {"seen": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "name": attrs.get("meaningful_name", "")}
    except Exception:
        return None


def passwords_from_text(text: str) -> list[str]:
    """Pull candidate archive passwords out of the email body
    ('password: 1234', 'lozinka je abc', 'lösenord: x')."""
    pats = re.findall(
        r"(?:password|passcode|pass|pwd|lozinka|šifra|sifra|lösenord|losenord|kennwort|code)"
        r"\s*(?:is|je|är|:|=|-)?\s*[:\-]?\s*[\"'“«]?([^\s\"'”»,;]{3,32})",
        text or "", flags=re.IGNORECASE)
    out = []
    for p in pats:
        p = p.strip(".")
        if p and p.lower() not in ("is", "je", "for", "the") and p not in out:
            out.append(p)
    return out[:10]


# ---------------------------------------------------------------- scanner
class _Scan:
    """State for one top-level attachment (limits are shared across nesting)."""

    def __init__(self, model=None, passwords=None):
        self.model = model
        self.passwords = list(passwords or []) + _COMMON_PASSWORDS
        self.signals: list[dict] = []
        self.findings: list[str] = []
        self.members = 0
        self.unpacked = 0
        self._seen_signals: set[tuple] = set()

    # -- recording
    def add(self, sig: str, weight: int, detail: str):
        key = (sig, detail)
        if key in self._seen_signals:
            return
        self._seen_signals.add(key)
        self.signals.append({"signal": sig, "weight": weight, "detail": detail})

    def note(self, line: str):
        if len(self.findings) < 60:
            self.findings.append(line)

    # -- dispatch
    def scan(self, path: str, data: bytes, depth: int = 0):
        name = path.split("/")[-1].lower()
        ftype = detect_type(data, name)
        if ftype == "zip" and self._is_ooxml(data):
            ftype = "ooxml"
        self.note(f"{path}: type={ftype}, {len(data)} bytes")

        self._check_name_vs_type(path, name, ftype)

        if depth > 0:  # top level VT is done by caller
            self._vt(path, data)

        handler = {
            "zip": self._zip, "7z": self._7z, "rar": self._rar, "gzip": self._gzip,
            "ooxml": self._ooxml, "ole": self._ole, "rtf": self._rtf,
            "pdf": self._pdf, "html": self._html, "svg": self._html,
            "ics": self._ics, "image": self._image, "eml": self._eml,
            "text": self._text,
        }.get(ftype)
        if handler is None and ftype in ("exe", "elf", "lnk", "script", "iso"):
            return  # already flagged by name/type check
        if handler is None:
            self._urls(path, _printable(data))
            return
        if handler in (self._zip, self._7z, self._rar, self._gzip):
            if depth >= MAX_DEPTH:
                self.add("archive_too_deep", 20,
                         f"Archive nested more than {MAX_DEPTH} levels deep: {path}")
                return
            handler(path, data, depth)
        else:
            handler(path, data)

    # -- generic checks
    def _check_name_vs_type(self, path, name, ftype):
        if ftype in ("exe", "elf") or name.endswith(EXECUTABLE_EXT) or ftype == "lnk":
            w = 45 if "/" in path else 40
            self.add("attachment_executable", w,
                     f"Executable/script file {'inside archive' if '/' in path else 'attached'}: {path}")
        if ftype == "iso" or name.endswith(DISK_IMAGE_EXT):
            self.add("attachment_disk_image", 30,
                     f"Disk image (used to bypass Mark-of-the-Web): {path}")
        # double extension: invoice.pdf.exe
        parts = name.split(".")
        if len(parts) >= 3 and "." + parts[-2] in DOC_LIKE_EXT and \
                ("." + parts[-1] in EXECUTABLE_EXT or ftype in ("exe", "script")):
            self.add("attachment_double_extension", 30,
                     f"Double extension hides real type: {path}")
        # extension lies about content
        if name.endswith(DOC_LIKE_EXT) and ftype in ("exe", "elf", "lnk"):
            self.add("attachment_type_mismatch", 40,
                     f"File named like a document is really {ftype}: {path}")
        if "\u202e" in name:
            self.add("attachment_rtlo_trick", 35,
                     f"Right-to-left override character in filename: {path!r}")

    def _vt(self, path, data):
        rep = vt_file_report(sha256(data))
        if rep and rep.get("seen"):
            if rep.get("malicious", 0) >= 3:
                self.add("attachment_vt_malicious", 50,
                         f"VirusTotal: {rep['malicious']} engines flag this file ({path})")
            elif rep.get("malicious", 0) >= 1:
                self.add("attachment_vt_flagged", 35,
                         f"VirusTotal: {rep['malicious']} engine(s) flag this file ({path})")
            elif rep.get("suspicious", 0) >= 3:
                self.add("attachment_vt_suspicious", 12,
                         f"VirusTotal: {rep['suspicious']} engines suspicious ({path})")

    def _urls(self, path, text):
        urls = extract_urls(text)
        if urls:
            self.note(f"{path}: URLs: " + ", ".join(urls[:MAX_URLS_PER_FILE]))
        for url in urls[:MAX_URLS_PER_FILE]:
            for sig in check_url(url):
                self.add(sig["signal"], min(sig["weight"], 25),
                         f"[in {path}] {sig['detail']}")

    def _content(self, path, text, label="file"):
        """Text phishing heuristics + ML on extracted document text."""
        if not text or len(text.strip()) < 20:
            return
        from .features import analyze_text
        excerpt = re.sub(r"\s+", " ", text)[:300]
        self.note(f"{path}: text excerpt: {excerpt}")
        hits = [h for h in analyze_text(text) if h["weight"] >= 10]
        sig = "pdf_phishing_content" if label == "PDF" else "attachment_phishing_content"
        if len(hits) >= 2:
            self.add(sig, 20, f"{label} {path} contains {len(hits)} phishing patterns: "
                     + "; ".join(h["signal"] for h in hits[:3]))
        elif hits:
            self.add(sig, 10, f"{label} {path} contains a phishing pattern: {hits[0]['signal']}")
        if self.model is not None and len(text) > 80:
            try:
                prob = float(self.model.predict_proba([text[:3000]])[0][1])
                if prob >= 0.7:
                    self.add("pdf_ml_phishing" if label == "PDF" else "attachment_ml_phishing",
                             int(15 * prob), f"ML flags {label} text in {path} as phishing ({prob:.0%})")
            except Exception:
                pass
        self._urls(path, text)

    # -- archives
    def _budget_ok(self, path, size, csize=None) -> bool:
        if self.members >= MAX_MEMBERS:
            self.add("archive_too_many_files", 10,
                     f"Archive has more than {MAX_MEMBERS} files, rest not scanned ({path})")
            return False
        if size > MAX_MEMBER_BYTES or self.unpacked + size > MAX_TOTAL_UNPACKED:
            self.add("archive_oversize", 15, f"Archive member too large to scan safely: {path}")
            return False
        if csize and size / max(csize, 1) > MAX_RATIO and size > 1_000_000:
            self.add("archive_zip_bomb", 40,
                     f"Extreme compression ratio ({size // max(csize, 1)}:1) - possible zip bomb: {path}")
            return False
        self.members += 1
        self.unpacked += size
        return True

    def _zip(self, path, data, depth):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as e:
            self.add("archive_corrupt", 10, f"Corrupt/unreadable ZIP {path}: {e}")
            return
        infos = [i for i in zf.infolist() if not i.is_dir()]
        self.note(f"{path}: ZIP with {len(infos)} file(s): "
                  + ", ".join(i.filename for i in infos[:15]))
        encrypted = any(i.flag_bits & 0x1 for i in infos)
        pwd = None
        if encrypted:
            pwd = self._find_zip_password(zf, infos)
            if pwd is None:
                self.add("archive_encrypted", 30,
                         f"Password-protected archive, content cannot be inspected "
                         f"(common malware filter-evasion trick): {path} "
                         f"[files: {', '.join(i.filename for i in infos[:5])}]")
            else:
                self.add("archive_encrypted_opened", 15,
                         f"Password-protected archive opened with password from email: {path}")
        for info in infos:
            member = f"{path}/{info.filename}"
            # check names even if we cannot read the content
            self._check_name_vs_type(member, info.filename.lower(), "unknown")
            if encrypted and pwd is None:
                continue
            if not self._budget_ok(member, info.file_size, info.compress_size):
                continue
            try:
                with zf.open(info, pwd=pwd) as f:
                    content = f.read(MAX_MEMBER_BYTES + 1)
            except Exception as e:
                self.note(f"{member}: could not read ({e})")
                continue
            self.scan(member, content, depth + 1)

    def _find_zip_password(self, zf, infos):
        target = next((i for i in infos if i.flag_bits & 0x1), None)
        if target is None:
            return None
        for p in self.passwords:
            try:
                with zf.open(target, pwd=p.encode()) as f:
                    f.read(1024)
                return p.encode()
            except Exception:
                continue
        return None

    def _7z(self, path, data, depth):
        try:
            import py7zr
        except ImportError:
            self.add("archive_unscanned", 12, f"7z archive not inspected (pip install py7zr): {path}")
            return
        archive = None
        for pwd in [None] + self.passwords:
            try:
                archive = py7zr.SevenZipFile(io.BytesIO(data), password=pwd)
                names = archive.getnames()
                if archive.needs_password() and pwd is None:
                    archive.close()
                    archive = None
                    continue
                files = archive.readall() or {}
                if pwd:
                    self.add("archive_encrypted_opened", 15,
                             f"Password-protected 7z opened with password from email: {path}")
                break
            except Exception:
                archive = None
                continue
        if archive is None:
            self.add("archive_encrypted", 30,
                     f"Password-protected/unreadable 7z archive, content not inspected: {path}")
            return
        self.note(f"{path}: 7z with {len(names)} file(s): " + ", ".join(names[:15]))
        for name, bio in files.items():
            content = bio.read(MAX_MEMBER_BYTES + 1)
            member = f"{path}/{name}"
            if self._budget_ok(member, len(content)):
                self.scan(member, content, depth + 1)

    def _rar(self, path, data, depth):
        try:
            import rarfile
            rf = rarfile.RarFile(io.BytesIO(data))
        except ImportError:
            self.add("archive_unscanned", 12, f"RAR archive not inspected (pip install rarfile): {path}")
            return
        except Exception as e:
            self.add("archive_corrupt", 10, f"Unreadable RAR {path}: {e}")
            return
        infos = [i for i in rf.infolist() if not i.is_dir()]
        self.note(f"{path}: RAR with {len(infos)} file(s): " + ", ".join(i.filename for i in infos[:15]))
        if rf.needs_password():
            pwd = None
            for p in self.passwords:
                try:
                    rf.setpassword(p)
                    rf.read(infos[0])
                    pwd = p
                    break
                except Exception:
                    continue
            if pwd is None:
                self.add("archive_encrypted", 30,
                         f"Password-protected RAR, content not inspected: {path}")
                for i in infos:
                    self._check_name_vs_type(f"{path}/{i.filename}", i.filename.lower(), "unknown")
                return
        for info in infos:
            member = f"{path}/{info.filename}"
            if not self._budget_ok(member, info.file_size, info.compress_size):
                continue
            try:
                self.scan(member, rf.read(info), depth + 1)
            except Exception as e:
                self.note(f"{member}: could not read ({e}) - unrar tool installed?")

    def _gzip(self, path, data, depth):
        import gzip
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                content = g.read(MAX_MEMBER_BYTES + 1)
        except Exception:
            return
        inner_name = re.sub(r"\.(gz|tgz)$", "", path.split("/")[-1])
        member = f"{path}/{inner_name}"
        if self._budget_ok(member, len(content), len(data)):
            if content[257:262] == b"ustar":
                self._tar(member, content, depth + 1)
            else:
                self.scan(member, content, depth + 1)

    def _tar(self, path, data, depth):
        import tarfile
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data))
        except Exception:
            return
        for m in tf.getmembers()[:MAX_MEMBERS]:
            if not m.isfile():
                continue
            member = f"{path}/{m.name}"
            if self._budget_ok(member, m.size):
                f = tf.extractfile(m)
                if f:
                    self.scan(member, f.read(MAX_MEMBER_BYTES + 1), depth + 1)

    # -- Office
    @staticmethod
    def _is_ooxml(data: bytes) -> bool:
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
            return "[Content_Types].xml" in names
        except Exception:
            return False

    def _ooxml(self, path, data):
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            self.add("office_macro", 35, f"Office document contains VBA macros: {path}")
        if any("activex" in n.lower() for n in names):
            self.add("office_activex", 15, f"Office document contains ActiveX controls: {path}")
        if any(n.lower().endswith((".bin", ".exe")) and "embeddings" in n.lower() for n in names):
            self.add("office_embedded_object", 20, f"Office document has embedded OLE objects: {path}")
        text_parts = []
        for n in names:
            low = n.lower()
            if not low.endswith((".xml", ".rels")):
                continue
            try:
                xml = zf.read(n)[:2_000_000].decode("utf-8", errors="ignore")
            except Exception:
                continue
            if low.endswith(".rels"):
                # remote template injection / external links
                for tgt in re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', xml):
                    if re.search(r"attachedTemplate|oleObject|frame", xml) and tgt.startswith(("http", "\\\\")):
                        self.add("office_remote_template", 35,
                                 f"Office doc loads remote template/object (template injection): {tgt[:80]}")
                    text_parts.append(tgt)
            elif any(k in low for k in ("document.xml", "sharedstrings", "slide", "sheet",
                                        "header", "footer")):
                if "ddeauto" in xml.lower() or "\\dde" in xml.lower():
                    self.add("office_dde", 30, f"DDE field (command execution) in {path}")
                text_parts.append(re.sub(r"<[^>]+>", " ", xml))
        self._content(path, " ".join(text_parts), "Office document")

    def _ole(self, path, data):
        found_macro = False
        try:
            from oletools.olevba import VBA_Parser
            vp = VBA_Parser(path.split("/")[-1], data=data)
            if vp.detect_vba_macros():
                found_macro = True
                kinds = {kw for (t, kw, _d) in vp.analyze_macros() if t in ("AutoExec", "Suspicious")}
                self.add("office_macro", 40 if kinds else 30,
                         f"Legacy Office file with VBA macros in {path}"
                         + (f" (suspicious: {', '.join(sorted(kinds)[:5])})" if kinds else ""))
            vp.close()
        except ImportError:
            pass
        except Exception:
            pass
        if not found_macro and (b"VBA" in data and (b"_VBA_PROJECT" in data or b"Attribute VB_" in data)):
            self.add("office_macro", 30, f"Legacy Office file appears to contain VBA macros: {path}")
        self._content(path, _printable(data), "Office document")

    def _rtf(self, path, data):
        low = data[:2_000_000].lower()
        if b"\\objdata" in low or b"\\object" in low:
            self.add("rtf_embedded_object", 25, f"RTF with embedded object (exploit vector): {path}")
        self._urls(path, _printable(data))

    # -- PDF
    def _pdf(self, path, data):
        raw = data[:5_000_000]
        risky = []
        for marker, label in ((b"/JavaScript", "JavaScript"), (b"/JS", "JavaScript"),
                              (b"/Launch", "Launch action"), (b"/EmbeddedFile", "embedded file"),
                              (b"/OpenAction", "auto-open action"), (b"/AcroForm", "form"),
                              (b"/XFA", "XFA form"), (b"/SubmitForm", "form submit")):
            if marker in raw and label not in risky:
                risky.append(label)
        dangerous = [r for r in risky if r in ("JavaScript", "Launch action", "embedded file")]
        if dangerous:
            self.add("pdf_active_content", 25 if "Launch action" in dangerous else 18,
                     f"PDF {path} contains {', '.join(dangerous)}")
        text = extract_pdf_text(data)
        self._content(path, text, "PDF")
        self._qr_in_pdf(path, data)

    def _qr_in_pdf(self, path, data):
        """Render first pages and look for QR codes (needs pypdfium2 + opencv)."""
        try:
            import pypdfium2 as pdfium
        except ImportError:
            return
        try:
            pdf = pdfium.PdfDocument(data)
            for i in range(min(len(pdf), 3)):
                img = pdf[i].render(scale=2).to_pil()
                for url in _decode_qr_pil(img):
                    self._qr_hit(f"{path} (page {i + 1})", url)
        except Exception:
            pass

    # -- HTML / SVG (HTML smuggling, fake login pages)
    def _html(self, path, data):
        src = data[:3_000_000].decode("utf-8", errors="ignore")
        low = src.lower()
        is_svg = "<svg" in low[:4096]
        if re.search(r'<input[^>]+type\s*=\s*["\']?password', low):
            self.add("html_credential_form", 35, f"Attachment {path} contains a password login form")
        elif "<form" in low and re.search(r'action\s*=\s*["\']?https?://', low):
            self.add("html_external_form", 20, f"Attachment {path} posts a form to an external site")
        if "<script" in low:
            w = 25 if is_svg else 12
            self.add("svg_script" if is_svg else "html_script", w,
                     f"{'SVG image' if is_svg else 'HTML file'} {path} contains JavaScript")
        smuggle = [k for k in ("atob(", "fromcharcode", "unescape(", "msSaveOrOpenBlob".lower(),
                               "new blob(", "createobjecturl", "eval(") if k in low]
        if len(smuggle) >= 2 or ("new blob(" in low and "download" in low):
            self.add("html_smuggling", 35,
                     f"HTML smuggling / obfuscated JS in {path}: {', '.join(smuggle[:4])}")
        if re.search(r"(window|document|top)\.location(\.href)?\s*=|location\.replace\(|"
                     r"http-equiv\s*=\s*[\"']?refresh", low):
            self.add("html_redirect", 15, f"{path} automatically redirects the browser")
        if re.search(r"[A-Za-z0-9+/]{2000,}={0,2}", src):
            self.add("html_large_base64", 12, f"{path} contains a large base64 blob (hidden payload)")
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", src)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        import html as h
        self._content(path, h.unescape(text), "SVG" if is_svg else "HTML")
        self._urls(path, " ".join(re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)', src)))

    # -- calendar invites
    def _ics(self, path, data):
        txt = data[:1_000_000].decode("utf-8", errors="ignore")
        txt = re.sub(r"\r?\n[ \t]", "", txt)  # unfold lines
        urls = extract_urls(txt)
        if urls:
            self.add("calendar_invite_links", 10,
                     f"Calendar invite {path} contains {len(urls)} link(s)")
        self._content(path, txt, "Calendar invite")

    # -- images (QR phishing)
    def _image(self, path, data):
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.load()
        except Exception:
            return
        for url in _decode_qr_pil(img):
            self._qr_hit(path, url)

    def _qr_hit(self, where, payload):
        self.note(f"{where}: QR code -> {payload[:150]}")
        if re.match(r"(?i)https?://|www\.", payload):
            self.add("qr_code_url", 20, f"QR code with link in {where}: {payload[:80]}")
            for sig in check_url(payload):
                self.add(sig["signal"], min(sig["weight"], 25), f"[QR in {where}] {sig['detail']}")

    # -- attached emails / text
    def _eml(self, path, data):
        import email as email_mod
        import email.policy
        try:
            msg = email_mod.message_from_bytes(data, policy=email.policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            text = body.get_content() if body else ""
            self.note(f"{path}: attached email, subject={msg.get('Subject', '')!r}")
            self._content(path, f"{msg.get('Subject', '')} {text}", "Attached email")
            for part in msg.iter_attachments():
                self.scan(f"{path}/{part.get_filename() or 'unnamed'}",
                          part.get_payload(decode=True) or b"", 1)
        except Exception:
            self._urls(path, _printable(data))

    def _text(self, path, data):
        self._content(path, data[:500_000].decode("utf-8", errors="ignore"), "Text file")


def _decode_qr_pil(img) -> list[str]:
    """Decode QR codes from a PIL image (opencv, then pyzbar). [] if unavailable."""
    out = []
    import warnings
    warnings.filterwarnings("ignore", module="PIL")
    try:
        import numpy as np
        import cv2
        arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)
        det = cv2.QRCodeDetector()
        try:
            ok, decoded, _pts, _ = det.detectAndDecodeMulti(arr)
            if ok:
                out += [d for d in decoded if d]
        except Exception:
            pass
        if not out:
            d, _pts, _ = det.detectAndDecode(arr)
            if d:
                out.append(d)
    except Exception:
        pass
    if not out:
        try:
            from pyzbar.pyzbar import decode
            out += [r.data.decode("utf-8", "ignore") for r in decode(img)]
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- public API
def analyze_attachment(filename: str, data: bytes, model=None,
                       passwords: list[str] | None = None) -> tuple[list[dict], list[str]]:
    """Full recursive analysis -> (signals, findings for the LLM)."""
    name = filename or "unnamed"
    s = _Scan(model=model, passwords=passwords)
    if not data:
        return [], []
    if len(data) > MAX_ATTACHMENT_BYTES:
        s.add("attachment_too_large", 5, f"Attachment over 10MB, content not scanned: {name}")
        s._check_name_vs_type(name, name.lower(), detect_type(data[:70000], name))
        return s.signals, s.findings
    s._vt(name, data)
    try:
        s.scan(name, data, 0)
    except Exception as e:  # never let a malformed file crash the monitor
        s.add("attachment_scan_error", 8, f"Attachment {name} could not be fully analyzed: {e}")
    return s.signals, s.findings


def scan_attachment(filename: str, data: bytes, model=None,
                    passwords: list[str] | None = None) -> list[dict]:
    """Backward-compatible: signals only."""
    return analyze_attachment(filename, data, model=model, passwords=passwords)[0]


# ---------------------------------------------------------------- isolation
# Malicious files are crafted to hang or crash parsers (pypdf, zip, XML...).
# Scanning runs in a separate worker process with a hard timeout and (on
# Linux/macOS) a memory cap. A hang/crash kills only the worker, never the
# monitor - and the attachment is reported as suspicious.
import concurrent.futures as _cf
import logging as _logging
import os as _os

ATTACHMENT_TIMEOUT = int(_os.getenv("ATTACHMENT_TIMEOUT", "30"))     # seconds per attachment
WORKER_MEMORY_MB = int(_os.getenv("ATTACHMENT_WORKER_MEMORY_MB", "2048"))
WORKERS = int(_os.getenv("ATTACHMENT_WORKERS", "1"))
_pool = None
import threading as _threading
_pool_lock = _threading.RLock()
_log = _logging.getLogger("antiphish.attachments")


def _worker_init():
    # single-threaded math libs: less RAM / virtual memory, predictable on small VPS
    for var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        _os.environ.setdefault(var, "1")
    # Ctrl+C is handled by the main process; the worker must not print a traceback
    try:
        import signal
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass
    import warnings
    warnings.filterwarnings("ignore")
    try:
        import resource  # not available on Windows
        lim = WORKER_MEMORY_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
    except Exception:
        pass


def _worker_scan(filename, data, passwords, use_model):
    model = None
    if use_model:
        try:
            from .detector import _get_model
            model = _get_model()
        except Exception:
            model = None
    return analyze_attachment(filename, data, model=model, passwords=passwords)


def _get_pool():
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = _cf.ProcessPoolExecutor(max_workers=WORKERS, initializer=_worker_init)
        return _pool


def shutdown_sandbox():
    """Stop the worker cleanly (call on program exit)."""
    _reset_pool()


def _reset_pool():
    global _pool
    with _pool_lock:
        _reset_pool_locked()


def _reset_pool_locked():
    global _pool
    if _pool is not None:
        for p in list(getattr(_pool, "_processes", {}).values()):
            try:
                p.kill()
            except Exception:
                pass
        try:
            _pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
    _pool = None


def _sandbox_healthy() -> bool:
    """Can a worker process run a trivial job at all?"""
    try:
        ok = _get_pool().submit(int, "1").result(timeout=60) == 1
    except Exception:
        ok = False
    if not ok:
        _reset_pool()
    return ok


def _hang_for_test(*_a):
    """Simulates a parser hang (used by tests; importable in spawned workers)."""
    import time
    time.sleep(120)


def analyze_attachment_isolated(filename: str, data: bytes, passwords=None,
                                use_model: bool = True, timeout: int | None = None,
                                _fn=None) -> tuple[list[dict], list[str]]:
    """analyze_attachment() in a sandboxed worker process with a hard timeout."""
    timeout = timeout or ATTACHMENT_TIMEOUT
    try:
        fut = _get_pool().submit(_fn or _worker_scan, filename, data, passwords, use_model)
    except Exception as e:  # pool cannot start (restricted env) -> in-process fallback
        _log.warning("Sandbox unavailable (%s) - scanning in-process", e)
        return analyze_attachment(filename, data, passwords=passwords)
    try:
        return fut.result(timeout=timeout)
    except _cf.TimeoutError:
        _reset_pool()
        return ([{"signal": "attachment_scan_timeout", "weight": 25,
                  "detail": f"Scanning {filename} exceeded {timeout}s and was aborted "
                            f"(files crafted to hang scanners are a red flag)"}],
                [f"{filename}: scan aborted after {timeout}s"])
    except Exception as e:  # worker crashed (memory cap / parser crash)
        _reset_pool()
        if not _sandbox_healthy():
            # the sandbox itself is broken on this machine - don't blame the file
            _log.warning("Sandbox worker cannot run here - falling back to in-process scanning")
            return analyze_attachment(filename, data, passwords=passwords)
        return ([{"signal": "attachment_scan_crash", "weight": 20,
                  "detail": f"Scanning {filename} crashed the isolated scanner ({type(e).__name__})"}],
                [f"{filename}: scanner crashed"])
