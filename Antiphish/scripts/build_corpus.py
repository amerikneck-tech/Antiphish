"""Download public email corpora and build data/corpus.csv for training.

Sources
-------
PHISHING  Jose Nazario phishing corpus 2015-2025 (CC-BY-4.0, commercial use OK,
          attribution required): https://monkey.org/~jose/phishing/
LEGIT     SpamAssassin public corpus easy_ham, easy_ham_2, hard_ham
          https://spamassassin.apache.org/old/publiccorpus/
          (copyright of message text stays with original senders - used only
          to train a statistical model; the raw mails are NOT redistributed)

Usage:
    python scripts/build_corpus.py             # download + build
    python scripts/build_corpus.py --offline   # only use files already in data/raw

Output: data/corpus.csv  (text,label,source,year)   label 1 = phishing, 0 = legit
Your own data/feedback.csv is merged in at training time (antiphish.learn).
"""
from __future__ import annotations

import csv
import email
import email.policy
import hashlib
import mailbox
import os
import sys
import tarfile
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from antiphish.email_parser import parse_message, message_from_bytes_robust  # noqa: E402

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "corpus.csv")

NAZARIO_YEARS = range(2015, 2026)
NAZARIO_URL = "https://monkey.org/~jose/phishing/phishing-{y}"
SA_URL = "https://spamassassin.apache.org/old/publiccorpus/{n}.tar.bz2"
SA_SETS = ["20030228_easy_ham", "20030228_easy_ham_2", "20030228_hard_ham"]
MAX_CHARS = 4000


def _download(url: str, dest: str):
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return
    print("downloading", url)
    req = urllib.request.Request(url, headers={"User-Agent": "antiphish-corpus-builder"})
    with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as f:
        f.write(r.read())


def _text(msg) -> str:
    try:
        d = parse_message(msg)
    except Exception:
        return ""
    return f"{d.get('subject', '')}\n{d.get('body', '')}".strip()[:MAX_CHARS]


def nazario_rows():
    for y in NAZARIO_YEARS:
        path = os.path.join(RAW, f"nazario-{y}.mbox")
        if not os.path.exists(path):
            continue
        box = mailbox.mbox(path, factory=lambda f: message_from_bytes_robust(f.read()))
        n = 0
        for msg in box:
            t = _text(msg)
            if len(t) > 40:
                n += 1
                yield t, 1, "nazario", y
        print(f"  nazario {y}: {n}")


def spamassassin_rows():
    for name in SA_SETS:
        path = os.path.join(RAW, f"{name}.tar.bz2")
        if not os.path.exists(path):
            continue
        n = 0
        with tarfile.open(path, "r:bz2") as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.name.endswith("cmds"):
                    continue
                raw = tf.extractfile(m).read()
                t = _text(message_from_bytes_robust(raw))
                if len(t) > 40:
                    n += 1
                    yield t, 0, name.split("_", 1)[1], 2002
        print(f"  spamassassin {name}: {n}")


def main():
    os.makedirs(RAW, exist_ok=True)
    if "--offline" not in sys.argv:
        for y in NAZARIO_YEARS:
            _download(NAZARIO_URL.format(y=y), os.path.join(RAW, f"nazario-{y}.mbox"))
        for n in SA_SETS:
            _download(SA_URL.format(n=n), os.path.join(RAW, f"{n}.tar.bz2"))

    seen, rows = set(), []
    for t, label, src, year in list(nazario_rows()) + list(spamassassin_rows()):
        h = hashlib.sha1(" ".join(t.lower().split())[:1500].encode()).hexdigest()
        if h in seen:
            continue  # drop duplicates (same campaign sent many times)
        seen.add(h)
        rows.append((t, label, src, year))

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "source", "year"])
        w.writerows(rows)
    ph = sum(r[1] for r in rows)
    print(f"wrote {OUT}: {len(rows)} emails ({ph} phishing / {len(rows) - ph} legit)")


if __name__ == "__main__":
    main()
