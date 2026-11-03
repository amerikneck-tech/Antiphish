# 🛡️ AntiPhish MVP

AI-asistirana detekcija phishing mejlova. Komponente:

| Fajl | Uloga |
|---|---|
| `antiphish/checks.py` | URL + sender + SPF/DKIM/DMARC heuristike |
| `antiphish/features.py` | Tekstualne heuristike (EN/SV/RS) |
| `antiphish/model.py` | ML klasifikator (TF-IDF + LogisticRegression) + starter dataset |
| `antiphish/scorer.py` | Težinski scoring -> rizik 0-100 |
| `antiphish/detector.py` | Glavni API: `analyze_email(email_dict)` |
| `app.py` | Streamlit UI |
| `demo.py` | CLI demo sa 3 primera |
| `train.py` | (Re)trening modela |

## Pokretanje

```bash
pip install -r requirements.txt
python train.py        # trenira model -> models/model.joblib
python demo.py         # demo analiza
streamlit run app.py   # web UI
python -m pytest tests/
```

## API

```python
from antiphish.detector import analyze_email

result = analyze_email({
    "subject": "Urgent: verify your account",
    "body": "...email text...",
    "sender": "security@fake-paypal.tk",
    "reply_to": None,
    "spf": "fail", "dkim": "fail", "dmarc": "fail",
})
# result["score"] -> 0..100
# result["level"] -> LOW / SUSPICIOUS / HIGH / CRITICAL
# result["signals"] -> lista uočenih signala sa težinama
# result["ml_phishing_probability"] -> ML procena
```

## Nivoi rizika

- **< 30 LOW** — normalna pažnja
- **30-60 SUSPICIOUS** — proveri pošiljaoca pre klika
- **60-85 HIGH** — verovatno phishing; ne klikati
- **> 85 CRITICAL** — skoro sigurno phishing; blokirati i prijaviti

## Šta je sledeće (roadmap)

1. **Pravi dataset** — zameni sintetičke podatke u `model.py` pravim korpusom
   (npr. [Nazario phishing corpus](https://monkey.org/~jose/phishing/),
   Enron + r/phishing prikupljanje, vlastiti feed od beta korisnika)
2. **VirusTotal/Urlscan integracija** — reputacija linkova bez kliktanja
   (samo API poziv po URL-u)
3. **Microsoft Graph API** — čitanje mejlova iz M365 i automatsko označavanje
   (javna beta, `Mail.Read`, dodavanje banner-a preko actionable messages)
4. **Behavioral baseline** — učenje "normalnog" stila komunikacije po firmi
   (za BEC detekciju — najteži ali najvredniji deo)
5. **Višejezični model** — XLM-R ili fine-tune mBERT umesto TF-IDF

## Napomene / ograničenja MVP-a

- ML je treniran na ~90 sintetičkih primera — dobar za demo, **ne za produkciju**
- Bez sandbox analize priloga (sledeća faza)
- False-positive rate nije kalibrisan na realnom saobraćaju
- Heuristike su dizajnirane da budu objasnjive (explainability > maksimalna tačnost)


## v0.2 — "Real" upgrade

- **280-sample starter corpus** including evasion variants (spaced words,
  leetspeak, homoglyphs, QR/vishing lures, BEC scripts) + calibrated model
  (trustworthy probabilities)
- **Real .eml parsing** (`parse_eml.py` / `analyze_eml()`) — headers,
  auth results, HTML->text, attachments
- **New signals**: display-name spoofing, freemail-for-role, risky attachments
- **Threat intel ready**: VirusTotal + urlscan.io clients in
  `antiphish/urlintel.py` — set `VT_API_KEY` / `URLSCAN_API_KEY` env vars
- **Evaluation**: `python evaluate.py` (current CV F1 ~0.81 on synthetic corpus)

### End-to-end test result
Phishing .eml (fake PayPal + IP-host URL + auth fails): **99.5 CRITICAL**
Legit .eml: **2.2 LOW**

### Metrics caveat
F1 ~0.81 is measured ONLY on the synthetic starter corpus. Real-world
performance requires a real labeled corpus — see roadmap item 1.


## v0.3 — Qwen AI judge + live inbox monitor

### Qwen LLM-as-judge (`antiphish/llm_judge.py`)
- Local & free via **Ollama**: install from ollama.com, then `ollama pull qwen2.5:7b`
- Or cloud via **DashScope**: set `DASHSCOPE_API_KEY` + `QWEN_PROVIDER=dashscope`
- Returns strict JSON verdict -> `llm_phishing_judged` (+25/35) or `llm_clean_judged` (-12)
- Usage: `analyze_email(email, use_llm=True)` — degrades gracefully if Qwen down

### Live monitor (`python -m antiphish.monitor`)
Connects to any IMAP mailbox and analyzes every new email automatically,
raising a Windows desktop notification when level >= SUSPICIOUS.
All alerts also go to `antiphish_alerts.log`.

Setup (Gmail): 2FA -> App password, then:
```
set IMAP_HOST=imap.gmail.com
set IMAP_USER=you@gmail.com
set IMAP_PASSWORD=your_app_password
python -m antiphish.monitor
```
Stop with Ctrl+C. Works with Outlook (imap-mail.outlook.com), Yahoo, etc.

### New tests: 14 total, all passing.


## v0.4 — FP fixes + feedback loop

- `auth_all_pass` legitimacy signal (-15): SPF+DKIM+DMARC pass marks sender as likely legit
- ALL CAPS detection ignores product codes (YZY, QNTM, B2B), needs 5+ hits
- Reply-To extraction fixed (parses real address from 'Name <addr>' headers)
- Reduced weights for many-subdomains / very long URLs (newsletter tracking links)
- **Feedback loop**: put misclassified emails into `data/feedback.csv` as
  `"subject + body text",0` (legit) or `,1` (phishing), then `python -m antiphish.learn`.
  Each retrain includes your real traffic -> fewer false positives over time.
- Monitor: set `MONITOR_USE_LLM=1` to add Qwen judgment to every scanned email
  (fixes borderline cases like 'Confirm your email' transactional mail).
- Startup log now shows VirusTotal ON/OFF and LLM ON/OFF status.

Measured on your real inbox traffic: newsletters dropped from HIGH (80) to LOW (5-16),
real phishing stays CRITICAL (99.3).


## v0.5 — Setup wizard + provider auto-detection

`python -m antiphish.monitor` now starts an interactive wizard if no
credentials are configured:
1. Enter your email -> provider auto-detected (Gmail, Outlook, Yahoo,
   iCloud, AOL, GMX, Zoho, Proton, Seznam + IMAP host guessing for unknown domains)
2. Provider-specific app-password instructions shown
3. Password entered via hidden input (getpass)
4. Connection tested BEFORE saving; 3 attempts on failure
5. Optional: save to `.env` (auto-loaded on every start) - never commit .env!

Environment variables / .env still override the wizard (IMAP_HOST, IMAP_USER,
IMAP_PASSWORD). `.env` loader is built into config.py - no extra dependency.

## v0.5.1 - critical fix
run() polling loop restored (dropped accidentally in the wizard refactor) +
30s socket timeout on all IMAP connections. Regression test added.

## v0.6 — Attachment scanning + score-based alerts

### Attachment scanning (`antiphish/attachment_scan.py`)
Every attachment is now analyzed, not just its filename:
1. SHA256 hash -> VirusTotal file reputation (hash lookup only, no upload)
2. PDFs: text extracted (pypdf, with raw-byte fallback) -> phishing
   heuristics + ML probability on the content
3. URLs found inside the file -> same URL checks as body links
4. Size cap 10MB

### Score-based notifications
Monitor alerts only when score >= NOTIFY_MIN_SCORE (default **70** =
HIGH and above). Newsletters at 40-60 no longer pop notifications.
Override: set NOTIFY_MIN_SCORE=60 (or any value) in .env / config.

Startup line now shows the threshold: "Alert score >= 70".
Tests: 26 total, all passing (incl. end-to-end .eml with phishing PDF).
