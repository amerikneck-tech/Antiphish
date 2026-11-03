from antiphish.checks import check_url, extract_urls
from antiphish.features import analyze_text
from antiphish.detector import analyze_email


def test_ip_url():
    hits = [s["signal"] for s in check_url("http://192.168.1.1/login")]
    assert "url_ip_host" in hits


def test_shortener():
    hits = [s["signal"] for s in check_url("https://bit.ly/3xAb12")]
    assert "url_shortener" in hits


def test_https():
    hits = [s["signal"] for s in check_url("http://fake-login-example.com")]
    assert "url_no_https" in hits


def test_extract_urls():
    text = "Click here http://evil.tk/x or www.example.com/page"
    urls = extract_urls(text)
    assert any("evil.tk" in u for u in urls)


def test_urgency_text():
    hits = [s["signal"] for s in analyze_text("URGENT act now, account will be closed immediately!")]
    assert "text_urgency_high" in hits


def test_clear_phishing_scores_high():
    r = analyze_email({
        "subject": "Urgent verify your account",
        "body": "Your account will be suspended. Confirm your password now: "
                "http://paypa1-secure-login.tk/verify",
        "sender": "security@paypa1.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
    })
    assert r["score"] >= 60, r


def test_legit_scores_low():
    r = analyze_email({
        "subject": "Meeting moved to Tuesday",
        "body": "Hi, please update your calendar. Thanks!",
        "sender": "colleague@company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
    })
    assert r["score"] < 60, r


def test_displayname_spoof():
    from antiphish.checks import check_display_name
    hits = [s["signal"] for s in check_display_name("PayPal Support <security.alerts@gmail.com>")]
    assert "sender_displayname_spoof" in hits


def test_attachment_risky():
    from antiphish.checks import check_attachments
    hits = [s["signal"] for s in check_attachments(["invoice_2024.pdf.exe", "notes.txt"])]
    assert "attachment_risky" in hits


def test_eml_parsing_end_to_end():
    import os
    from antiphish.detector import analyze_eml
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = analyze_eml(os.path.join(base, "sample_phishing.eml"))
    assert r["score"] >= 85, r
    r2 = analyze_eml(os.path.join(base, "sample_legit.eml"))
    assert r2["score"] < 30, r2


def test_llm_json_extraction():
    from antiphish.llm_judge import _extract_json
    assert _extract_json('pre {"is_phishing": true, "confidence": 90, "techniques": [], "summary": "x"} post')["is_phishing"] is True
    assert _extract_json("no json") is None


def test_llm_judge_signals_mocked():
    import antiphish.llm_judge as lj
    lj._call_ollama = lambda p: '{"is_phishing": true, "confidence": 88, "techniques": ["BEC"], "summary": "CEO fraud"}'
    sigs = lj.judge_email("Quick request", "wire today urgent")
    assert sigs and sigs[0]["signal"] == "llm_phishing_judged"


def test_monitor_should_alert():
    from antiphish.monitor import should_alert
    assert should_alert("CRITICAL", 95.0) and should_alert("SUSPICIOUS", 71.0)
    assert not should_alert("LOW", 10.0) and not should_alert("HIGH", 55.0)


def test_score_never_negative_with_llm_clean():
    import antiphish.detector as d
    import antiphish.llm_judge as l2
    l2._call_ollama = lambda p: '{"is_phishing": false, "confidence": 95, "techniques": ["none"], "summary": "clean"}'
    r = d.analyze_email({"subject": "Hi", "body": "See you tomorrow", "sender": "a@b.com",
                         "spf": "pass", "dkim": "pass", "dmarc": "pass"}, use_llm=True)
    assert r["score"] >= 0.0


def test_auth_all_pass_lowers_score():
    from antiphish.checks import check_auth
    hits = [s for s in check_auth("pass", "pass", "pass")]
    assert hits and hits[0]["weight"] < 0


def test_newsletter_not_flagged():
    import antiphish.detector as d
    r = d.analyze_email({
        "subject": "UP TO 40 PCT OFF - Heat your Outfit",
        "body": "SALE: shop now! https://buzzsneakers.m14.mailplus.nl/unsub?token=abc123xyz",
        "sender": "BUZZ Sneaker Station <newsletter@buzzsneakers-promo.com>",
        "spf": "pass", "dkim": "pass", "dmarc": "pass"})
    assert r["level"] in ("LOW", "SUSPICIOUS"), r


def test_real_phishing_still_critical():
    import antiphish.detector as d
    r = d.analyze_email({
        "subject": "Urgent: Your account has been limited",
        "body": "Dear customer, verify your account within 24 hours or it will be closed: "
                "http://paypa1-secure-login.tk/verify Confirm your password now.",
        "sender": "security@paypa1-secure.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail"})
    assert r["level"] == "CRITICAL", r


def test_reply_to_parses_real_address():
    from antiphish.checks import check_sender
    sigs = check_sender("Wenn from Footshop <help@footshop.eu>",
                        "Footshop <reply-abc@footshop.eu>")
    assert not any(s["signal"] == "reply_to_mismatch" for s in sigs)


def test_provider_detection():
    from antiphish.providers import detect, guess_hosts
    assert detect("a@gmail.com")["host"] == "imap.gmail.com"
    assert detect("a@hotmail.com")["host"] == "imap-mail.outlook.com"
    assert detect("a@proton.me")["port"] == 1143
    assert detect("a@nepoznato.rs") is None
    assert guess_hosts("a@firma.rs")[0] == "imap.firma.rs"


def test_wizard_autodetect_gmail(monkeypatch=None):
    import antiphish.monitor as mon
    class FakeIMAP:
        def login(self, *a): pass
        def logout(self): pass
    mon.imaplib.IMAP4_SSL = lambda host: FakeIMAP()
    seq = iter(["test.user@gmail.com", "apppassword123", "n"])
    import builtins
    orig_input, orig_getpass = builtins.input, mon.getpass.getpass
    builtins.input = lambda prompt="": next(seq)
    mon.getpass.getpass = lambda prompt="": "apppassword123"
    try:
        host, user, pw = mon._wizard()
    finally:
        builtins.input, mon.getpass.getpass = orig_input, orig_getpass
    assert host == "imap.gmail.com" and user == "test.user@gmail.com"


def test_run_loop_connects_polls_exits_cleanly():
    """Regression: run() must connect, poll, and exit on Ctrl+C."""
    import time
    import antiphish.monitor as mon
    class FakeIMAP:
        def __init__(self, *a, **k): pass
        def login(self, *a): pass
        def select(self, *a): pass
        def search(self, *a): return ("OK", [b""])
        def logout(self): pass
    mon._connect = lambda *a, **k: FakeIMAP()
    orig_sleep = time.sleep
    time.sleep = lambda s: (_ for _ in ()).throw(KeyboardInterrupt)
    orig_cfg = (mon.IMAP_HOST, mon.IMAP_USER, mon.IMAP_PASSWORD)
    mon.IMAP_HOST, mon.IMAP_USER, mon.IMAP_PASSWORD = "h", "u", "p"
    try:
        mon.run()
    finally:
        time.sleep = orig_sleep
        mon.IMAP_HOST, mon.IMAP_USER, mon.IMAP_PASSWORD = orig_cfg


def test_run_has_polling_loop():
    src = open("antiphish/monitor.py", encoding="utf-8").read()
    assert "while True:" in src and "check_once(mail)" in src


def test_scan_attachment_pdf_phishing():
    import antiphish.attachment_scan as att
    data = open("data/sample_phishing.pdf", "rb").read()
    sigs = att.scan_attachment("invoice.pdf", data, model=None)
    names = [s["signal"] for s in sigs]
    assert "pdf_phishing_content" in names, sigs
    assert any("paypa1" in s["detail"] or "in invoice.pdf" in s["detail"] for s in sigs), sigs


def test_scan_attachment_vt_hash_mocked():
    import antiphish.attachment_scan as att
    att.vt_file_report = lambda h: {"seen": True, "malicious": 5, "suspicious": 0, "name": "evil.pdf"}
    sigs = att.scan_attachment("doc.pdf", b"%PDF-fake", model=None)
    assert any(s["signal"] == "attachment_vt_malicious" for s in sigs), sigs


def test_should_alert_score_based():
    from antiphish.monitor import should_alert
    from antiphish.config import NOTIFY_MIN_SCORE
    assert NOTIFY_MIN_SCORE == 70
    assert should_alert("LOW", 75.0) is True
    assert should_alert("HIGH", 69.9) is False
    assert should_alert("CRITICAL", 99.0) is True


def test_eml_with_pdf_attachment_end_to_end():
    import base64, os
    from antiphish.detector import analyze_eml
    pdf = open("data/sample_phishing.pdf", "rb").read()
    b64 = base64.b64encode(pdf).decode()
    eml = ("From: Billing <billing@fake-invoice.tk>\r\n"
           "To: victim@company.com\r\n"
           "Subject: Invoice attached\r\n"
           "MIME-Version: 1.0\r\n"
           "Content-Type: multipart/mixed; boundary=B\r\n\r\n"
           "--B\r\nContent-Type: text/plain\r\n\r\nPlease find invoice attached.\r\n"
           "--B\r\nContent-Type: application/pdf\r\n"
           'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
           "Content-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--B--\r\n")
    path = "data/_test_att.eml"
    open(path, "w").write(eml)
    try:
        r = analyze_eml(path)
        names = [s["signal"] for s in r["signals"]]
        assert "pdf_phishing_content" in names, r["signals"][:8]
        assert r["score"] >= 60, r["score"]
    finally:
        os.remove(path)
