"""Web app + forward-to-scan tests (FastAPI TestClient, temp SQLite DB)."""
import base64
import io
import re
import zipfile

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    from webapp import config, db
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config, "WEB_USE_URL_INTEL", False)
    monkeypatch.setattr(config, "WEB_ALLOW_LLM", False)
    monkeypatch.setattr(db, "_initialized_for", None)
    from webapp import security
    alice = db.create_user("alice@example.com", security.hash_password("alice-password-1"), 10)
    bob = db.create_user("bob@example.com", security.hash_password("bob-password-12"), 10)
    admin = db.create_user("admin@example.com", security.hash_password("admin-password-1"), 999, True)
    from webapp.main import app
    return app, {"alice": alice, "bob": bob, "admin": admin}


def _csrf(client, path="/login"):
    html = client.get(path).text
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1)


def _login(client, email, pw):
    tok = _csrf(client)
    return client.post("/login", data={"email": email, "password": pw, "csrf": tok},
                       follow_redirects=False)


PHISH_EML = (b"From: PayPal Security <security@paypa1-secure.tk>\r\n"
             b"To: you@example.com\r\nSubject: Urgent: verify your account\r\n"
             b"Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\n"
             b"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n"
             b"Your account will be suspended. Verify your password now: http://paypa1-secure.tk/login\r\n")


def test_requires_login(app_env):
    app, _ = app_env
    c = TestClient(app)
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_login_wrong_password_and_rate_limit(app_env):
    app, _ = app_env
    c = TestClient(app)
    for _ in range(8):
        assert _login(c, "alice@example.com", "nope-nope-nope").status_code == 401
    r = _login(c, "alice@example.com", "alice-password-1")
    assert r.status_code == 429  # locked out even with the right password


def test_csrf_required(app_env):
    app, _ = app_env
    c = TestClient(app)
    _login(c, "alice@example.com", "alice-password-1")
    r = c.post("/scan", data={"raw": "hello", "csrf": "bad"}, follow_redirects=False)
    assert r.status_code == 400


def test_scan_upload_flow_credits_and_defanged_links(app_env):
    app, ids = app_env
    from webapp import db
    c = TestClient(app)
    assert _login(c, "alice@example.com", "alice-password-1").status_code == 303
    tok = _csrf(c, "/")
    r = c.post("/scan", data={"csrf": tok, "mode": "quick"},
               files={"file": ("mail.eml", PHISH_EML, "message/rfc822")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/r/")
    page = c.get(r.headers["location"]).text
    assert "Visok rizik" in page or "KRITIČNO" in page
    assert "hxxp://paypa1-secure[.]tk" in page            # links are defanged
    assert 'href="http://paypa1' not in page               # never clickable
    assert db.get_user(ids["alice"])["credits"] == 9


def test_other_user_cannot_see_result(app_env):
    app, _ = app_env
    a, b = TestClient(app), TestClient(app)
    _login(a, "alice@example.com", "alice-password-1")
    r = a.post("/scan", data={"csrf": _csrf(a, "/"), "raw": "Meeting moved to Tuesday"},
               follow_redirects=False)
    url = r.headers["location"]
    _login(b, "bob@example.com", "bob-password-12")
    assert b.get(url).status_code == 404


def test_no_credits(app_env):
    app, ids = app_env
    from webapp import db
    db.set_credits(ids["alice"], 0)
    c = TestClient(app)
    _login(c, "alice@example.com", "alice-password-1")
    r = c.post("/scan", data={"csrf": _csrf(c, "/"), "raw": "hello there"}, follow_redirects=True)
    assert "Nemaš dovoljno kredita" in r.text


def test_feedback_and_export(app_env, tmp_path):
    app, _ = app_env
    from webapp import db, manage
    c = TestClient(app)
    _login(c, "alice@example.com", "alice-password-1")
    r = c.post("/scan", data={"csrf": _csrf(c, "/"), "raw": PHISH_EML.decode()}, follow_redirects=False)
    sid = r.headers["location"].split("/")[-1]
    c.post(f"/r/{sid}/feedback", data={"csrf": _csrf(c, "/"), "label": "1"})
    assert db.feedback_stats()["phishing"] == 1
    manage.FEEDBACK_CSV = str(tmp_path / "feedback.csv")
    assert manage.export_feedback() == 1
    with open(manage.FEEDBACK_CSV, encoding="utf-8") as f:
        assert "verify your account" in f.read()


def test_admin_only(app_env):
    app, _ = app_env
    c = TestClient(app)
    _login(c, "alice@example.com", "alice-password-1")
    assert c.get("/admin").status_code == 403
    c2 = TestClient(app)
    _login(c2, "admin@example.com", "admin-password-1")
    assert c2.get("/admin").status_code == 200


def test_security_headers(app_env):
    app, _ = app_env
    r = TestClient(app).get("/login")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_xss_in_subject_is_escaped(app_env):
    app, _ = app_env
    c = TestClient(app)
    _login(c, "alice@example.com", "alice-password-1")
    eml = b"From: a@b.com\r\nSubject: <script>alert(1)</script>\r\nDate: x\r\n\r\nhello"
    r = c.post("/scan", data={"csrf": _csrf(c, "/"), "raw": eml.decode()}, follow_redirects=True)
    assert "<script>alert(1)</script>" not in r.text and "&lt;script&gt;" in r.text


def test_password_change_logs_out_other_sessions(app_env):
    app, _ = app_env
    a, b = TestClient(app), TestClient(app)
    _login(a, "alice@example.com", "alice-password-1")
    _login(b, "alice@example.com", "alice-password-1")
    a.post("/account/password", data={"csrf": _csrf(a, "/account"), "current": "alice-password-1",
                                      "new": "brand-new-password"})
    assert a.get("/", follow_redirects=False).status_code == 200
    assert b.get("/", follow_redirects=False).status_code == 303


# ---------------------------------------------------------------- mail intake
def _forward_as_attachment(from_addr, inner: bytes, auth="spf=pass; dkim=pass; dmarc=pass"):
    b64 = base64.b64encode(inner).decode()
    return (f"From: {from_addr}\r\nTo: scan@mydomain.com\r\nSubject: Fwd: check this\r\n"
            f"Message-ID: <abc@gmail.com>\r\nAuthentication-Results: mx.hostinger.com; {auth}\r\n"
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n"
            "--X\r\nContent-Type: text/plain\r\n\r\nplease check\r\n"
            "--X\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"orig.eml\"\r\n\r\n"
            + inner.decode() + "\r\n--X--\r\n").encode()


def test_intake_forward_as_attachment(app_env):
    from webapp import mail_intake
    sent = []
    st = mail_intake.process_message(_forward_as_attachment("alice@example.com", PHISH_EML),
                                     send=lambda *a: sent.append(a))
    assert st in ("scanned:HIGH", "scanned:CRITICAL"), st
    to, subj, body, irt = sent[0]
    assert to == "alice@example.com" and "[AntiPhish]" in subj and irt == "<abc@gmail.com>"
    assert "hxxp://paypa1-secure[.]tk" in body and "http://paypa1" not in body


def test_intake_inline_forward_uses_original_sender(app_env):
    from webapp import mail_intake
    raw = (b"From: alice@example.com\r\nTo: scan@mydomain.com\r\nSubject: Fwd: Urgent: verify your account\r\n\r\n"
           b"---------- Forwarded message ---------\r\nFrom: PayPal <security@paypa1-secure.tk>\r\n"
           b"Subject: Urgent: verify your account\r\n\r\nVerify your password now: http://paypa1-secure.tk/login\r\n")
    sent = []
    st = mail_intake.process_message(raw, send=lambda *a: sent.append(a))
    assert st.startswith("scanned:")
    assert "proslijeđen kao običan tekst" in sent[0][2]


def test_intake_ignores_strangers_spoofs_and_loops(app_env):
    from webapp import mail_intake
    send = lambda *a: (_ for _ in ()).throw(AssertionError("must not reply"))
    assert mail_intake.process_message(_forward_as_attachment("stranger@evil.com", PHISH_EML),
                                       send=send) == "ignored:unknown-sender"
    assert mail_intake.process_message(
        _forward_as_attachment("alice@example.com", PHISH_EML, auth="spf=fail; dkim=none; dmarc=fail"),
        send=send) == "ignored:auth-failed"
    loop = b"From: alice@example.com\r\nSubject: [AntiPhish] HIGH\r\nAuto-Submitted: auto-replied\r\n\r\nx"
    assert mail_intake.process_message(loop, send=send) == "ignored:automated"


def test_report_defangs_bare_domains_but_keeps_our_link(app_env):
    from webapp import mail_intake, config
    sent = []
    mail_intake.process_message(_forward_as_attachment("alice@example.com", PHISH_EML),
                                send=lambda *a: sent.append(a))
    body = sent[0][2]
    assert "paypa1-secure.tk" not in body and "paypa1-secure[.]tk" in body
    assert f"{config.BASE_URL}/r/" in body          # our own report link must stay usable
