"""AntiPhish web app (FastAPI).

Run locally:   uvicorn webapp.main:app --reload
Production:    see deploy/DEPLOY.md (Docker + Caddy HTTPS)
"""
from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import config, db, scanning, security
from .explain import explain_signal, level_info

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("antiphish.web")

HERE = os.path.dirname(__file__)


@asynccontextmanager
async def lifespan(_app):
    db.init()
    if config.SECRET_KEY_IS_RANDOM:
        log.warning("SECRET_KEY not set - using a random key (sessions reset on restart). "
                    "Set SECRET_KEY in .env for production!")
    db.purge_old_text(config.RETAIN_TEXT_HOURS)
    yield
    try:
        from antiphish.attachment_scan import shutdown_sandbox
        shutdown_sandbox()
    except Exception:
        pass


app = FastAPI(title="AntiPhish", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY,
                   session_cookie="ap_session", max_age=config.SESSION_DAYS * 86400,
                   same_site="lax", https_only=config.HTTPS_ONLY_COOKIES)
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))
templates.env.filters["defang"] = security.defang
templates.env.filters["dt"] = lambda ts: time.strftime("%d.%m.%Y %H:%M", time.localtime(ts or 0))
templates.env.globals["level_info"] = level_info


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if config.HTTPS_ONLY_COOKIES:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ------------------------------------------------------------------ helpers
class Redirect(Exception):
    def __init__(self, url):
        self.url = url


@app.exception_handler(Redirect)
async def _redirect_handler(request, exc: Redirect):
    return RedirectResponse(exc.url, status_code=303)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = security.new_csrf()
        request.session["csrf"] = tok
    return tok


def check_csrf(request: Request, token: str):
    if not security.csrf_ok(request.session.get("csrf"), token):
        raise HTTPException(status_code=400, detail="Neispravan sigurnosni token (CSRF). Osvježi stranicu.")


def current_user(request: Request):
    uid = request.session.get("uid")
    user = db.get_user(uid) if uid else None
    if not user or user["disabled"] or request.session.get("pwh") != user["password_hash"][-12:]:
        request.session.clear()
        raise Redirect("/login")
    return user


def admin_user(user=Depends(current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Samo za administratore.")
    return user


def render(request: Request, name: str, ctx: dict | None = None, status: int = 200):
    ctx = dict(ctx or {})
    ctx.setdefault("user", None)
    ctx["csrf"] = csrf_token(request)
    ctx["flash"] = request.session.pop("flash", None)
    ctx["config"] = config
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def flash(request: Request, msg: str, kind: str = "info"):
    request.session["flash"] = {"msg": msg, "kind": kind}


# ------------------------------------------------------------------ auth
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...),
          csrf: str = Form("")):
    check_csrf(request, csrf)
    key = f"login:{client_ip(request)}:{email.strip().lower()}"
    if db.count(key, 900) >= config.LOGIN_MAX_ATTEMPTS:
        return render(request, "login.html",
                      {"error": "Previše neuspjelih pokušaja. Sačekaj 15 minuta."}, 429)
    user = db.get_user_by_email(email)
    ok = security.verify_password(password, user["password_hash"] if user else security.DUMMY_HASH)
    if not user or not ok or user["disabled"]:
        db.hit(key, 900)
        return render(request, "login.html", {"error": "Pogrešan email ili lozinka."}, 401)
    db.clear(key)
    request.session.clear()
    request.session.update({"uid": user["id"], "pwh": user["password_hash"][-12:],
                            "csrf": security.new_csrf()})
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ------------------------------------------------------------------ scanning
@app.get("/", response_class=HTMLResponse)
def index(request: Request, user=Depends(current_user)):
    return render(request, "index.html", {"user": user, "llm": scanning.llm_ready()})


@app.post("/scan")
async def scan(request: Request, user=Depends(current_user), csrf: str = Form(""),
               mode: str = Form("quick"), raw: str = Form(""),
               file: UploadFile | None = File(None)):
    check_csrf(request, csrf)
    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    data, source = b"", "paste"
    if file is not None and file.filename:
        name = file.filename.lower()
        if name.endswith(".msg"):
            flash(request, "Outlook .msg nije podržan. U Outlooku izaberi 'Sačuvaj kao' / 'Download' "
                           "u .eml formatu.", "error")
            return RedirectResponse("/", status_code=303)
        data = await file.read(limit + 1)
        source = "upload"
    elif raw.strip():
        data = raw.encode("utf-8", errors="replace")
    if not data:
        flash(request, "Priloži .eml fajl ili zalijepi sadržaj maila.", "error")
        return RedirectResponse("/", status_code=303)
    if len(data) > limit:
        flash(request, f"Fajl je veći od {config.MAX_UPLOAD_MB} MB.", "error")
        return RedirectResponse("/", status_code=303)
    mode = "ai" if mode == "ai" and scanning.llm_ready() else "quick"
    try:
        parsed, has_headers = scanning.parse_input(data)
        from starlette.concurrency import run_in_threadpool
        scan_id = await run_in_threadpool(scanning.run_scan, user, parsed, source, mode, has_headers)
    except scanning.ScanError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/", status_code=303)
    return RedirectResponse(f"/r/{scan_id}", status_code=303)


@app.get("/r/{scan_id}", response_class=HTMLResponse)
def result(request: Request, scan_id: str, user=Depends(current_user)):
    row = db.get_scan(scan_id, None if user["is_admin"] else user["id"])
    if not row:
        raise HTTPException(status_code=404, detail="Rezultat nije pronađen.")
    res = json.loads(row["result_json"])
    signals = [dict(s, help=explain_signal(s["signal"])) for s in res.get("signals", [])]
    with db.conn() as con:
        fb = con.execute("SELECT label FROM feedback WHERE scan_id=?", (scan_id,)).fetchone()
    return render(request, "result.html", {
        "user": user, "row": row, "res": res,
        "positive": [s for s in signals if s["weight"] > 0],
        "negative": [s for s in signals if s["weight"] < 0],
        "feedback": fb["label"] if fb else None,
        "can_feedback": bool(row["text"]) or fb is not None,
        "own": row["user_id"] == user["id"],
    })


@app.post("/r/{scan_id}/feedback")
def feedback(request: Request, scan_id: str, user=Depends(current_user), csrf: str = Form(""),
             label: int = Form(...), comment: str = Form("")):
    check_csrf(request, csrf)
    row = db.get_scan(scan_id, user["id"])
    if not row:
        raise HTTPException(status_code=404)
    if label not in (0, 1):
        raise HTTPException(status_code=400)
    with db.conn() as con:
        existing = con.execute("SELECT text FROM feedback WHERE scan_id=?", (scan_id,)).fetchone()
    text = row["text"] or (existing["text"] if existing else None)
    if not text:
        flash(request, "Tekst ovog maila je već obrisan (privatnost), feedback više nije moguć.", "error")
        return RedirectResponse(f"/r/{scan_id}", status_code=303)
    db.save_feedback(scan_id, user["id"], label, text, comment)
    flash(request, "Hvala! Feedback je sačuvan i koristiće se za učenje modela.", "ok")
    return RedirectResponse(f"/r/{scan_id}", status_code=303)


@app.get("/history", response_class=HTMLResponse)
def history(request: Request, user=Depends(current_user)):
    return render(request, "history.html", {"user": user, "scans": db.list_scans(user["id"])})


# ------------------------------------------------------------------ account
@app.get("/account", response_class=HTMLResponse)
def account(request: Request, user=Depends(current_user)):
    return render(request, "account.html", {"user": user})


@app.post("/account/password")
def change_password(request: Request, user=Depends(current_user), csrf: str = Form(""),
                    current: str = Form(...), new: str = Form(...)):
    check_csrf(request, csrf)
    if not security.verify_password(current, user["password_hash"]):
        flash(request, "Trenutna lozinka nije tačna.", "error")
        return RedirectResponse("/account", status_code=303)
    problem = security.password_problems(new)
    if problem:
        flash(request, problem, "error")
        return RedirectResponse("/account", status_code=303)
    h = security.hash_password(new)
    db.set_password(user["id"], h)
    request.session["pwh"] = h[-12:]   # other sessions of this user are logged out
    flash(request, "Lozinka je promijenjena.", "ok")
    return RedirectResponse("/account", status_code=303)


# ------------------------------------------------------------------ admin
@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, user=Depends(admin_user)):
    return render(request, "admin.html", {
        "user": user, "users": db.list_users(), "fb": db.feedback_stats(),
        "recent": db.recent_feedback(30), "llm": scanning.llm_ready()})


@app.post("/admin/users")
def admin_create_user(request: Request, user=Depends(admin_user), csrf: str = Form(""),
                      email: str = Form(...), password: str = Form(...),
                      credits: int = Form(config.DEFAULT_CREDITS)):
    check_csrf(request, csrf)
    problem = security.password_problems(password)
    if problem or "@" not in email:
        flash(request, problem or "Neispravan email.", "error")
    elif db.get_user_by_email(email):
        flash(request, "Korisnik sa tim emailom već postoji.", "error")
    else:
        db.create_user(email, security.hash_password(password), credits)
        flash(request, f"Korisnik {email} je kreiran.", "ok")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/credits")
def admin_credits(request: Request, uid: int, user=Depends(admin_user), csrf: str = Form(""),
                  credits: int = Form(...)):
    check_csrf(request, csrf)
    db.set_credits(uid, credits)
    flash(request, "Krediti ažurirani.", "ok")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/toggle")
def admin_toggle(request: Request, uid: int, user=Depends(admin_user), csrf: str = Form("")):
    check_csrf(request, csrf)
    target = db.get_user(uid)
    if target and target["id"] != user["id"]:
        db.set_disabled(uid, not target["disabled"])
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/feedback/export")
def admin_export(request: Request, user=Depends(admin_user), csrf: str = Form("")):
    check_csrf(request, csrf)
    from .manage import export_feedback
    n = export_feedback()
    flash(request, f"{n} novih primjera dodano u data/feedback.csv. "
                   f"Za ponovno treniranje: python -m antiphish.learn (pa restart).", "ok")
    return RedirectResponse("/admin", status_code=303)


# ------------------------------------------------------------------ misc
@app.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    uid = request.session.get("uid")
    return render(request, "privacy.html", {"user": db.get_user(uid) if uid else None})


@app.get("/healthz")
def healthz():
    db.init()
    return JSONResponse({"ok": True})


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")
