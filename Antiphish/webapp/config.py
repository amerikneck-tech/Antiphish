"""Web app configuration - everything comes from environment variables (.env)."""
from __future__ import annotations

import os
import secrets

from antiphish import config as _core  # noqa: F401  (loads project .env)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = _core.DATA_DIR
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA_DIR, "antiphish.db"))

# Session signing key. MUST be set in production (random 64+ chars).
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)  # dev only: sessions reset on restart
    SECRET_KEY_IS_RANDOM = True
else:
    SECRET_KEY_IS_RANDOM = False

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
HTTPS_ONLY_COOKIES = os.getenv("HTTPS_ONLY_COOKIES", "1" if BASE_URL.startswith("https") else "0") == "1"
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))

# Scanning
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "15"))
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "2"))   # protect VPS RAM/CPU
WEB_USE_URL_INTEL = os.getenv("WEB_USE_URL_INTEL", "1") == "1"
WEB_ALLOW_LLM = os.getenv("WEB_ALLOW_LLM", "1") == "1"       # offer "AI scan" if Qwen reachable

# Credits
COST_QUICK = int(os.getenv("COST_QUICK", "1"))
COST_AI = int(os.getenv("COST_AI", "3"))
DEFAULT_CREDITS = int(os.getenv("DEFAULT_CREDITS", "50"))

# Abuse limits
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "8"))      # per IP+email / 15 min
SCANS_PER_HOUR = int(os.getenv("SCANS_PER_HOUR", "60"))             # per user

# Privacy: e-mail text is kept only this long (for feedback), then wiped.
RETAIN_TEXT_HOURS = int(os.getenv("RETAIN_TEXT_HOURS", "72"))

# Forward-to-scan mailbox (e.g. scan@yourdomain.com on Hostinger Email)
INTAKE_IMAP_HOST = os.getenv("INTAKE_IMAP_HOST", "imap.hostinger.com")
INTAKE_IMAP_PORT = int(os.getenv("INTAKE_IMAP_PORT", "993"))
INTAKE_SMTP_HOST = os.getenv("INTAKE_SMTP_HOST", "smtp.hostinger.com")
INTAKE_SMTP_PORT = int(os.getenv("INTAKE_SMTP_PORT", "465"))
INTAKE_USER = os.getenv("INTAKE_USER", "")          # scan@yourdomain.com
INTAKE_PASSWORD = os.getenv("INTAKE_PASSWORD", "")
INTAKE_POLL_SECONDS = int(os.getenv("INTAKE_POLL_SECONDS", "20"))
INTAKE_USE_LLM = os.getenv("INTAKE_USE_LLM", "0") == "1"
