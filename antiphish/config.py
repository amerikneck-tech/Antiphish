"""Central configuration: thresholds, weights, external API keys."""
from __future__ import annotations

import os


def _load_dotenv():
    """Load project-root .env file if present (no external dependency)."""
    path = os.path.join(os.path.dirname(__file__), "..", ".env")
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv()

# Risk levels
THRESHOLDS = {"SUSPICIOUS": 30, "HIGH": 60, "CRITICAL": 85}

# Scoring mix between heuristic signals and ML probability
HEURISTIC_WEIGHT = 0.55
ML_WEIGHT = 0.45

# External threat intel (set via environment variables or edit here)
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# Freemail providers (legit for personal mail, suspicious for "IT dept")
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
}

# --- Qwen LLM judge ---
# provider: "ollama" (local, free, default) or "dashscope" (Alibaba API)
QWEN_PROVIDER = os.getenv("QWEN_PROVIDER", "ollama")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen2.5:7b")
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "http://localhost:11434")
QWEN_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
LLM_TIMEOUT = 30

# --- Live inbox monitor (IMAP) ---
IMAP_HOST = os.getenv("IMAP_HOST", "")          # e.g. imap.gmail.com
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD", "")  # Gmail: app password!
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
NOTIFY_MIN_LEVEL = "SUSPICIOUS"                 # kept for backward compat
# Alert only when risk score >= this (70 = HIGH and above). Override with env.
NOTIFY_MIN_SCORE = int(os.getenv("NOTIFY_MIN_SCORE", "70"))
# Set "1" to add Qwen LLM judgment to every scanned email (slower, smarter)
MONITOR_USE_LLM = os.getenv("MONITOR_USE_LLM", "0") == "1"
