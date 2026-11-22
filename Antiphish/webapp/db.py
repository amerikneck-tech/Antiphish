"""SQLite storage (WAL mode). Small, zero-maintenance, perfect for a test deployment.
Swap for PostgreSQL when you go multi-server."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    credits       INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,              -- random, unguessable
    user_id     INTEGER NOT NULL REFERENCES users(id),
    created_at  REAL NOT NULL,
    source      TEXT NOT NULL,                 -- upload | paste | email
    mode        TEXT NOT NULL,                 -- quick | ai
    subject     TEXT,
    sender      TEXT,
    score       REAL NOT NULL,
    level       TEXT NOT NULL,
    result_json TEXT NOT NULL,
    text        TEXT,                          -- wiped after RETAIN_TEXT_HOURS
    cost        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scans_user ON scans(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL UNIQUE REFERENCES scans(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    label       INTEGER NOT NULL,              -- 0 legit, 1 phishing
    text        TEXT NOT NULL,
    comment     TEXT,
    created_at  REAL NOT NULL,
    exported    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (           -- rate limiting / audit
    key         TEXT NOT NULL,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events ON events(key, ts);
"""

_init_lock = threading.Lock()
_initialized_for: str | None = None


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(config.DB_PATH, timeout=15, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=15000")
    return con


def init():
    global _initialized_for
    with _init_lock:
        if _initialized_for == config.DB_PATH:
            return
        con = _connect()
        con.executescript(_SCHEMA)
        con.close()
        _initialized_for = config.DB_PATH


@contextmanager
def conn():
    init()
    con = _connect()
    try:
        yield con
    finally:
        con.close()


@contextmanager
def tx():
    """Exclusive write transaction (atomic credit changes)."""
    with conn() as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            yield con
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise


# ------------------------------------------------------------------ users
def create_user(email: str, password_hash: str, credits: int, is_admin: bool = False) -> int:
    with tx() as con:
        cur = con.execute(
            "INSERT INTO users(email, password_hash, is_admin, credits, created_at) VALUES (?,?,?,?,?)",
            (email.strip().lower(), password_hash, int(is_admin), credits, time.time()))
        return cur.lastrowid


def get_user(user_id: int):
    with conn() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def get_user_by_email(email: str):
    with conn() as con:
        return con.execute("SELECT * FROM users WHERE email=?", ((email or "").strip().lower(),)).fetchone()


def list_users():
    with conn() as con:
        return con.execute(
            "SELECT u.*, (SELECT COUNT(*) FROM scans s WHERE s.user_id=u.id) AS n_scans "
            "FROM users u ORDER BY u.id").fetchall()


def set_credits(user_id: int, credits: int):
    with tx() as con:
        con.execute("UPDATE users SET credits=? WHERE id=?", (max(0, credits), user_id))


def set_password(user_id: int, password_hash: str):
    with tx() as con:
        con.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))


def set_disabled(user_id: int, disabled: bool):
    with tx() as con:
        con.execute("UPDATE users SET disabled=? WHERE id=?", (int(disabled), user_id))


def charge(user_id: int, amount: int) -> bool:
    """Atomically take credits. False if not enough."""
    with tx() as con:
        cur = con.execute("UPDATE users SET credits = credits - ? WHERE id=? AND credits >= ?",
                          (amount, user_id, amount))
        return cur.rowcount == 1


def refund(user_id: int, amount: int):
    with tx() as con:
        con.execute("UPDATE users SET credits = credits + ? WHERE id=?", (amount, user_id))


# ------------------------------------------------------------------ scans
def save_scan(scan_id: str, user_id: int, source: str, mode: str, result: dict,
              subject: str, sender: str, text: str, cost: int):
    with tx() as con:
        con.execute(
            "INSERT INTO scans(id,user_id,created_at,source,mode,subject,sender,score,level,"
            "result_json,text,cost) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, user_id, time.time(), source, mode, (subject or "")[:300],
             (sender or "")[:300], result["score"], result["level"],
             json.dumps(result, ensure_ascii=False), (text or "")[:6000], cost))


def get_scan(scan_id: str, user_id: int | None = None):
    """user_id given -> only that user's scan (prevents viewing others' results)."""
    with conn() as con:
        if user_id is None:
            return con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return con.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id)).fetchone()


def list_scans(user_id: int, limit: int = 100):
    with conn() as con:
        return con.execute(
            "SELECT s.id, s.created_at, s.source, s.mode, s.subject, s.sender, s.score, s.level, "
            "f.label AS feedback FROM scans s LEFT JOIN feedback f ON f.scan_id=s.id "
            "WHERE s.user_id=? ORDER BY s.created_at DESC LIMIT ?", (user_id, limit)).fetchall()


def purge_old_text(hours: int) -> int:
    """Privacy: wipe stored e-mail text after the retention window,
    except for scans the user explicitly sent as feedback."""
    cutoff = time.time() - hours * 3600
    with tx() as con:
        cur = con.execute("UPDATE scans SET text=NULL WHERE text IS NOT NULL AND created_at < ?",
                          (cutoff,))
        return cur.rowcount


# ------------------------------------------------------------------ feedback
def save_feedback(scan_id: str, user_id: int, label: int, text: str, comment: str = ""):
    with tx() as con:
        con.execute(
            "INSERT INTO feedback(scan_id,user_id,label,text,comment,created_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(scan_id) DO UPDATE SET label=excluded.label, comment=excluded.comment, "
            "exported=0", (scan_id, user_id, int(label), text, (comment or "")[:500], time.time()))


def feedback_stats():
    with conn() as con:
        return con.execute(
            "SELECT COUNT(*) AS total, SUM(label=1) AS phishing, SUM(label=0) AS legit, "
            "SUM(exported=0) AS pending FROM feedback").fetchone()


def unexported_feedback():
    with conn() as con:
        return con.execute("SELECT * FROM feedback WHERE exported=0 ORDER BY id").fetchall()


def mark_exported(ids: list[int]):
    if not ids:
        return
    with tx() as con:
        con.executemany("UPDATE feedback SET exported=1 WHERE id=?", [(i,) for i in ids])


def recent_feedback(limit: int = 50):
    with conn() as con:
        return con.execute(
            "SELECT f.*, u.email, s.subject, s.score, s.level FROM feedback f "
            "JOIN users u ON u.id=f.user_id JOIN scans s ON s.id=f.scan_id "
            "ORDER BY f.created_at DESC LIMIT ?", (limit,)).fetchall()


# ------------------------------------------------------------------ rate limit
def hit(key: str, window_s: int) -> int:
    """Record an event and return how many happened in the window (incl. this one)."""
    now = time.time()
    with tx() as con:
        con.execute("DELETE FROM events WHERE ts < ?", (now - 86400,))
        con.execute("INSERT INTO events(key, ts) VALUES (?,?)", (key, now))
        return con.execute("SELECT COUNT(*) FROM events WHERE key=? AND ts >= ?",
                           (key, now - window_s)).fetchone()[0]


def count(key: str, window_s: int) -> int:
    with conn() as con:
        return con.execute("SELECT COUNT(*) FROM events WHERE key=? AND ts >= ?",
                           (key, time.time() - window_s)).fetchone()[0]


def clear(key: str):
    with tx() as con:
        con.execute("DELETE FROM events WHERE key=?", (key,))
