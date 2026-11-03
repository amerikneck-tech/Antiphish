"""Qwen LLM-as-judge phishing analysis.

Two modes:
  1. "ollama"   — local, free, private (default). Requires Ollama + `ollama pull qwen2.5:7b`
  2. "dashscope"— Alibaba Cloud API (needs DASHSCOPE_API_KEY env var)

The judge returns structured JSON which we convert into detector signals.
Everything degrades gracefully: if Qwen is unreachable, detector works without it.
"""
from __future__ import annotations

import json
import os
import re

from .config import (QWEN_PROVIDER, QWEN_MODEL, QWEN_BASE_URL,
                     QWEN_API_KEY, LLM_TIMEOUT)

PROMPT_TEMPLATE = """You are a phishing detection expert. Analyze this email and respond with ONLY a JSON object (no markdown, no explanation) with exactly these keys:
- "is_phishing": boolean
- "confidence": integer 0-100 (how sure you are)
- "techniques": array of 1-4 short strings naming the attack techniques used (e.g. "credential harvesting", "urgency pressure", "brand spoofing", "BEC", "malicious attachment", "none")
- "summary": one sentence verdict

Email:
From: {sender}
Subject: {subject}
Body:
{body}
"""


def _extract_json(text: str) -> dict | None:
    """Qwen sometimes wraps JSON in prose/markdown — extract the first JSON object."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _call_ollama(prompt: str) -> str | None:
    import requests
    try:
        r = requests.post(
            f"{QWEN_BASE_URL}/api/chat",
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "stream": False,
                  "format": "json",
                  "options": {"temperature": 0.1}},
            timeout=LLM_TIMEOUT)
        r.raise_for_status()
        return r.json()["message"]["content"]
    except Exception:
        return None


def _call_dashscope(prompt: str) -> str | None:
    import requests
    try:
        r = requests.post(
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            headers={"Authorization": f"Bearer {QWEN_API_KEY}"},
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.1,
                  "response_format": {"type": "json_object"}},
            timeout=LLM_TIMEOUT)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def llm_available() -> bool:
    if QWEN_PROVIDER == "dashscope":
        return bool(QWEN_API_KEY)
    import requests
    try:
        r = requests.get(f"{QWEN_BASE_URL}/api/tags", timeout=3)
        return r.ok
    except Exception:
        return False


def judge_email(subject: str, body: str, sender: str = "") -> list[dict]:
    """Analyze with Qwen -> detector signals (empty list on failure)."""
    prompt = PROMPT_TEMPLATE.format(
        sender=sender, subject=subject, body=(body or "")[:3000])
    raw = (_call_ollama if QWEN_PROVIDER == "ollama" else _call_dashscope)(prompt)
    if not raw:
        return []
    data = _extract_json(raw)
    if not data or "is_phishing" not in data:
        return []

    signals = []
    conf = int(data.get("confidence", 50))
    techs = ", ".join(data.get("techniques", [])) or "n/a"
    if data["is_phishing"]:
        w = 35 if conf >= 80 else 25
        signals.append({"signal": "llm_phishing_judged", "weight": w,
                        "detail": f"Qwen: phishing ({conf}% conf) [{techs}]: {data.get('summary','')}"})
    elif conf >= 80:
        signals.append({"signal": "llm_clean_judged", "weight": -12,
                        "detail": f"Qwen: clean ({conf}% conf): {data.get('summary','')}"})
    return signals
