"""Text-content heuristics (language-agnostic, EN + SV + HR/RS coverage)."""
from __future__ import annotations

import re

URGENCY_WORDS = [
    "urgent", "immediately", "expires", "limited time", "act now", "final notice",
    "as soon as possible", "within 24 hours", "account will be closed",
    "hitno", "odmah", "ističe", "poslednji rok", "vaš nalog će biti",
    "akut", "omedelbart", "gå ut", "sista dagen", "ditt konto kommer att",
]

MONEY_PRESSURE = [
    "wire transfer", "payment", "invoice", "iban", "swish", "refund",
    "won", "prize", "lottery", "bitcoin", "gift card",
    "uplatite", "novac", "faktura", "dobili ste", "nagrada",
    "betalning", "faktura", "vinst", "belopp", "presentkort",
]

CREDENTIAL_ASK = [
    "verify your", "confirm your", "update your payment", "enter your password",
    "click the link below", "log in to", "sign in to",
    "verifiera din", "bekräfta ditt", "ange ditt lösenord",
    "potvrdite", "prijavite se", "unesite lozinku", "kliknite na link",
]

GENERIC_GREETING = [
    "dear customer", "dear user", "dear account holder", "dear valued",
    "bästa kund", "kära användare", "poštovani korisniče", "poštovana korisnice",
]

THREAT_WORDS = [
    "suspended", "blocked", "terminated", "legal action", "unauthorized access",
    "stängas av", "spärras", "rättsliga åtgärder",
    "obustavljen", "blokiran", "tužba", "neovlašćen pristup",
]


def analyze_text(text: str) -> list[dict]:
    signals = []
    t = (text or "").lower()

    def add(name, weight, detail):
        signals.append({"signal": name, "weight": weight, "detail": detail})

    def count_hits(words):
        return sum(1 for w in words if w in t)

    u = count_hits(URGENCY_WORDS)
    if u >= 2:
        add("text_urgency_high", 18, f"{u} urgency phrases")
    elif u == 1:
        add("text_urgency_low", 8, "One urgency phrase")

    m = count_hits(MONEY_PRESSURE)
    if m >= 2:
        add("text_money_pressure", 10, f"{m} financial/pressure phrases")
    elif m == 1:
        add("text_money_pressure", 5, "One financial/pressure phrase")

    c = count_hits(CREDENTIAL_ASK)
    if c >= 1:
        add("text_credential_ask", 16, f"{c} credential-harvesting phrases")

    g = count_hits(GENERIC_GREETING)
    if g >= 1 and ("dear" in t or "bästa" in t or "poštovan" in t):
        add("text_generic_greeting", 8, "Generic greeting without a name")

    th = count_hits(THREAT_WORDS)
    if th >= 1:
        add("text_threat", 12, f"{th} threat/sanction phrases")

    # ALL CAPS words (ignore product codes like YZY, QNTM, B2B)
    caps = [w for w in re.findall(r"\b[A-ZÄÖÅŠĐČĆŽ]{5,}\b", text or "")
            if not any(c.isdigit() for c in w)]
    if len(caps) >= 5:
        add("text_excessive_caps", 4, f"{len(caps)} words in ALL CAPS")

    return signals
