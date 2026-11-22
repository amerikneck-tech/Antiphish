"""ML text classifier: TF-IDF + calibrated LogisticRegression.

Starter corpus now includes ~140 phishing + ~140 legit samples, including
EVASION variants (spaced words, homoglyphs, image-only lures, QR lures)
because real attackers actively avoid keyword filters.

>>> Replace load_dataset() with a real corpus before production use. <<<
"""
from __future__ import annotations

import csv
import os
import re

import joblib
import numpy as np
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

_PHISHING = [
    "Urgent: Your account will be suspended verify your identity now",
    "Your PayPal account has been limited click the link below to log in",
    "Final notice: unpaid invoice attached please review payment",
    "You have won 50000 USD in our lottery claim your prize now",
    "Security alert: unauthorized access to your account confirm your password",
    "Dear customer your package could not be delivered update your address",
    "Your Netflix account expires today update your payment information",
    "Verify your Microsoft account within 24 hours or it will be closed",
    "Invoice attached: outstanding balance 1200 EUR pay immediately",
    "Your account has been compromised click here to secure it",
    "DHL: customs fee required for your shipment pay now",
    "Dear user confirm your email address to avoid termination",
    "You received a refund of 350 USD confirm your bank details",
    "Urgent wire transfer needed for the supplier invoice",
    "Your Apple ID has been locked verify your identity immediately",
    "Congratulations you are our lucky winner claim reward now",
    "Action required: your password expires in 24 hours",
    "Suspicious sign-in detected verify your account now",
    "Your Amazon order cannot be shipped update payment method",
    "Last warning: legal action will be taken unless you pay",
    "Account verification required: click the secure link below",
    "Your subscription will be cancelled confirm your billing info",
    "Unusual activity detected log in to your bank account now",
    "Confirm your identity to receive your tax refund",
    "Dear valued customer you must update your details immediately",
    "Payment declined: update your card to keep your account",
    "You've been selected for an exclusive offer act now",
    "Your mailbox storage is full verify your account to continue",
    "Bank security notice: your card has been blocked confirm pin",
    "New voice message: sign in to listen to your voicemail",
    # evasion: spaced / leetspeak / homoglyph variants
    "Your acc0unt will be sus pended ver1fy now within 24 h0urs",
    "P a y P a l: unauth0rized log in detected confirm y0ur identity",
    "Ver1fy your Micros0ft acc0unt or it will be cl0sed",
    "Your accοunt has unusuаl activity (lookalike letters) log in now",
    "C l i c k   h e r e   t o   v e r i f y   y o u r   a c c o u n t",
    "Your pаyment of 12OO EUR is pеnding cοnfirm yοur card",
    "Unusuаl sign-in tο yοur bank accοunt verify nοw",
    "Urgent: reset y0ur p@ssword in the next 24 hours",
    # QR / callback / vishing lures
    "Scan the QR code to verify your account and avoid suspension",
    "You missed a delivery scan the QR code to reschedule now",
    "Our fraud team called you call back immediately to avoid account closure",
    "Voicemail attachment: listen to secure message from your bank",
    "We tried to deliver your parcel twice scan QR to book redelivery",
    # BEC / business lures
    "Are you at your desk? I need a quick favor regarding a payment",
    "I'm heading into a meeting can you process the attached wire transfer today",
    "We have a new supplier send payment to the account in the attached invoice",
    "I need you to buy gift cards for the client event today keep it confidential",
    "Change of bank details: please update our account for future invoices",
    "The CEO approved this transfer please execute today it's urgent",
    "HR: your salary increase is ready confirm your details in the portal",
    "IT department: your mailbox will be migrated confirm password to continue",
    "Please review the attached purchase order and confirm delivery date",
    "Your direct deposit failed update your banking information today",
    # Swedish phishing
    "Akut: ditt konto kommer att stängas verifiera din identitet",
    "Du har vunnit 50000 SEK i vårt lotteri hämta din vinst nu",
    "Bekräfta ditt lösenord för att undvika att kontot spärras",
    "Faktura bifogad: betala omedelbart för att undvika påminnelseavgift",
    "Ditt paket kunde inte levereras betala fraktavgift nu",
    "Obehörig åtkomst upptäckt logga in för att skydda ditt konto",
    "Skatteverket: du har ett återbetalningskrav bekräfta dina uppgifter",
    "Uppdatera dina betalningsuppgifter innan ditt konto stängs",
    "Ditt BankID har gått ut verifiera det innan midnatt",
    "PostNord: din försändelse är stoppad betala hanteringsavgift",
    "Din Swish-betalning misslyckades bekräfta ditt konto",
    "Vi har blockerat ditt kort efter misstänkt aktivitet logga in nu",
    "Ditt Microsoft 365-konto kommer att inaktiveras bekräfta åtkomst",
    "Vinstmeddelande: du har vunnit en iPhone bekräfta leveransadress",
    "Betalningspåminnelse: faktura 4451 förfaller idag",
    # Serbian/Croatian phishing
    "Hitno: vaš nalog će biti obustavljen potvrdite identitet odmah",
    "Vaš račun je hakovan kliknite na link da ga zaštitite",
    "Faktura u prilogu platite odmah inače sledi tužba",
    "Dobili ste nagradu od 10000 EUR potvrdite podatke",
    "Vaš paket nije mogao biti dostavljen uplatite carinu",
    "Verifikujte svoj nalog u narednih 24 sata",
    "Vaša kartica je blokirana potvrdite PIN kod",
    "Poštanski servis: plaćanje po preuzimanju potrebno odmah",
    "Vaš nalog za e-bankaristvu zahteva verifikaciju",
    "Obaveštenje o nasleđu: potvrdite podatke za transfer sredstava",
]

# 2025-2026 lure styles (calendar, e-signature, file share, MFA/device-code,
# AiTM, callback, BEC). Wording differs from eval_sets.MODERN_PHISH.
_PHISHING += [
    "Meeting invitation: Annual performance review - accept and log in with your Office credentials to see the agenda",
    "New event: Benefits enrollment deadline. Open the invite and sign in to the HR portal to confirm your selection",
    "Calendar: Policy acknowledgement required. Click the event link and authenticate with your corporate account",
    "You have been invited to edit Budget_2026.xlsx on SharePoint. Sign in to open the document",
    "Adobe Sign: Contract amendment awaiting your signature. Review now, the envelope expires today",
    "Dropbox Transfer: 3 files were sent to you, enter your email password to download",
    "Your authenticator registration will be removed. Re-register MFA today by scanning the code below",
    "To keep using Teams, visit the device login page and enter the code shown in this message",
    "IT Helpdesk: we are migrating mailboxes tonight. Validate your account at the link to avoid data loss",
    "Voicemail received (0:47) from external caller. Listen to the message by signing in with your work email",
    "Your Norton subscription renewed for 399 USD. If you did not authorize this call our billing desk immediately",
    "PayPal invoice: you were charged 649.99 for a crypto purchase. To dispute, call the support number provided",
    "Hi, it's the CEO. I'm in a meeting, can you process an urgent payment to a new supplier? Don't call, just email",
    "Please update the bank account on file for our company, all future invoices must be paid to the new IBAN",
    "Payroll notice: your direct deposit details need confirmation before this month's salary is released",
    "Your Apple account was used to purchase a gift card, if this was not you sign in to cancel the order",
    "Facebook Meta: your page will be deleted for copyright violation. Submit an appeal using the form",
    "Coinbase: withdrawal request pending. Verify it was you or your wallet will be frozen",
    "Kalendarski poziv: obavezna obuka. Prihvatite poziv i prijavite se službenim nalogom",
    "Pošta: paket čeka carinjenje, uplatite 2,49 EUR karticom da ne bude vraćen pošiljaocu",
]

_LEGIT = [
    "Meeting moved to Tuesday at 10 please update your calendar",
    "Here is the quarterly report attached for your review",
    "Thanks for the call today, sending over the contract draft",
    "Reminder: team lunch on Friday at the usual place",
    "Your order 8842 has shipped and arrives Thursday",
    "Welcome aboard! Your onboarding starts Monday at 9",
    "Please review the attached proposal when you have time",
    "Invoice 2024-118 for consulting services, due in 30 days",
    "Happy birthday! Hope you have a great day",
    "The server maintenance window is Sunday 02:00-04:00",
    "New comment on your pull request, please take a look",
    "Your booking is confirmed for Friday 19:00, party of 4",
    "Newsletter: October product updates and webinar schedule",
    "Minutes from yesterday's sync are attached",
    "Can you send me the latest sales numbers by Wednesday",
    "Your password was changed successfully, no action needed",
    "Flight itinerary for your trip to Stockholm attached",
    "Reminder: dentist appointment next Monday 15:30",
    "The project kickoff is scheduled for next week",
    "HR: open enrollment for benefits ends next Friday",
    "Hvala na sastanku, šaljem zapisnik u prilogu",
    "Pozdrav, evo ponude koju smo diskutovali prošle nedelje",
    "Podsećanje: rok za izveštaj je petak",
    "Vaša porudžbina je poslata i stiže za 3 dana",
    "Tack för mötet, bifogar protokollet från idag",
    "Påminnelse: leveransen till kund sker på måndag",
    "Bokningen är bekräftad, välkommen på fredag",
    "Månadsrapporten för september är bifogad",
    "Vi ses på konferensen nästa vecka",
    "Din beställning har skickats och anländer på torsdag",
    # realistic everyday business noise (should stay LOW)
    "Follow-up on the budget discussion from last week",
    "The shared drive cleanup is scheduled for Saturday",
    "Please approve the vacation request in the HR portal",
    "WiFi will be unavailable in building B on Thursday evening",
    "New parking policy starts next month, see attached memo",
    "The client loved the demo, next steps call on Monday",
    "Don't forget to submit your expense reports by Friday",
    "Elevator maintenance tomorrow 08:00-09:00, use the stairs",
    "Coffee machine on floor 3 is broken, vendor called",
    "The design files are in the shared folder, let me know if you can't access",
    "Annual security training is due, complete it by month end",
    "Welcome to the team intro session on Wednesday at 14",
    "Printer on floor 2 is out of toner, replacement ordered",
    "The board meeting agenda is attached, 30 min slots please",
    "IT: VPN client update available, install at your convenience",
    "Reminder: submit timesheets before payroll cutoff on Friday",
    "The library book you reserved is ready for pickup",
    "Gym class schedule for next month is posted in the app",
    "Your package from the bookstore arrived at the front desk",
    "Team offsite moved to the lakeside venue, map attached",
    "Please review my vacation request for the first week of July",
    "The quarterly business review deck is ready for comments",
    "Car service reminder: your appointment is confirmed for Tuesday",
    "Neighborhood association: recycling schedule change next week",
    "School newsletter: parent-teacher conferences next month",
    "Your subscription receipt: thanks for your payment, no action needed",
    "Receipt for your order, thank you for shopping with us",
    "The webinar recording from yesterday is now available",
    "Backup completed successfully last night",
    "Your login from a new device was you, right? Just checking per policy",
]


from .config import DATA_DIR as _DATA_DIR
CORPUS_PATH = os.getenv("CORPUS_PATH", os.path.join(os.path.dirname(__file__), "..", "data", "corpus.csv"))
FEEDBACK_PATH = os.path.join(_DATA_DIR, "feedback.csv")


def normalize_text(t: str) -> str:
    """Make text era-independent: the model must learn LANGUAGE patterns,
    not that '2002 mail = legit'. Applied identically at train and predict."""
    t = (t or "").lower()
    t = re.sub(r"https?://([^/\s]+)\S*", r" urltoken \1 ", t)
    t = re.sub(r"www\.([^/\s]+)\S*", r" urltoken \1 ", t)
    t = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", " emailtoken ", t)
    t = re.sub(r"\b(19|20)\d\d\b", " yeartoken ", t)
    t = re.sub(r"\d+", "0", t)
    t = re.sub(r"[=_*~\-]{3,}", " ", t)          # ascii separators
    return re.sub(r"\s+", " ", t)[:4000]


def load_starter(n_synth: int = 1500):
    """Hand-written starter samples + generated modern legit (hard negatives)."""
    from .synth_legit import generate
    legit = _LEGIT * 3 + generate(n_synth)
    texts = _PHISHING * 3 + legit
    labels = [1] * (len(_PHISHING) * 3) + [0] * len(legit)
    return texts, np.array(labels)


def _read_csv(path, with_meta=False):
    rows = []
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return rows
    csv.field_size_limit(10_000_000)
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.reader(f):
            if len(r) < 2 or r[0] == "text":
                continue
            try:
                label = int(r[1])
            except ValueError:
                continue
            if label in (0, 1):
                rows.append((r[0], label, r[2] if len(r) > 2 else "feedback",
                             int(r[3]) if len(r) > 3 and r[3].isdigit() else 0))
    return rows


def load_dataset(include_feedback: bool = True):
    """Real corpus (data/corpus.csv) + starter samples + your feedback.
    Falls back to the starter corpus if corpus.csv was not built yet."""
    rows = _read_csv(CORPUS_PATH)
    st, sy = load_starter()
    # starter samples are short modern examples - repeat so they carry weight
    rows += [(t, int(y), "starter", 2026) for t, y in zip(st, sy)]
    if include_feedback:
        # your own mail is the most valuable data -> weight x5
        rows += [(t, y, "feedback", 2026) for t, y, *_ in _read_csv(FEEDBACK_PATH)] * 5
    texts = [r[0] for r in rows]
    y = np.array([r[1] for r in rows])
    return texts, y


def build_pipeline() -> Pipeline:
    from sklearn.pipeline import FeatureUnion
    features = FeatureUnion([
        ("word", TfidfVectorizer(preprocessor=normalize_text, ngram_range=(1, 2),
                                 min_df=2, max_df=0.9, max_features=60000,
                                 sublinear_tf=True)),
        # char n-grams resist obfuscation: 'P a y P a l', 'verífy', 'acc0unt'
        ("char", TfidfVectorizer(preprocessor=normalize_text, analyzer="char_wb",
                                 ngram_range=(3, 5), min_df=3, max_features=80000,
                                 sublinear_tf=True)),
    ])
    base = Pipeline([
        ("features", features),
        ("clf", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced")),
    ])
    # Calibration makes predict_proba trustworthy (needed for risk scoring)
    return CalibratedClassifierCV(base, cv=3, method="sigmoid", ensemble=False)


def evaluate(pipe=None, verbose: bool = True) -> dict:
    """Honest evaluation:
    1. temporal holdout - train on phishing <= 2023, test on 2024-2025 phishing
       (+ random 20% of legit) -> does it catch NEW campaigns?
    2. held-out modern probe sets (eval_sets.py) never seen in training.
    """
    from sklearn.metrics import precision_score, recall_score, f1_score
    from .eval_sets import MODERN_LEGIT, MODERN_PHISH
    rows = _read_csv(CORPUS_PATH)
    if not rows:
        print("data/corpus.csv missing - run: python scripts/build_corpus.py")
        return {}
    rng = np.random.default_rng(42)
    train_rows, test_rows = [], []
    for r in rows:
        if r[1] == 1:
            (test_rows if r[3] >= 2024 else train_rows).append(r)
        else:
            (test_rows if rng.random() < 0.2 else train_rows).append(r)
    st, sy = load_starter()
    Xtr = [r[0] for r in train_rows] + list(st)
    ytr = np.array([r[1] for r in train_rows] + list(sy))
    pipe = pipe or build_pipeline()
    pipe.fit(Xtr, ytr)
    Xte = [r[0] for r in test_rows]
    yte = np.array([r[1] for r in test_rows])
    pred = (pipe.predict_proba(Xte)[:, 1] >= 0.5).astype(int)
    p_leg = pipe.predict_proba(MODERN_LEGIT)[:, 1]
    p_ph = pipe.predict_proba(MODERN_PHISH)[:, 1]
    res = {
        "temporal_precision": precision_score(yte, pred),
        "temporal_recall_2024_25": recall_score(yte, pred),
        "temporal_f1": f1_score(yte, pred),
        "modern_legit_fp_rate": float((p_leg >= 0.5).mean()),
        "modern_legit_mean_prob": float(p_leg.mean()),
        "modern_phish_recall": float((p_ph >= 0.5).mean()),
        "modern_phish_mean_prob": float(p_ph.mean()),
    }
    if verbose:
        print(f"Train: {len(Xtr)}  Test: {len(Xte)} (phishing 2024-2025 + 20% legit)")
        for k, v in res.items():
            print(f"  {k:28s} {v:.3f}")
        print("Modern legit with highest phishing probability:")
        for i in np.argsort(-p_leg)[:5]:
            print(f"   {p_leg[i]:.2f}  {MODERN_LEGIT[i][:70]!r}")
        print("Modern phishing with LOWEST probability (misses):")
        for i in np.argsort(p_ph)[:5]:
            print(f"   {p_ph[i]:.2f}  {MODERN_PHISH[i][:70]!r}")
    return res


def train() -> Pipeline:
    texts, y = load_dataset()
    pipe = build_pipeline()
    pipe.fit(texts, y)
    return pipe


def save_model(pipe, path: str):
    """Save model + SHA256 sidecar (verified on load)."""
    import hashlib
    joblib.dump(pipe, path)
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(path + ".sha256", "w") as f:
        f.write(digest)


class ModelIntegrityError(RuntimeError):
    pass


def load_model(path: str):
    """joblib/pickle can execute code -> refuse a model file whose hash does
    not match the sidecar written by save_model()."""
    import hashlib
    side = path + ".sha256"
    if not os.path.exists(side):
        raise ModelIntegrityError(f"Missing {side} - retrain with: python train.py")
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(side) as f:
        expected = f.read().strip()
    if digest != expected:
        raise ModelIntegrityError(f"Model file {path} was modified (hash mismatch) - refusing to load")
    return joblib.load(path)
