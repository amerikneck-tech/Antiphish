"""ML text classifier: TF-IDF + calibrated LogisticRegression.

Starter corpus now includes ~140 phishing + ~140 legit samples, including
EVASION variants (spaced words, homoglyphs, image-only lures, QR lures)
because real attackers actively avoid keyword filters.

>>> Replace load_dataset() with a real corpus before production use. <<<
"""
from __future__ import annotations

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


def load_dataset():
    texts = _PHISHING + _LEGIT
    labels = [1] * len(_PHISHING) + [0] * len(_LEGIT)
    return texts, np.array(labels)


def build_pipeline() -> Pipeline:
    base = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1,
                                  max_features=30000, sublinear_tf=True)),
        ("clf", LogisticRegression(C=2.0, max_iter=2000, class_weight="balanced")),
    ])
    # Calibration makes predict_proba trustworthy (needed for risk scoring)
    return CalibratedClassifierCV(base, cv=3, ensemble=False)


def evaluate(pipe=None, verbose: bool = True) -> dict:
    """Cross-validated metrics on the built-in dataset."""
    texts, y = load_dataset()
    if pipe is None:
        pipe = build_pipeline()
    Xtr, Xte, ytr, yte = train_test_split(
        texts, y, test_size=0.25, random_state=42, stratify=y)
    pipe.fit(Xtr, ytr)
    acc = pipe.score(Xte, yte)
    prec = cross_val_score(clone(build_pipeline()), texts, y, cv=5,
                           scoring="precision").mean()
    rec = cross_val_score(clone(build_pipeline()), texts, y, cv=5,
                          scoring="recall").mean()
    f1 = cross_val_score(clone(build_pipeline()), texts, y, cv=5,
                         scoring="f1").mean()
    if verbose:
        print(f"Holdout accuracy : {acc:.3f}")
        print(f"CV precision     : {prec:.3f}")
        print(f"CV recall        : {rec:.3f}")
        print(f"CV F1            : {f1:.3f}")
        print(f"NOTE: metrics are on the synthetic starter corpus only.")
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}


def train() -> Pipeline:
    texts, y = load_dataset()
    pipe = build_pipeline()
    pipe.fit(texts, y)
    return pipe


def save_model(pipe, path: str):
    joblib.dump(pipe, path)


def load_model(path: str):
    return joblib.load(path)
