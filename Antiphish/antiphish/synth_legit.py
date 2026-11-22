"""Generator of MODERN legitimate email samples (hard negatives).

Why: public legit corpora are from ~2002 (mailing lists). Modern phishing
imitates receipts, sign-in alerts and newsletters, so a model trained only on
old ham learns "looks like a receipt => phishing". These templates teach it
what the REAL versions look like (no credential ask, 'no action needed',
links to the brand's own domain, unsubscribe footers).

Wording intentionally differs from eval_sets.MODERN_LEGIT (held-out probe).
"""
from __future__ import annotations

import random

BRANDS = [("Zalando", "zalando.com"), ("Spotify", "spotify.com"), ("IKEA", "ikea.com"),
          ("Booking.com", "booking.com"), ("Bolt", "bolt.eu"), ("Wolt", "wolt.com"),
          ("Decathlon", "decathlon.com"), ("H&M", "hm.com"), ("Lidl", "lidl.com"),
          ("Steam", "steampowered.com"), ("Airbnb", "airbnb.com"), ("Uber", "uber.com"),
          ("Revolut", "revolut.com"), ("GitHub", "github.com"), ("Slack", "slack.com"),
          ("Notion", "notion.so"), ("Canva", "canva.com"), ("Asos", "asos.com"),
          ("Temu", "temu.com"), ("AliExpress", "aliexpress.com"), ("Ryanair", "ryanair.com"),
          ("Glovo", "glovoapp.com"), ("Duolingo", "duolingo.com"), ("LinkedIn", "linkedin.com"),
          ("Twitch", "twitch.tv"), ("Reddit", "reddit.com"), ("Etsy", "etsy.com"),
          ("Vinted", "vinted.com"), ("Telenor", "telenor.com"), ("A1", "a1.net")]
NAMES = ["Ana", "Marko", "Sara", "Ivan", "Elena", "Nikola", "Emma", "Lucas", "Mia", "Adnan",
         "Lejla", "Jonas", "Olivia", "Petar", "Amra", "Filip", "Nora", "Edin", "Lena", "Tarik"]
PRODUCTS = ["running shoes", "wireless headphones", "desk lamp", "winter jacket", "phone case",
            "coffee grinder", "backpack", "yoga mat", "gaming mouse", "water bottle", "book"]
CITIES = ["Sarajevo", "Belgrade", "Zagreb", "Vienna", "Stockholm", "Berlin", "Milan", "Ljubljana"]
FOOTERS = ["You're receiving this email because you signed up at {d}. Unsubscribe | Preferences",
           "Manage your email settings: https://www.{d}/settings/notifications",
           "© {brand}. All rights reserved. Privacy | Terms | Unsubscribe",
           "Don't want these emails? Update preferences at https://{d}/account",
           "This is an automated message from {brand}. Please do not reply.", ""]


def _r(seq):
    return random.choice(seq)


def _tpl():
    b, d = _r(BRANDS)
    n, p, c = _r(NAMES), _r(PRODUCTS), _r(CITIES)
    amt = f"{random.randint(3, 400)}.{random.randint(0, 99):02d}"
    cur = _r(["EUR", "USD", "BAM", "RSD", "SEK", "KM"])
    num = random.randint(10000, 999999)
    day = _r(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"])
    pct = _r([10, 15, 20, 25, 30, 40, 50, 60, 70])
    url = f"https://www.{d}/{_r(['orders', 'account', 'deals', 'app', 'help', 'trips'])}/{num}"
    T = [
        # transactional
        f"{b}: order {num} confirmed\nHi {n}, thanks for shopping with us. We'll let you know when your {p} ships. Order total {amt} {cur}. Details: {url}",
        f"Good news, your {p} is on the way\nTracking number {num}. Estimated delivery {day}. Follow your parcel: {url}",
        f"Delivered: your {b} package\nYour order {num} was delivered today. Enjoy! Rate your experience in the app.",
        f"Your {b} receipt\nPaid {amt} {cur} with card ending {random.randint(1000, 9999)}. Billing period renews next month. Download PDF receipt from your account page.",
        f"Payment received - thank you\nWe received your payment of {amt} {cur} for invoice {num}. No further action is needed.",
        f"Your refund has been processed\nWe've refunded {amt} {cur} to your original payment method. It may take 5-10 business days to appear.",
        f"Your trip to {c} is booked\nBooking reference {num}. Check-in {day} from 14:00. Manage the reservation in the {b} app.",
        f"Your ride receipt\nThanks for riding with {b}, {n}. Trip total {amt} {cur}. Tip your driver in the app.",
        f"Subscription renewed\nYour {b} plan renewed automatically for {amt} {cur}. Change or cancel anytime in account settings.",
        f"Your {b} invoice is available\nInvoice {num} for {amt} {cur} is ready. You can view it at {url}. Questions? Contact our support team.",
        # security - the LEGIT versions (no credential ask)
        f"New login to your {b} account\nWe noticed a login from {c} on {day}. If this was you, you can ignore this message. If not, change your password from the app.",
        f"{num} is your {b} security code\nUse it to complete sign-in. The code expires in 10 minutes. We will never call you to ask for this code.",
        f"Your {b} password was updated\nThis confirms your password change. If you didn't do this, contact support through the official app.",
        f"Two-factor authentication enabled\nYou turned on 2FA for your {b} account. Great choice for keeping your account safe.",
        f"Confirm your email for {b}\nThanks for signing up, {n}! Tap the button to confirm this address and finish creating your account. If you didn't sign up, ignore this email.",
        f"Your monthly {b} statement\nYour statement for last month is available in the app. We will never ask for your PIN or password by email.",
        # newsletters / promos
        f"{pct}% off {p}s this weekend only\nOur biggest {b} sale of the season is here. Free returns. Shop now at https://www.{d}/sale",
        f"New arrivals just dropped\nFresh styles from your favourite brands at {b}. Be the first to shop the collection.",
        f"{n}, picked for you\nBased on your recent views: {p}, {_r(PRODUCTS)} and more. Prices from {amt} {cur}.",
        f"Last chance: {pct}% off ends at midnight\nDon't miss out on {b} deals. Use code SAVE{pct} at checkout.",
        f"What's new at {b} this month\nProduct updates, tips and stories from our community. Read the full newsletter on our blog.",
        f"Your {b} year in review\nYou listened, watched and explored a lot this year. See your personalised highlights.",
        f"Members-only early access\nAs a {b} member you get early access to our winter sale starting {day}.",
        f"Free shipping on everything\nThis week only at {b}: free delivery, no minimum order.",
        # social / app notifications
        f"{n} mentioned you in a comment\n\"@you what do you think about this?\" Reply in {b}.",
        f"{n} sent you a message\nOpen {b} to read and reply.",
        f"You have {random.randint(2, 40)} new notifications\nSee what you missed on {b}.",
        f"{n} invited you to a workspace\nJoin {n}'s team on {b} to start collaborating.",
        f"Your weekly {b} summary\nYou completed {random.randint(1, 20)} lessons this week. Keep your streak going!",
        f"{n} commented on your post\n\"Great photo from {c}!\" See the conversation.",
        f"Reminder: event on {day}\n{n} invited you to Team dinner in {c} at 19:00. Going? Yes / Maybe / No",
        # utilities / telco / services
        f"Your {b} bill is ready\nAmount due {amt} {cur}, due date {day}. Pay through the app or your usual bank transfer.",
        f"You've used 80% of your data\nYou have 1GB left until your plan resets. Add more data in the {b} app if needed.",
        f"Scheduled maintenance on {day}\n{b} services may be briefly unavailable between 02:00 and 04:00. No action is required.",
        f"We're updating our privacy policy\nThe changes take effect next month. You don't need to do anything. Read the summary on our website.",
        f"Your appointment is confirmed\nSee you on {day} at 10:30 in {c}. Need to reschedule? Use the link in your booking confirmation.",
        # work / personal
        f"Re: plan for {day}\nHi {n}, works for me. I'll bring the slides, see you at 10.",
        f"Notes from today's call\nThanks all. Summary and next steps attached. Next check-in on {day}.",
        f"Draft proposal for review\nHi {n}, attached is the first draft. Comments welcome before {day}.",
        f"Quick question about the report\n{n}, could you send me the numbers for {c} when you have a minute? Thanks!",
        f"Happy birthday {n}!\nWishing you a great day, let's celebrate on {day}.",
        f"Faktura {num}\nPozdrav {n}, u prilogu je faktura za prošli mjesec. Rok plaćanja 15 dana po ugovoru.",
        f"Vaša porudžbina {num} je poslata\nPaket stiže u {day}. Pratite pošiljku u aplikaciji {b}.",
        f"Sastanak u {day}\nĆao {n}, može u 11h kod nas u kancelariji? Javi.",
        f"Din beställning {num} har skickats\nLeverans beräknas till {day}. Spåra paketet i appen.",
        f"Novi popust {pct}% u {b}\nPogledaj ponudu za {p}. Odjava sa liste u dnu poruke.",
    ]
    body = _r(T)
    foot = _r(FOOTERS).format(d=d, brand=b)
    return (body + ("\n" + foot if foot else "")).strip()


def generate(n: int = 1500, seed: int = 7) -> list[str]:
    random.seed(seed)
    out = set()
    while len(out) < n:
        out.add(_tpl())
    return sorted(out)
