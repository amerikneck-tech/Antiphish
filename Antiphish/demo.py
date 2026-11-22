"""CLI demo: analyze sample emails."""
from antiphish.detector import analyze_email

SAMPLES = [
    {
        "name": "PayPal phishing",
        "email": {
            "subject": "Urgent: Your PayPal account has been limited",
            "body": "Dear customer, we detected unauthorized access. Verify your account within 24 hours or it will be closed: http://paypa1-secure-login.tk/verify",
            "sender": "security@paypa1-secure.com",
            "spf": "fail", "dkim": "fail", "dmarc": "fail",
        },
    },
    {
        "name": "CEO BEC scam",
        "email": {
            "subject": "Quick request",
            "body": "I'm in a meeting, can you process a wire transfer to the supplier today? Urgent. Reply to my private address.",
            "sender": "ceo@company-mail.net",
            "reply_to": "ceo.private@gmail.com",
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
        },
    },
    {
        "name": "Legit newsletter",
        "email": {
            "subject": "October product updates and webinar schedule",
            "body": "Hi team, here are the updates for this month. Register for the webinar if interested. Best regards",
            "sender": "newsletter@vendor.com",
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
        },
    },
]

if __name__ == "__main__":
    for s in SAMPLES:
        r = analyze_email(s["email"])
        print("=" * 70)
        print(f"[{s['name']}]  Score: {r['score']}  ->  {r['level']}")
        print("Verdict:", r["verdict"])
        print("ML phishing probability:", r["ml_phishing_probability"])
        for sig in r["signals"][:6]:
            print(f"  - ({sig['weight']}) {sig['signal']}: {sig['detail']}")
