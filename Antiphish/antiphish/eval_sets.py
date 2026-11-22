"""Held-out probe sets - NEVER used for training.

They measure what the public corpora cannot: behaviour on MODERN everyday
mail (newsletters, notifications, receipts) and on 2025-2026 lure styles.
Add your own real examples here over time (anonymized).
"""

MODERN_LEGIT = [
    # newsletters / marketing
    "We have 1200 sneakers ON SALE\nNIKE ADIDAS JORDAN up to 60% off. Free shipping over 50 EUR. Shop now. Unsubscribe | Privacy policy",
    "This FALL Will Bring Some Heat\nNew arrivals from Puma, New Balance and Converse are here. Shop the collection. You are receiving this because you subscribed.",
    "Pocket 20% off the things you love with this coupon until Sunday!\nUse code SAVE20 at checkout on eligible items. Terms apply. Unsubscribe from marketing emails.",
    "Dolce & Gabbana Extra 20% Off\nYour favourite fragrances, now even better value. Limited time. View in browser. Manage preferences.",
    "30% OFF Discount Storm Proxies\nUpgrade your residential proxy plan this week and save 30%. Questions? Reply to this email.",
    "NOVA KOLEKCIJA koja mora biti tvoja!\nPogledaj najnovije modele patika i opreme. Besplatna dostava za porudžbine preko 5000 RSD. Odjava sa liste.",
    "Black Friday starts now\nDoorbuster deals on TVs, laptops and headphones. Prices valid while stocks last. See all deals.",
    "Your weekly digest: 5 stories we think you will like\nRead more on our blog. Update your email preferences or unsubscribe.",
    "Webinar invitation: Cloud cost optimisation best practices\nJoin our engineers on Thursday. Register for free. Can't make it? We'll send the recording.",
    "New Supreme x Nike drop\nThe latest release is live on the marketplace. Place a bid or buy now. Download the app.",
    # notifications
    "Logan mentioned you in Introducing of Coin\nLogan: hey check this out @you. Reply in Discord. Manage notification settings.",
    "You missed messages in Balkan SnaKe\nYou have 14 unread messages. Open Discord to catch up.",
    "New comment on your pull request #482\nmaria-dev commented: looks good, just one nit on line 40. View it on GitHub.",
    "Your Zoom meeting recording is ready\nThe cloud recording for Weekly sync is now available. Share it with participants from your Zoom web portal.",
    "Jane Doe shared a document with you\nQ3 planning notes. Open in Docs. You received this because Jane shared a file with you.",
    "Someone liked your post\nAna and 12 others liked your photo. See activity.",
    "Your verification code is 482913\nEnter this code to finish signing in. If you didn't request it, you can ignore this email.",
    "Security alert: new sign-in on Windows\nWe noticed a new sign-in to your account on a Windows device. If this was you, you don't need to do anything.",
    # transactional
    "Your order has shipped\nOrder #88213 is on its way and should arrive Thursday. Track your package in your account.",
    "Receipt for your payment\nThanks for your purchase. Amount paid 12.99 EUR. Monthly subscription. View invoice in your account settings.",
    "Your booking is confirmed\nCheck-in Friday 15:00, check-out Sunday 11:00. Manage your booking in the app.",
    "Your flight to Belgrade: online check-in is open\nCheck in now to choose your seat. Passenger locator form may be required at destination.",
    "Your data plan will expire soon\nYour 5GB plan expires in 3 days. Top up in the app to stay connected.",
    "We are updating our Client Agreement\nThe updated terms take effect next month. No action is required. Read the full agreement on our website.",
    "Your statement is ready\nYour monthly statement is now available in online banking. For your security we never ask for your password by email.",
    "Password changed\nThe password for your account was changed. If you made this change, no further action is needed.",
    # personal / work
    "Re: dinner on Saturday\nSounds great, see you at 8. I'll book the table.",
    "Minutes from today's meeting\nAttached are the notes and action items. Next sync is Tuesday.",
    "Pozdrav, šaljem ti ponudu\nU prilogu je ponuda koju smo dogovorili. Javi ako treba izmjena.",
    "Invoice 2026-044 for October\nPlease find attached our invoice for consulting services, payment terms 30 days as agreed in the contract.",
]

MODERN_PHISH = [
    "Action required: Microsoft 365 password expires today\nYour password will expire in 2 hours. Keep your current password by signing in here to avoid losing access to your mailbox.",
    "DocuSign: Please review and sign - Payroll adjustment Q4\nYou have received a document to review and sign. REVIEW DOCUMENT. This link expires in 24 hours.",
    "Zoom: You have a missed meeting recording from HR\nSign in with your work account to view the recording shared with you.",
    "Scan the QR code to keep your MFA active\nOur records show your multi-factor authentication must be re-enrolled. Scan the attached code with your phone to continue.",
    "Your mailbox storage is full\nIncoming messages are being held. Verify your account now to release 23 pending messages.",
    "Invoice overdue - final reminder\nPlease remit payment today. Our bank details have changed, use the new account in the attached PDF.",
    "Shared file: Salary_Increase_2026.pdf\nHR has shared a confidential document with you. Log in with your email credentials to view.",
    "Unusual sign-in activity\nWe detected a sign-in attempt from Russia. If this wasn't you, secure your account immediately by confirming your identity.",
    "Your package is held at customs\nA customs fee of 1.99 EUR is required. Pay now or the parcel will be returned to sender.",
    "Device verification required\nGo to microsoft.com/devicelogin and enter code XQ7-PLM2 to keep access to your company account.",
    "Hitno: vaš nalog će biti blokiran\nPotvrdite podatke za e-bankarstvo u roku od 24 sata klikom na link ispod.",
    "Quick favour\nAre you at your desk? I need you to buy 5 gift cards for a client today, I'll reimburse you. Keep this confidential. Sent from my iPhone",
    "Calendar invite: Mandatory compliance training\nAccept the invite and sign in to the training portal with your corporate credentials before Friday.",
    "Netflix: your payment was declined\nUpdate your billing information within 48 hours to avoid suspension of your membership.",
    "Tax refund notification\nYou are eligible for a tax refund of 412.50 EUR. Submit your bank card details to receive the refund.",
]
