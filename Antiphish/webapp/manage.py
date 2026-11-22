"""Admin command line.

  python -m webapp.manage create-admin you@example.com
  python -m webapp.manage create-user friend@example.com --credits 100
  python -m webapp.manage credits friend@example.com 200
  python -m webapp.manage reset-password friend@example.com
  python -m webapp.manage list
  python -m webapp.manage export-feedback        # -> data/feedback.csv (then: python -m antiphish.learn)
"""
from __future__ import annotations

import csv
import getpass
import os
import sys

from . import config, db, security

FEEDBACK_CSV = os.path.join(config.DATA_DIR, "feedback.csv")


def _ask_password() -> str:
    pw = os.getenv("NEW_PASSWORD") or ""
    if pw:
        return pw
    while True:
        pw = getpass.getpass("Lozinka (min 10 znakova): ")
        problem = security.password_problems(pw)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Ponovi lozinku: ") != pw:
            print("Lozinke se ne poklapaju.")
            continue
        return pw


def export_feedback() -> int:
    rows = db.unexported_feedback()
    if not rows:
        return 0
    os.makedirs(os.path.dirname(FEEDBACK_CSV), exist_ok=True)
    with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for r in rows:
            w.writerow([r["text"], r["label"]])
    db.mark_exported([r["id"] for r in rows])
    return len(rows)


def main(argv: list[str]):
    if not argv:
        print(__doc__)
        return 1
    cmd, args = argv[0], argv[1:]
    db.init()
    if cmd in ("create-admin", "create-user"):
        if not args:
            print("Navedi email.")
            return 1
        email = args[0]
        credits = int(args[args.index("--credits") + 1]) if "--credits" in args else (
            100000 if cmd == "create-admin" else config.DEFAULT_CREDITS)
        if db.get_user_by_email(email):
            print("Korisnik već postoji.")
            return 1
        db.create_user(email, security.hash_password(_ask_password()), credits,
                       is_admin=(cmd == "create-admin"))
        print(f"Kreiran {'admin' if cmd == 'create-admin' else 'korisnik'} {email} ({credits} kredita).")
    elif cmd == "credits":
        u = db.get_user_by_email(args[0])
        if not u:
            print("Nema korisnika.")
            return 1
        db.set_credits(u["id"], int(args[1]))
        print(f"{args[0]}: {args[1]} kredita.")
    elif cmd == "reset-password":
        u = db.get_user_by_email(args[0])
        if not u:
            print("Nema korisnika.")
            return 1
        db.set_password(u["id"], security.hash_password(_ask_password()))
        print("Lozinka promijenjena.")
    elif cmd == "list":
        for u in db.list_users():
            print(f"{u['id']:3d}  {u['email']:35s} credits={u['credits']:<6d} admin={u['is_admin']} "
                  f"disabled={u['disabled']} scans={u['n_scans']}")
    elif cmd == "export-feedback":
        print(f"{export_feedback()} primjera dodano u {FEEDBACK_CSV}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
