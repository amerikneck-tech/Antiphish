"""Feedback-driven retraining.

When the monitor marks a legit email as phishing (false positive) or misses a
real phishing email (false negative), add the (text, label) to data/feedback.csv
and retrain. Over time the model learns YOUR traffic.

CSV format (no header needed, but fine if present):
  "email subject and body text",0        <- 0 = legit
  "email subject and body text",1        <- 1 = phishing

Usage:
  python -m antiphish.learn                 # retrain with current feedback
  python -m antiphish.learn --stats       # show dataset composition
"""
from __future__ import annotations

import csv
import os
import sys

import numpy as np

from .model import train, save_model

from .config import DATA_DIR, MODEL_PATH
FEEDBACK_PATH = os.path.join(DATA_DIR, "feedback.csv")


def load_feedback() -> tuple[list[str], np.ndarray]:
    path = os.path.abspath(FEEDBACK_PATH)
    texts, labels = [], []
    if not os.path.exists(path):
        return texts, np.array([], dtype=int)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 2 or row[0].lower() in ("text", ""):
                continue
            try:
                label = int(row[1].strip())
            except ValueError:
                continue
            if label in (0, 1):
                texts.append(row[0].strip())
                labels.append(label)
    return texts, np.array(labels, dtype=int)


def retrain():
    fb_texts, fb_y = load_feedback()
    if len(fb_texts) == 0:
        print("No feedback yet. Add rows to data/feedback.csv, then re-run.")
    else:
        print(f"Feedback: {len(fb_texts)} samples "
              f"({(fb_y==1).sum()} phishing / {(fb_y==0).sum()} legit) - weighted x5")
    pipe = train()  # corpus.csv + starter + feedback.csv
    os.makedirs(os.path.dirname(os.path.abspath(MODEL_PATH)), exist_ok=True)
    save_model(pipe, os.path.abspath(MODEL_PATH))
    print(f"Model retrained -> {MODEL_PATH}. Restart the monitor / web app to load it.")


if __name__ == "__main__":
    if "--stats" in sys.argv:
        t, y = load_feedback()
        print(f"feedback.csv: {len(t)} rows ({(y==1).sum()} phishing / {(y==0).sum()} legit)")
    else:
        retrain()
