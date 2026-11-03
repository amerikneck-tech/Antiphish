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

from .model import load_dataset, train, save_model, evaluate

FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "feedback.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "model.joblib")


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
    base_texts, base_y = load_dataset()
    fb_texts, fb_y = load_feedback()
    if len(fb_texts) == 0:
        print("No feedback yet. Add rows to data/feedback.csv, then re-run.")
    else:
        print(f"Feedback: {len(fb_texts)} samples "
              f"({(fb_y==1).sum()} phishing / {(fb_y==0).sum()} legit)")
    pipe = train()
    # train() uses only built-in corpus; retrain properly with merged data:
    from .model import build_pipeline
    pipe = build_pipeline()
    pipe.fit(base_texts + fb_texts, np.concatenate([base_y, fb_y]))
    save_model(pipe, os.path.abspath(MODEL_PATH))
    print(f"Model retrained with {len(base_texts) + len(fb_texts)} samples -> models/model.joblib")


if __name__ == "__main__":
    if "--stats" in sys.argv:
        t, y = load_feedback()
        print(f"feedback.csv: {len(t)} rows ({(y==1).sum()} phishing / {(y==0).sum()} legit)")
    else:
        retrain()
