"""Train the production model.

    python scripts/build_corpus.py   # once: download public corpora -> data/corpus.csv
    python train.py                  # train on corpus + starter + data/feedback.csv
"""
import os

from antiphish.config import MODEL_PATH
from antiphish.model import train, save_model, CORPUS_PATH

if __name__ == "__main__":
    if not os.path.exists(CORPUS_PATH):
        print("WARNING: data/corpus.csv not found - training on the small starter set only.\n"
              "         Run: python scripts/build_corpus.py")
    pipe = train()
    os.makedirs(os.path.dirname(os.path.abspath(MODEL_PATH)), exist_ok=True)
    save_model(pipe, MODEL_PATH)
    print(f"Model trained and saved to {MODEL_PATH} (+ .sha256)")
