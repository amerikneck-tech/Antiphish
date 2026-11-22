# Third-party data notices

## Jose Nazario phishing corpus (training data for models/model.joblib)
Phishing email corpus 2015-2025 by Jose Nazario — https://monkey.org/~jose/phishing/
Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).
Used to train the statistical text classifier. Raw emails are not redistributed
with this project; `scripts/build_corpus.py` downloads them from the source.

## SpamAssassin public corpus (legitimate "ham" training data)
https://spamassassin.apache.org/old/publiccorpus/ — copyright of message text
remains with the original senders. Used only to train a statistical model; the
raw messages are not redistributed. **Review with legal counsel before
commercial release**, or replace with your own consented legitimate-mail data.
