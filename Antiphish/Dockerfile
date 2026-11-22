# AntiPhish server image: web app + forward-to-scan worker.
# The ML model is trained INSIDE the image so library versions always match.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
    DATA_DIR=/app/data \
    ANTIPHISH_MODEL_PATH=/app/data/models/model.joblib \
    CORPUS_PATH=/app/corpus/corpus.csv

# libglib: opencv (QR codes) | libarchive-tools: bsdtar for .rar archives
RUN apt-get update && apt-get install -y --no-install-recommends libglib2.0-0 libarchive-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt

COPY antiphish ./antiphish
COPY webapp ./webapp
COPY scripts ./scripts
COPY train.py evaluate.py NOTICE.md ./
COPY deploy/entrypoint.sh /entrypoint.sh

# Build corpus (public data, ~110MB download) + train. If the download fails the
# image still builds with the small starter model (check the build log!).
RUN mkdir -p data corpus models-baked \
    && (python scripts/build_corpus.py || echo "WARNING: corpus download failed - starter model only") \
    && if [ -f data/corpus.csv ]; then mv data/corpus.csv corpus/corpus.csv; fi \
    && ANTIPHISH_MODEL_PATH=/app/models-baked/model.joblib python train.py \
    && rm -rf data/raw data/*

RUN useradd --create-home --uid 1000 app && mkdir -p /app/data && chown -R app:app /app/data \
    && chmod +x /entrypoint.sh
# entrypoint starts as root, fixes /app/data ownership, then drops to "app" (setpriv)
VOLUME ["/app/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=4).status==200 else 1)" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
