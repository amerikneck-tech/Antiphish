#!/bin/sh
# Runs as root only long enough to fix volume permissions, then drops to user "app".
set -e
mkdir -p /app/data/models
# docker creates bind-mounted ./data as root -> give it to the app user
chown -R app:app /app/data
if [ ! -f /app/data/models/model.joblib ]; then
  cp /app/models-baked/model.joblib /app/models-baked/model.joblib.sha256 /app/data/models/
  chown app:app /app/data/models/*
  echo "entrypoint: installed baked model into /app/data/models"
fi
exec setpriv --reuid=app --regid=app --init-groups "$@"
