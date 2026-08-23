# Scoring service for WALLIX privileged-session anomaly detection.
#
# The image ships the FEATURE CODE, not just a pickle. api/main.py computes
# features by calling feature_extraction/transform.py -- the same module that
# built the training matrix -- so a serving-side copy cannot drift from it.
# That is why feature_extraction/ and ml/ are copied in.
#
# Build from the REPO ROOT, not from api/:
#   docker build -f api/Dockerfile -t pam-scoring:1.0 .
#
# The bundle is baked in rather than mounted: an image and the model it serves
# should be one immutable, traceable artifact. Mount a different one at
# /app/bundles and set BUNDLE_PATH to override for testing.

FROM python:3.12-slim

# libgomp is LightGBM's OpenMP runtime -- absent from slim, and its absence
# fails at import time, not at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Requirements first: this layer is cached unless the pins change, so ordinary
# code edits do not trigger a full scikit-learn/LightGBM reinstall.
COPY api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY feature_extraction/ ./feature_extraction/
COPY ml/ ./ml/
COPY api/ ./api/

# The model bundles ship with the repo (ml/bundles/ is tracked) and are copied
# in above. SCORES_DB_PATH defaults here to /data, a dir owned by the runtime
# user so the pam_scores named volume (mounted there) is writable -- a fresh
# named volume inherits the mountpoint's ownership from the image.
ENV BUNDLE_PATH=/app/ml/bundles/isolationforest.joblib \
    SCORES_DB_PATH=/data/scores.db \
    PYTHONPATH=/app:/app/feature_extraction \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 scoring \
    && mkdir -p /data \
    && chown -R scoring /app /data
USER scoring

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
