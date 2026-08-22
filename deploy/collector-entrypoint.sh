#!/bin/sh
# collector-entrypoint.sh -- the VM collector's job: keep the store fresh.
#
# Two concurrent loops, one container:
#   background) extract.py pulls newly-closed WALLIX sessions from the Wazuh
#               indexer into sessions.jsonl (append+dedup) every cycle.
#   foreground) api.collector runs CONTINUOUSLY, so its in-memory "seen" set
#               persists across cycles -- it POSTs only unseen closed sessions
#               to pam-scoring:/grafana/ingest, where the model runs once each.
#
# Running the collector in continuous mode (not --once in a loop) is deliberate:
# a fresh --once each cycle would re-scan the whole accumulating file and re-post
# every session, wasting inference. Continuous mode keeps the watermark.
set -eu

OUT="${PAM_OUT_DIR:-/app/feature_extraction/out}"
API="${PAM_API_URL:-http://pam-scoring:8000}"
INTERVAL="${PAM_INTERVAL:-30}"
SINCE="${EXTRACT_SINCE:-1h}"
mkdir -p "$OUT"

echo "[entrypoint] api=$API out=$OUT interval=${INTERVAL}s extract-since=$SINCE"

# --- background: refresh sessions.jsonl from the indexer ---------------------
(
  while true; do
    python feature_extraction/extract.py \
        --source indexer --index archives \
        --since "$SINCE" --out-dir "$OUT" \
      || echo "[entrypoint] extract failed (indexer unreachable?); retry next cycle"
    sleep "$INTERVAL"
  done
) &
EXTRACT_PID=$!

# clean shutdown: kill the extract loop when the collector exits
trap 'kill "$EXTRACT_PID" 2>/dev/null || true' EXIT INT TERM

# --- foreground: continuous ingest (PID 1) ----------------------------------
exec python -m api.collector \
    --api "$API" \
    --sessions "$OUT/sessions.jsonl" \
    --interval "$INTERVAL"
