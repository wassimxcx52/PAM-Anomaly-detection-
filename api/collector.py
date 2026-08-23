#!/usr/bin/env python3
"""
collector.py -- the periodic driver that keeps the Grafana store fresh.

This is the piece that makes the dashboard "real-time" without ever putting the
model on Grafana's refresh path:

    every INTERVAL seconds:
        read newly-CLOSED sessions since the last watermark
        POST them once to /grafana/ingest   (model runs here, exactly once each)
        advance the watermark

Grafana then polls the cheap read endpoints as fast as you like (5s/10s); the
model is touched only when a new session actually appears.

WATERMARK / IDEMPOTENCY
-----------------------
Two guards stop double-work and double-alerting:
  * a session is only ingested once its `session_end` is set (extract.py emits
    a session while it is still open with estimated timestamps -- scoring those
    gives wrong features, see CLAUDE.md 7). We skip `*_is_estimated` sessions.
  * we remember every session_id already sent, and only forward unseen ones.
    /grafana/ingest is upsert-idempotent anyway, so a re-send is harmless.

SOURCE
------
Default source is the pipeline's sessions.jsonl (what extract.py writes). To go
fully live, point --sessions at the file your scheduled `extract.py` refreshes,
or replace read_new_sessions() with a direct extract call.

Usage
-----
  python -m api.collector --api http://127.0.0.1:8000 \
      --sessions feature_extraction/out/sessions.jsonl --interval 30
  python -m api.collector --once        # single pass, for cron
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Iterable

import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SESSIONS = os.path.join(REPO, "feature_extraction", "out", "sessions.jsonl")


def read_sessions(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def is_closed(session: dict) -> bool:
    """Only score sessions that have genuinely closed. extract.py flags estimated
    lifecycle fields; an estimated end means the session was still open when pulled."""
    if session.get("session_end_is_estimated") or session.get("duration_sec_is_estimated"):
        return False
    return bool(session.get("session_end"))


def read_new_sessions(path: str, seen: set[str]) -> list[dict]:
    out = []
    for s in read_sessions(path):
        sid = s.get("session_id")
        if not sid or sid in seen or not is_closed(s):
            continue
        out.append(s)
    return out


# Scoring cost is per-session (feature extraction + TF-IDF novelty + model), so
# a big chunk can exceed the HTTP timeout on a slow host and never complete --
# the collector then retries the same oversized chunk forever. Keep chunks small
# and the timeout generous; both are tunable via env for slow/fast environments.
CHUNK_SIZE = int(os.environ.get("PAM_INGEST_CHUNK", "25"))
INGEST_TIMEOUT = int(os.environ.get("PAM_INGEST_TIMEOUT", "300"))


def ingest(api: str, sessions: list[dict]) -> dict:
    resp = requests.post(f"{api.rstrip('/')}/grafana/ingest",
                         json={"sessions": sessions}, timeout=INGEST_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def run_once(api: str, path: str, seen: set[str]) -> int:
    new = read_new_sessions(path, seen)
    if not new:
        return 0
    # Ingest in small chunks; mark each chunk seen as soon as it succeeds so a
    # later failure never re-sends what already landed (progress is monotonic).
    sent = 0
    for i in range(0, len(new), CHUNK_SIZE):
        chunk = new[i:i + CHUNK_SIZE]
        result = ingest(api, chunk)
        for s in chunk:
            seen.add(s["session_id"])
        sent += result.get("ingested", 0)
    print(f"[collector] ingested {sent} new session(s); "
          f"{len(seen)} total tracked", flush=True)
    return sent


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api", default=os.environ.get("PAM_API_URL", "http://127.0.0.1:8000"))
    p.add_argument("--sessions", default=os.environ.get("PAM_SESSIONS", DEFAULT_SESSIONS))
    p.add_argument("--interval", type=float, default=float(os.environ.get("PAM_INTERVAL", "30")))
    p.add_argument("--once", action="store_true", help="one pass then exit (for cron)")
    args = p.parse_args(argv)

    seen: set[str] = set()
    print(f"[collector] api={args.api} sessions={args.sessions} "
          f"interval={args.interval}s once={args.once}", flush=True)

    if args.once:
        run_once(args.api, args.sessions, seen)
        return 0

    while True:
        try:
            run_once(args.api, args.sessions, seen)
        except FileNotFoundError:
            print(f"[collector] sessions file not found yet: {args.sessions}", flush=True)
        except requests.RequestException as e:
            print(f"[collector] API error (will retry): {e}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
