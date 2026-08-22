#!/usr/bin/env python3
"""
seed_demo.py -- DEMO ONLY. Re-time real sessions onto the recent past so the
Grafana time picker has data in every window (Last 15m / 1h / 12h / 24h).

WHY THIS EXISTS
---------------
The dashboard filters on each session's REAL session_start. The collected
template sessions were captured on fixed dates (e.g. 2026-08-03..07), so a
"now-relative" window like Last 12h is legitimately empty. That is correct
behaviour, not a bug -- a SOC panel is anchored to when activity happened.

For a live demo you want every interval populated. This script reads the real
sessions, spreads them EVENLY across [now - span, now] (preserving each
session's own duration and command content), and ingests them with those
synthetic timestamps. Newest sessions land within the last minute, so even
Last 5m shows something.

INTEGRITY NOTE
--------------
This fabricates timestamps and must never be used to produce evaluation data or
report figures -- it exists purely so the dashboard demo is not empty. The real
collector (api/collector.py) preserves true capture times. Consistent with the
project's rule that any synthetic metadata is documented as such.

Usage
-----
  python -m api.seed_demo --api http://localhost:8000 --span 24h
  python -m api.seed_demo --api http://localhost:8000 --span 48h --sessions <path>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SESSIONS = os.path.join(REPO, "feature_extraction", "out", "sessions.jsonl")


def parse_span(text: str) -> float:
    """'24h' -> seconds. Accepts s/m/h/d suffix, default hours."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", text.strip().lower())
    if not m:
        raise ValueError(f"bad span: {text!r} (use e.g. 90m, 24h, 2d)")
    val = float(m.group(1))
    return val * {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 3600}[m.group(2)]


def iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def read_closed(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            s = json.loads(line)
            if not s.get("session_end"):
                continue
            if s.get("session_end_is_estimated") or s.get("duration_sec_is_estimated"):
                continue
            rows.append(s)
    return rows


def retime(sessions: list[dict], span_sec: float) -> list[dict]:
    """Spread sessions evenly across [now - span, now], keeping each duration."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - int(span_sec * 1000)
    n = len(sessions)
    step = (now_ms - start_ms) / max(1, n - 1) if n > 1 else 0
    out = []
    for i, s in enumerate(sessions):
        new_start = int(start_ms + i * step)
        dur = float(s.get("duration_sec") or 0)
        new_end = new_start + int(dur * 1000)
        s2 = dict(s)
        s2["session_start"] = iso(new_start)
        s2["session_end"] = iso(new_end)
        # clear the estimated flags so the record reads as a genuine closed one
        for k in ("session_start_is_estimated", "session_end_is_estimated",
                  "duration_sec_is_estimated"):
            s2.pop(k, None)
        out.append(s2)
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api", default=os.environ.get("PAM_API_URL", "http://localhost:8000"))
    p.add_argument("--sessions", default=DEFAULT_SESSIONS)
    p.add_argument("--span", default="24h", help="spread window ending now (e.g. 90m, 24h, 2d)")
    args = p.parse_args(argv)

    span = parse_span(args.span)
    sessions = read_closed(args.sessions)
    if not sessions:
        print(f"[seed_demo] no closed sessions in {args.sessions}", file=sys.stderr)
        return 1
    retimed = retime(sessions, span)

    sent = 0
    for i in range(0, len(retimed), 200):
        chunk = retimed[i:i + 200]
        r = requests.post(f"{args.api.rstrip('/')}/grafana/ingest",
                          json={"sessions": chunk}, timeout=60)
        r.raise_for_status()
        sent += r.json().get("ingested", 0)
    print(f"[seed_demo] re-timed {sent} sessions across the last {args.span} "
          f"(ending now). Every window up to Last {args.span} now has data.")
    print("[seed_demo] NOTE: timestamps are synthetic -- demo only, not for eval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
