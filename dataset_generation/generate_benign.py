#!/usr/bin/env python3
"""
generate_benign.py -- sample persona_weighted.json into synthetic benign sessions.

Output schema is IDENTICAL to extract.py's sessions.jsonl (session_id, account,
commands, session_start/end, duration_sec, ...) so transform.py consumes generated
and real sessions through the same code path -- the shared-substrate design. Extra
metadata columns (label/source/split/persona) ride along and pass through
transform.py's merge untouched.

SHARED, not benign-only: these sessions are the unsupervised track's training set
AND the 85% benign majority class of the supervised set. Attack sessions slot into
the same schema later; only the train-time filter differs per track.

Realism controls (calibrated against real_benign_calibration.json):
  --stickiness  P(a command re-uses one already issued this session) instead of a
                fresh draw. Real users repeat commands; without this, weighted
                sampling over ~800 distinct curated strings inflates
                unique_command_ratio above real. This is the argument-diversity
                knob that complements build_persona_weights' family-level --tail-mass.
  session length  bootstrapped from each persona's observed real lengths.

Metadata honesty (CLAUDE.md sec 10): timestamps are synthetic business-hours;
client_ip is a per-persona PLACEHOLDER until the real IP pool is provided -- the
IP-based contextual features stay disabled until then. real_ts/real_ip are absent
because these sessions never ran through WALLIX; they are declared source=generated.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

DATA = "commands_dataset"
WEIGHTED = f"{DATA}/persona_weighted.json"
OUT = "out/generated_benign.jsonl"

# persona -> vaulted account (CLAUDE.md sec 6)
ACCOUNT = {"dev": "p_dev", "dba": "p_dba", "auditor": "p_audit", "admin": "bastionsvc"}
TARGET_IP = "192.168.1.74"
TARGET_HOST = "debian-lab"
# placeholder home IP per persona until the real pool arrives
PLACEHOLDER_IP = {"dev": "10.0.0.11", "dba": "10.0.0.12",
                  "auditor": "10.0.0.13", "admin": "10.0.0.14"}


def sample_length(observed: list[int], median: int, rng: random.Random) -> int:
    if observed:
        return max(1, rng.choice(observed))
    return max(1, median)


def sample_commands(vocab: list[dict], length: int, stickiness: float,
                    rng: random.Random) -> list[str]:
    cmds = [r["command"] for r in vocab]
    weights = [r["weight"] for r in vocab]
    issued: list[str] = []
    for _ in range(length):
        if issued and rng.random() < stickiness:
            issued.append(rng.choice(issued))          # re-run something already typed
        else:
            issued.append(rng.choices(cmds, weights=weights, k=1)[0])
    return issued


def business_hours_start(rng: random.Random, day_span: int) -> datetime:
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    day = base + timedelta(days=rng.randint(0, day_span))
    # keep to Mon-Fri
    while day.weekday() >= 5:
        day += timedelta(days=1)
    hour = rng.randint(8, 17)
    minute = rng.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=rng.randint(0, 59))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-persona", type=int, default=200,
                    help="sessions to generate per persona")
    ap.add_argument("--stickiness", type=float, default=0.0,
                    help="P(re-use a command already issued this session)")
    ap.add_argument("--day-span", type=int, default=30,
                    help="spread synthetic timestamps over N days")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    weighted = json.load(open(WEIGHTED, encoding="utf-8"))

    n = 0
    with open(args.out, "w", encoding="utf-8") as fh:
        for persona, blk in weighted.items():
            vocab = blk["commands"]
            observed = blk["session_length"]["observed"]
            median = blk["session_length"]["median"]
            for _ in range(args.per_persona):
                length = sample_length(observed, median, rng)
                commands = sample_commands(vocab, length, args.stickiness, rng)
                start = business_hours_start(rng, args.day_span)
                dur = sum(rng.uniform(0.4, 1.3) for _ in commands)
                end = start + timedelta(seconds=dur)
                rec = {
                    "session_id": f"gen-{uuid.UUID(int=rng.getrandbits(128)).hex[:24]}",
                    "user": "test-ssh",
                    "account": ACCOUNT.get(persona, persona),
                    "client_ip": PLACEHOLDER_IP.get(persona),
                    "target_ip": TARGET_IP,
                    "target_hostname": TARGET_HOST,
                    "protocol": "SSH",
                    "session_start": start.isoformat(),
                    "session_end": end.isoformat(),
                    "duration_sec": round(dur, 2),
                    "commands": commands,
                    "event_types": ["KBD_INPUT"] * len(commands),
                    "raw_event_count": len(commands),
                    "file_transfer_bytes": 0,
                    # --- ride-along metadata (shared substrate) ---
                    "label": "benign",
                    "tactics": [],
                    "source": "generated",
                    "split": "train",
                    "persona": persona,
                    "ip_is_placeholder": True,
                    "ts_is_synthetic": True,
                }
                fh.write(json.dumps(rec) + "\n")
                n += 1

    print(f"wrote {n} benign sessions -> {args.out} "
          f"(stickiness={args.stickiness}, {args.per_persona}/persona)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
