#!/usr/bin/env python3
"""
build_calibration.py -- derive real per-persona benign command statistics from the
REAL collected sessions, for calibrating the synthetic benign generator.

This is the one place dataset_generation reads from the real feature pipeline: it
joins the real ground_truth.jsonl to the real sessions.jsonl (by the `echo TAG:`
marker) and, for each benign persona, records command-family frequencies and
observed session lengths. build_persona_weights.py consumes the output.

CAVEAT (see docs/decision_log.md): the real benign templates use fixed lists of
distinct commands, so their unique_command_ratio is ~1.0 -- an artifact, not human
behaviour. Use these frequencies to anchor WHICH command families are common per
role, NOT to calibrate diversity/repetition (that's generate_benign.py --stickiness,
a documented judgement call).

Output: commands_dataset/real_benign_calibration.json
"""

from __future__ import annotations

import collections
import json
import os
import re
import statistics

# real feature-pipeline outputs live in the sibling feature_extraction/out
REAL_OUT = os.path.join(os.path.dirname(__file__), "..", "feature_extraction", "out")
GROUND_TRUTH = os.path.join(REAL_OUT, "ground_truth.jsonl")
SESSIONS = os.path.join(REAL_OUT, "sessions.jsonl")
OUT = "commands_dataset/real_benign_calibration.json"

TAG_RE = re.compile(r"TAG:(\w+)")


def load_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main() -> int:
    gt = load_jsonl(GROUND_TRUTH)
    sessions = load_jsonl(SESSIONS)

    # index real sessions by the TAG marker embedded in their commands
    by_tag: dict[str, dict] = {}
    for s in sessions:
        for c in (s.get("commands") or []):
            m = TAG_RE.search(c)
            if m:
                by_tag[m.group(1)] = s
                break

    head_freq: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    lengths: dict[str, list] = collections.defaultdict(list)

    for g in gt:
        if g["kind"] != "benign" or g["status"] != "ok":
            continue
        s = by_tag.get(g["session_tag"])
        if not s:
            continue
        persona = g["scenario"]
        n = 0
        for c in (s.get("commands") or []):
            c = c.replace("<NL>", " ").replace("<TAB>", " ").strip()
            if c.startswith("echo TAG:") or c == "exit" or not c:
                continue
            head_freq[persona][c.split()[0]] += 1
            n += 1
        lengths[persona].append(n)

    out = {
        p: {"head_freq": dict(head_freq[p]), "session_lengths": lengths[p]}
        for p in head_freq
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    print(f"-> {OUT}")
    for p in sorted(out):
        med = statistics.median(lengths[p]) if lengths[p] else 0
        print(f"  {p:8s} heads={len(head_freq[p]):2d}  sessions={len(lengths[p]):2d}  len med={med:.0f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
