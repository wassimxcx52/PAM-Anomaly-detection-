#!/usr/bin/env python3
"""
build_persona_weights.py -- turn the curated persona command corpus into a
weighted sampling vocabulary, calibrated against REAL benign sessions.

Why this exists
---------------
persona_commands_curated.json is a deduplicated SET (800-1300 unique commands
per persona) with no frequency information. Sampling from it uniformly would make
almost every command in a generated session distinct, inflating
unique_command_ratio and command_entropy far above what real sessions show
(real benign: 7-16 command families, ~8-10 commands/session -- see
real_benign_calibration.json). Those two features are exactly what the
unsupervised anomaly detector keys on, so uniform sampling would make generated
BENIGN traffic look anomalous and poison the density model.

SHARED substrate (not benign-only). This weighted vocabulary is consumed by the
BENIGN generator, which produces the training set for the unsupervised track AND
the 85% majority class of the supervised track. Build it once; both tracks use it.

Weighting model -- a calibrated mixture
--------------------------------------
Per persona, a sampled command is drawn from one of two pools:

  core  (mass = 1 - TAIL_MASS):  command families actually OBSERVED in real
        benign sessions for this persona, weighted by their observed frequency.
        This anchors the head of the distribution to real role behaviour
        (dev -> git/python3, dba -> du/ps, ...). Full-command CONTENT with args
        comes from the curated corpus (any curated command sharing that family
        head); if the corpus has none, the real command string itself is used.

  tail  (mass = TAIL_MASS):  curated commands whose family head was NEVER seen
        in real sessions -- plausible-but-rare role activity. Uniform within.

TAIL_MASS is the diversity knob: raise it for more varied sessions, lower it to
hug the observed core. Default 0.15 was chosen so generated unique_command_ratio
/ command_entropy overlap the real distributions (validate with
--report after generating sessions).

Output: persona_weighted.json
  { persona: {
      "session_length": {"median": int, "observed": [int,...]},
      "tail_mass": float,
      "commands": [ {"command": str, "head": str, "weight": float,
                     "pool": "core"|"tail", "in_real": bool}, ... ]  # weights sum ~1
  } }

Inputs:
  commands_dataset/persona_commands_curated.json   (curated SET, breadth)
  commands_dataset/real_benign_calibration.json    (real head_freq + lengths)
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import statistics

from command_safety import filter_corpus

DATA = "commands_dataset"
CURATED = f"{DATA}/persona_commands_curated.json"
CALIB = f"{DATA}/real_benign_calibration.json"
OUT = f"{DATA}/persona_weighted.json"

DEFAULT_TAIL_MASS = 0.15


def head_of(command: str) -> str:
    """Command family = first whitespace token, ignoring a leading env-var
    assignment or `sudo`. Matches the granularity of the real calibration."""
    toks = command.split()
    if not toks:
        return command
    i = 0
    while i < len(toks) and ("=" in toks[i] or toks[i] == "sudo"):
        i += 1
    return toks[i] if i < len(toks) else toks[-1]


def build_persona(commands: list[str], head_freq: dict[str, int],
                  tail_mass: float) -> list[dict]:
    # index curated commands by family head
    by_head: dict[str, list[str]] = collections.defaultdict(list)
    for c in commands:
        by_head[head_of(c)].append(c)

    core_total = sum(head_freq.values()) or 1
    rows: list[dict] = []

    # --- core pool: observed families, weighted by observed frequency ---
    for head, freq in head_freq.items():
        members = by_head.get(head)
        head_prob = (1 - tail_mass) * (freq / core_total)
        if members:
            per = head_prob / len(members)
            for cmd in members:
                rows.append({"command": cmd, "head": head, "weight": per,
                             "pool": "core", "in_real": True})
        else:
            # observed in real but absent from curated corpus: keep the family
            # alive by synthesising a bare invocation of the head itself.
            rows.append({"command": head, "head": head, "weight": head_prob,
                         "pool": "core", "in_real": True})

    # --- tail pool: curated families never seen in real, uniform ---
    tail_cmds = [c for c in commands if head_of(c) not in head_freq]
    if tail_cmds:
        per = tail_mass / len(tail_cmds)
        for cmd in tail_cmds:
            rows.append({"command": cmd, "head": head_of(cmd), "weight": per,
                         "pool": "tail", "in_real": False})

    # renormalise (guards against empty tail redistributing mass)
    total = sum(r["weight"] for r in rows) or 1
    for r in rows:
        r["weight"] /= total
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tail-mass", type=float, default=DEFAULT_TAIL_MASS,
                    help="probability mass on plausible-but-rare tail commands")
    ap.add_argument("--report", action="store_true",
                    help="print per-persona diversity summary")
    args = ap.parse_args()

    # Same filter the collector applies to its benign filler. Not for safety --
    # nothing here is executed -- but for PARITY: a command the collector can
    # never emit must not be in the generated vocabulary either, or the gap
    # becomes a domain marker in ml/unsupervised/train.py's gate.
    curated = filter_corpus(json.load(open(CURATED, encoding="utf-8")),
                            label="persona_weights")
    calib = json.load(open(CALIB, encoding="utf-8"))

    out = {}
    for persona, commands in curated.items():
        head_freq = {k: int(v) for k, v in calib.get(persona, {}).get("head_freq", {}).items()}
        lengths = calib.get(persona, {}).get("session_lengths", [])
        rows = build_persona(commands, head_freq, args.tail_mass)
        out[persona] = {
            "session_length": {
                "median": int(statistics.median(lengths)) if lengths else 6,
                "observed": lengths,
            },
            "tail_mass": args.tail_mass,
            "commands": rows,
        }

    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    print(f"tail_mass={args.tail_mass}  -> {OUT}")
    for persona, blk in out.items():
        rows = blk["commands"]
        core = [r for r in rows if r["pool"] == "core"]
        tail = [r for r in rows if r["pool"] == "tail"]
        core_mass = sum(r["weight"] for r in core)
        no_curated = sum(1 for r in core if r["in_real"] and r["command"] == r["head"])
        print(f"  {persona:8s} {len(rows):5d} cmds  core={len(core):3d} "
              f"(mass {core_mass:.2f})  tail={len(tail):4d}  "
              f"synthesised-heads={no_curated}")
        if args.report:
            top = sorted(core, key=lambda r: -r["weight"])[:6]
            print("           top core:", ", ".join(f"{r['head']}({r['weight']:.3f})" for r in top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
