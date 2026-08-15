#!/usr/bin/env python3
"""
build_training_set.py -- merge generated_benign.jsonl + generated_attacks.jsonl
into the single labelled training set both ML tracks read.

ONE MATRIX, TWO TRACKS (docs/decision_log.md)
---------------------------------------------
This file is not "the supervised dataset". It is the shared substrate:

  unsupervised  fits on label=="benign" only, and the attack rows are held back
                as a scoring set -- a one-class detector that has seen an attack
                is no longer one-class.
  supervised    trains on all rows with `label` as the target.

Each track filters this file; neither regenerates it. Building the benign side
once is what keeps the two tracks comparable -- if they trained on separately
generated benign data, a difference in their scores could be a difference in
their data.

RATIO
-----
benign:attack = 85:15, locked (CLAUDE.md sec 10). The mix is enforced HERE by
subsetting, not by hoping the two generators emitted the right counts, so the
ratio is exact and any shortfall is reported rather than silently accepted.

SHUFFLE, DO NOT SORT
--------------------
Rows are interleaved by a seeded shuffle so the file order carries no label
information. Chronological order is NOT used: transform.py's cross-session
features sort by session_start themselves, and a train/test split taken off the
top of a time-sorted file would put every early session in train.

NEVER MIXED IN
--------------
feature_extraction/out/eval_real.jsonl. Generated data trains, real injected
sessions judge (CLAUDE.md sec 10, evaluation integrity). This script reads only
the two generated files and will refuse anything carrying split != "train".
"""

from __future__ import annotations

import argparse
import json
import os
import random
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BENIGN = os.path.join(HERE, "out", "generated_benign.jsonl")
ATTACKS = os.path.join(HERE, "out", "generated_attacks.jsonl")
OUT = os.path.join(HERE, "out", "generated_train.jsonl")

# Columns that exist only on attack rows. Written onto benign rows too, as
# explicit empties, so the merged file has one stable schema -- otherwise pandas
# fills them with NaN and "composition is missing" becomes a perfect label.
ATTACK_ONLY_DEFAULTS = {
    "mitre": [],
    "composition": "benign",
    "attack_command_count": 0,
    "campaign_id": None,
}


def load(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="merge benign + attack into one training set")
    ap.add_argument("--benign", default=BENIGN)
    ap.add_argument("--attacks", default=ATTACKS)
    ap.add_argument("--attack-share", type=float, default=0.15,
                    help="attack fraction of the combined set (locked at 0.15)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    benign = load(args.benign)
    attacks = load(args.attacks)

    stray = [r for r in benign + attacks if r.get("split") != "train"]
    if stray:
        raise SystemExit(f"{len(stray)} row(s) are not split=train -- refusing to "
                         f"mix evaluation data into the training set")

    # Enforce the ratio by subsetting whichever side is over-supplied.
    share = args.attack_share
    want_attacks = round(len(benign) * share / (1 - share))
    rng = random.Random(args.seed)

    if len(attacks) >= want_attacks:
        attacks = rng.sample(attacks, want_attacks)
    else:
        # Not enough attacks: shrink benign instead of duplicating attack rows.
        # Duplicates would let a model memorise a session it will see again.
        want_benign = round(len(attacks) * (1 - share) / share)
        print(f"[warn] only {len(attacks)} attack sessions available "
              f"({want_attacks} wanted) -- trimming benign to {want_benign} "
              f"to hold the ratio")
        benign = rng.sample(benign, min(len(benign), want_benign))

    rows = benign + attacks
    for row in rows:
        for key, default in ATTACK_ONLY_DEFAULTS.items():
            row.setdefault(key, default() if callable(default) else default)
    rng.shuffle(rows)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    labels = Counter(r["label"] for r in rows)
    personas = Counter(r["persona"] for r in rows)
    attack_personas = Counter(r["persona"] for r in rows if r["label"] == "attack")

    print(f"wrote {len(rows)} sessions -> {args.out}")
    print(f"  labels   : {dict(labels)} "
          f"(attack share {labels['attack'] / len(rows):.1%})")
    print(f"  personas : {dict(sorted(personas.items()))}")
    print(f"  attack by persona: {dict(sorted(attack_personas.items()))}")
    print(f"  users    : {len({r['user'] for r in rows})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
