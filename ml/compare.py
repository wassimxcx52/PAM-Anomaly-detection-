#!/usr/bin/env python3
"""
compare.py -- the four-model table for the report.

Merges results_unsupervised.csv and results_supervised.csv. Run the two training
scripts first; this only assembles what they wrote, so the table can never
disagree with the runs that produced it.

READING THE TABLE
-----------------
  headline_pr_auc   all 256 real sessions
  clean_pr_auc      minus the 22 p_admin attacks (a collection artifact -- see
                    ml/evaluation.py). This is the honest headline.
  flagless_*        the 16 real attacks tripping no keyword flag, invisible to
                    wallix_rules.xml. A model that wins above and loses here has
                    not earned deployment.
  domain_gap        supervised only: generated holdout PR-AUC minus real PR-AUC.
                    Large means the generator, not the model, is the problem.

The supervised and unsupervised tracks are NOT interchangeable at equal score.
The supervised pair trains on synthetic attacks and 0 of 882 of those contain no
unseen command, so part of what they learn is that the attack corpus is a
different corpus. The unsupervised pair never sees an attack. Prefer the
unsupervised model on a tie, and say why in the report.
"""

from __future__ import annotations

import os

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = {"unsupervised": os.path.join(HERE, "results_unsupervised.csv"),
           "supervised": os.path.join(HERE, "results_supervised.csv")}
OUT = os.path.join(HERE, "results_all.csv")

COLUMNS = ["track", "model", "headline_pr_auc", "headline_p@10", "headline_p@25",
           "clean_pr_auc", "clean_p@10", "flagless_roc_auc", "flagless_p@25",
           "flagless_worst_rank", "domain_gap"]


def main() -> int:
    frames = []
    for track, path in SOURCES.items():
        if not os.path.exists(path):
            print(f"[warn] missing {path} -- run ml/{track}/train.py first")
            continue
        frame = pd.read_csv(path)
        frame.insert(0, "track", track)
        frames.append(frame)

    if not frames:
        raise SystemExit("no results to compare")

    table = pd.concat(frames, ignore_index=True)
    table = table[[c for c in COLUMNS if c in table.columns]]
    table = table.sort_values("clean_pr_auc", ascending=False)

    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    table.to_csv(OUT, index=False)
    print(f"\n[out] {OUT}")

    best = table.iloc[0]
    print(f"\nBest by clean_pr_auc: {best['model']} ({best['track']}), "
          f"{best['clean_pr_auc']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
