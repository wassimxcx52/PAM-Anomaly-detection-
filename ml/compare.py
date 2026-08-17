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

import json
import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Same as the two train.py scripts: this is run as `python ml/compare.py`, so the
# repo root is not on the path and `import ml.evaluation` would fail.
sys.path.insert(0, ROOT)
SOURCES = {"unsupervised": os.path.join(HERE, "results_unsupervised.csv"),
           "supervised": os.path.join(HERE, "results_supervised.csv")}
EVAL_REAL = os.path.join(ROOT, "feature_extraction", "out", "eval_real.jsonl")
OUT = os.path.join(HERE, "results_all.csv")

COLUMNS = ["track", "model", "headline_pr_auc", "headline_precision",
           "headline_recall", "headline_p@10", "headline_p@25",
           "clean_pr_auc", "clean_p@10", "flagless_roc_auc", "flagless_p@25",
           "flagless_worst_rank", "domain_gap"]


def rule_layer_row() -> dict | None:
    """The deployed Wazuh rules as one more row in the comparison table.

    The rule layer emits no score, so it has no PR-AUC and no precision@k -- it
    is a binary verdict, not a ranking. Those cells stay empty on purpose: an
    imputed 0 would sort the rules to the bottom of a table they are meant to set
    the bar for. Precision and recall are directly comparable to the model rows'
    headline_precision/headline_recall, which is the comparison the report makes.
    """
    if not os.path.exists(EVAL_REAL):
        print(f"[warn] {EVAL_REAL} missing -- no rule-layer baseline row")
        return None

    from ml.evaluation import rule_id_baseline  # local: keeps import cost off

    rows = [json.loads(line) for line in open(EVAL_REAL, encoding="utf-8")
            if line.strip()]
    frame = pd.DataFrame(rows)
    y_true = (frame["label"] == "attack").astype(int).to_numpy()
    baseline = rule_id_baseline(frame, y_true)
    if not baseline:
        print("[warn] eval_real.jsonl has no fired_rule_ids -- rebuild it with "
              "ml/unsupervised/build_eval_set.py to get the rule-layer row")
        return None

    return {"track": "baseline",
            "model": "Wazuh rules (deployed)",
            "headline_precision": baseline["precision"],
            "headline_recall": baseline["recall"]}


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

    # The baseline goes last, after the sort: it has no clean_pr_auc to sort by,
    # and it reads as the line the models above it have to beat.
    baseline = rule_layer_row()
    if baseline is not None:
        table = pd.concat([table, pd.DataFrame([baseline])], ignore_index=True)

    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}",
                          na_rep="--"))
    table.to_csv(OUT, index=False)
    print(f"\n[out] {OUT}")

    models = table[table["track"] != "baseline"]
    best = models.iloc[0]
    print(f"\nBest by clean_pr_auc: {best['model']} ({best['track']}), "
          f"{best['clean_pr_auc']:.4f}")
    if baseline is not None:
        print(f"Rule layer          : precision "
              f"{baseline['headline_precision']:.4f}, recall "
              f"{baseline['headline_recall']:.4f} -- the bar ML has to clear")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
