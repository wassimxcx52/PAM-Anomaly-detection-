#!/usr/bin/env python3
"""
score.py -- score sessions with a saved bundle. The inference end of the pipeline.

    python ml/score.py --sessions feature_extraction/out/eval_real.jsonl \
                       --bundle ml/bundles/isolationforest.joblib --top 10

Takes sessions.jsonl-shaped input -- whatever extract.py produced from live
WALLIX telemetry -- and emits a ranked alert queue. This is the same path the
demo runs, and the same path a FastAPI /score endpoint would call.

WHY FEATURES ARE RECOMPUTED HERE RATHER THAN READ FROM A CSV
------------------------------------------------------------
Serving must not depend on the training-time feature CSVs existing. Sessions
arrive as JSON from extract.py, so score.py runs transform.py's own
build_features against the bundle's embedded command_profile -- the same code
that produced the training features, so there is no second implementation to
drift.

THE TWO THINGS THAT WOULD SILENTLY GIVE WRONG ANSWERS
-----------------------------------------------------
  * feature ORDER. The estimator indexes columns positionally. The bundle stores
    the exact list and this module reindexes to it rather than trusting whatever
    order the frame happens to have.
  * a MISSING feature. If the gate kept a column that this input cannot produce,
    the right move is to fail loudly -- scoring against a silently-imputed
    column produces a number that looks fine and means nothing.

RANKING, NOT A VERDICT
----------------------
The output is ordered by score. The bundle's threshold produces the `alert`
column, but the threshold is a convention (a training percentile, or 0.5 for the
supervised models), not a tuned operating point. Read the ranking; treat the
flag as advisory until a threshold is set from the eval set at an accepted
false-positive rate.
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))          # .../hps/ml
ROOT = os.path.dirname(HERE)                               # .../hps

sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "feature_extraction"))
from ml.persistence import describe, load  # noqa: E402

DEFAULT_BUNDLE = os.path.join(HERE, "bundles", "isolationforest.joblib")

DISPLAY = ["session_id", "user", "account", "target_hostname", "session_start",
           "command_count", "cmd_oov_rate", "cmd_max_surprisal"]


def score_sessions(sessions_path: str, bundle: dict) -> pd.DataFrame:
    """Sessions JSONL -> the same frame, plus `score` and `alert`, ranked."""
    import command_profile
    from transform import add_rarity_features, build_features

    features = build_features(sessions_path)
    scorer = command_profile.Scorer(bundle["command_profile"])
    features = add_rarity_features(features, scorer)

    missing = [c for c in bundle["features"] if c not in features.columns]
    if missing:
        raise SystemExit(
            f"input cannot produce {len(missing)} feature(s) the bundle needs: "
            f"{missing}. Scoring against imputed columns would return a number "
            f"that looks valid and is not.")

    # Positional indexing in the estimator: reindex, never trust frame order.
    X = features[bundle["features"]]
    if X.isna().any().any():
        bad = X.columns[X.isna().any()].tolist()
        raise SystemExit(f"NaN in feature(s) {bad} -- these sessions carry no "
                         f"command telemetry (RDP?) and cannot be scored by "
                         f"this bundle.")

    if bundle.get("scaler") is not None:
        X = bundle["scaler"].transform(X)

    model = bundle["model"]
    if hasattr(model, "predict_proba"):                     # supervised
        scores = model.predict_proba(X)[:, 1]
    elif hasattr(model, "score_samples"):                   # IsolationForest
        scores = -model.score_samples(X)
    else:                                                   # KMeans
        scores = model.transform(X).min(axis=1)

    features["score"] = scores
    threshold = bundle.get("threshold")
    features["alert"] = (scores > threshold).astype(int) if threshold is not None else 0
    return features.sort_values("score", ascending=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="score sessions with a saved bundle")
    ap.add_argument("--sessions", required=True,
                    help="sessions.jsonl from extract.py")
    ap.add_argument("--bundle", default=DEFAULT_BUNDLE)
    ap.add_argument("--top", type=int, default=10,
                    help="how many of the highest-scoring sessions to print")
    ap.add_argument("--out", default="", help="write the full ranked frame here")
    args = ap.parse_args()

    bundle = load(args.bundle)
    print(f"[bundle] {describe(bundle)}\n")

    ranked = score_sessions(args.sessions, bundle)
    print(f"[scored] {len(ranked)} sessions, "
          f"{int(ranked['alert'].sum())} above threshold "
          f"({bundle['threshold']:.4f})\n")

    columns = [c for c in DISPLAY if c in ranked.columns] + ["score", "alert"]
    if "label" in ranked.columns:
        columns.insert(1, "label")          # present only when scoring a labelled set

    print(f"--- TOP {args.top} ---")
    with pd.option_context("display.width", 200, "display.max_columns", None):
        print(ranked.head(args.top)[columns].to_string(index=False))

    if args.out:
        ranked.to_csv(args.out, index=False)
        print(f"\n[out] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
