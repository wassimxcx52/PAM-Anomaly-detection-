#!/usr/bin/env python3
"""
train.py -- the unsupervised track: KMeans and IsolationForest, fitted on BENIGN
ONLY, judged on real sessions.

    generated benign (5000)  ──fit──►  model
    generated attacks (882)  ──────►  held out entirely, scored as a control
    real eval (256)          ──────►  HEADLINE

WHY ONE-CLASS AT ALL, GIVEN THE SUPERVISED MODELS EXIST
-------------------------------------------------------
A supervised model can only recognise attacks that resemble its training
attacks, and this project's training attacks are synthetic: 0 of 882 generated
attack sessions contain no unseen command, so the supervised pair is partly
learning "the attack corpus is a different corpus". The unsupervised pair never
sees an attack at all. It learns the benign region and scores distance from it,
so it cannot inherit that particular bias -- which is why it stays in the
comparison even if it loses on precision@k.

The cost is the mirror image: a one-class detector has no way to learn that some
deviations are harmless, so everything unusual is suspicious.

WHAT IT IS FITTED ON
--------------------
label == "benign" rows of features_train.csv, and nothing else. In particular
the rarity columns are consumed AS ALREADY COMPUTED -- cross-fitted by
transform.py. Refitting a command profile here would score every training
session against a profile built from itself, which is the leak documented in
docs/session_2026-08-15_command_rarity.md sec 3 (CV PR-AUC 1.0000, 64 eval
sessions tied at one score).

DIRECTIONALITY, A KNOWN AND DELIBERATE IMPRECISION
--------------------------------------------------
Both detectors measure distance from normal in every direction, but only the
upper tail is actually suspicious here: long commands, high variety, rare
vocabulary. A session that is MORE routine than routine -- short, repetitive,
entirely familiar -- is a scripted maintenance job, and both models will spend
part of the alert budget on it. ECOD/COPOD allow one-sided scoring and would fix
this; they are out of scope for this comparison. Recorded, not worked around.

THRESHOLD
---------
Taken as a percentile of the TRAINING distance distribution, never fitted on the
eval set. It only produces the confusion matrix -- the comparison itself is
rank-based (precision@k), so the threshold choice does not move the headline.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))          # .../hps/ml/unsupervised
ROOT = os.path.dirname(os.path.dirname(HERE))              # .../hps

sys.path.insert(0, ROOT)
from ml.evaluation import comparison_table, evaluate, report_baselines  # noqa: E402
from ml.feature_gate import leaked, model_features  # noqa: E402
from ml.persistence import save as save_bundle  # noqa: E402

OUT_DIR = os.path.join(ROOT, "feature_extraction", "out")
TRAIN = os.path.join(OUT_DIR, "features_train.csv")
EVAL = os.path.join(OUT_DIR, "features_eval_real.csv")
PROFILE = os.path.join(OUT_DIR, "command_profile.json")
SCORED = os.path.join(OUT_DIR, "features_eval_real_unsupervised.csv")
RESULTS = os.path.join(ROOT, "ml", "results_unsupervised.csv")
BUNDLES = os.path.join(ROOT, "ml", "bundles")

THRESHOLD_PCT = 99


def fit_kmeans(X_train: np.ndarray, clusters: int, seed: int):
    """Distance to the nearest centroid as the anomaly score.

    Several clusters rather than one: benign behaviour is not a single blob --
    an admin's session and an auditor's session are both normal and sit in
    different places, and one centroid would put the midpoint between them at
    distance zero, which is where nothing actually lives.
    """
    model = KMeans(n_clusters=clusters, n_init=10, random_state=seed)
    model.fit(X_train)
    return model, lambda X: np.min(model.transform(X), axis=1)


def fit_iforest(X_train: np.ndarray, trees: int, seed: int):
    """Negated score_samples, so larger is more anomalous for every model here.

    contamination is left at its default because it only sets IsolationForest's
    own binary threshold; the comparison is rank-based and score_samples is
    unaffected by it.
    """
    model = IsolationForest(n_estimators=trees, random_state=seed, n_jobs=-1)
    model.fit(X_train)
    return model, lambda X: -model.score_samples(X)


def main() -> int:
    ap = argparse.ArgumentParser(description="unsupervised bake-off (KMeans, IForest)")
    ap.add_argument("--train", default=TRAIN)
    ap.add_argument("--eval", dest="eval_path", default=EVAL)
    ap.add_argument("--clusters", type=int, default=4,
                    help="KMeans clusters; 4 mirrors the four personas")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--threshold-pct", type=float, default=THRESHOLD_PCT,
                    help="percentile of the TRAINING scores used as the alert "
                         "threshold (confusion matrix only)")
    ap.add_argument("--drop", default="",
                    help="comma-separated features to drop after gating")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=SCORED)
    ap.add_argument("--results", default=RESULTS)
    ap.add_argument("--profile", default=PROFILE,
                    help="command_profile.json to embed in the saved bundles")
    ap.add_argument("--bundles", default=BUNDLES,
                    help="directory for deployable scoring bundles")
    args = ap.parse_args()

    train_df = pd.read_csv(args.train)
    eval_df = pd.read_csv(args.eval_path)

    features = model_features(
        train_df, eval_df,
        drop=[c.strip() for c in args.drop.split(",") if c.strip()])
    if not features:
        raise SystemExit("no features survived the gate")
    if leaked(features):
        raise SystemExit(f"leak columns reached the feature set: {leaked(features)}")

    # ---- benign only. The attacks in features_train.csv are a control set. ----
    benign = train_df[train_df["label"] == "benign"]
    attacks = train_df[train_df["label"] == "attack"]
    print(f"\n[fit] {len(benign)} benign sessions, {len(features)} features "
          f"({len(attacks)} generated attacks held out as a control)")

    scaler = StandardScaler().fit(benign[features])
    X_train = scaler.transform(benign[features])
    X_eval = scaler.transform(eval_df[features])

    y_eval = (eval_df["label"] == "attack").astype(int).to_numpy()

    report_baselines(eval_df, y_eval)

    profile = json.load(open(args.profile, encoding="utf-8"))

    rows, scored = [], eval_df.copy()
    for name, fit in (("KMeans", lambda: fit_kmeans(X_train, args.clusters, args.seed)),
                      ("IsolationForest", lambda: fit_iforest(X_train, args.trees, args.seed))):
        model, score_fn = fit()

        train_scores = score_fn(X_train)
        threshold = np.percentile(train_scores, args.threshold_pct)

        # Control: generated attacks the model never saw. A model that cannot
        # separate these from its own training benign will not separate real
        # ones either, and that is a modelling failure rather than a domain gap.
        attack_scores = score_fn(scaler.transform(attacks[features]))
        print(f"\n[{name}] train p{args.threshold_pct:g} threshold = {threshold:.4f}; "
              f"held-out generated attacks above it: "
              f"{(attack_scores > threshold).mean():.1%}")

        eval_scores = score_fn(X_eval)
        row = evaluate(name, eval_df, y_eval, eval_scores,
                       (eval_scores > threshold).astype(int))
        rows.append(row)

        scored[f"{name.lower()}_score"] = eval_scores
        scored[f"{name.lower()}_pred"] = (eval_scores > threshold).astype(int)

        path = save_bundle(
            os.path.join(args.bundles, f"{name.lower()}.joblib"),
            model=model, scaler=scaler, features=features, profile=profile,
            threshold=float(threshold), model_name=name, track="unsupervised",
            metrics=row)
        print(f"[bundle] {path}")

    print(f"\n\n{'#' * 62}\n# UNSUPERVISED COMPARISON\n{'#' * 62}")
    table = comparison_table(rows)
    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))

    scored.to_csv(args.out, index=False)
    # Full metrics, not the printed subset -- see the note in supervised/train.py.
    pd.DataFrame(rows).to_csv(args.results, index=False)
    print(f"\n[out] scored eval -> {args.out}")
    print(f"[out] comparison   -> {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
