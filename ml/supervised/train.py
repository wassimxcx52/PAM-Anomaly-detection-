#!/usr/bin/env python3
"""
train.py -- the supervised track: RandomForest and LightGBM, trained on the
labelled generated set, judged on real sessions.

    generated (5882, 85:15)  --80/20-->  fit  +  generated holdout  [CONTROL]
    real eval (256)                      ---------------------->    [HEADLINE]

Replaces the earlier train_rf.py; metrics now come from ml/evaluation.py so the
four models in the bake-off are measured by identical code.

WHY THE GENERATED HOLDOUT IS REPORTED EVERY TIME
------------------------------------------------
It is drawn from the distribution the model was fitted on, so it answers "did
the model learn its training data". Real eval answers "does that transfer to
sessions WALLIX actually captured". The GAP between them is the number that
matters: a high holdout score with a low real score indicts the generator, not
the model, and reporting only the holdout would look excellent and mean nothing.

The gap has already caught two real defects -- generator miscalibration
(avg_command_length fitted to truncated data) and a closed benign vocabulary --
neither of which was visible in the headline number alone.

WHAT THIS TRACK CANNOT ESCAPE
-----------------------------
It learns from synthetic attacks. 0 of 882 generated attack sessions contain no
unseen command, so part of what it learns is "the attack corpus is a different
corpus" rather than "this behaviour is hostile". The unsupervised track exists
precisely because it does not inherit that. Whichever model wins on
precision@k, this limitation belongs in the report.

class_weight / is_unbalance rather than SMOTE: at 85:15 the imbalance is mild,
and re-weighting the loss does the same job without synthesising feature-space
points that correspond to no session that could exist.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))          # .../hps/ml/supervised
ROOT = os.path.dirname(os.path.dirname(HERE))              # .../hps

sys.path.insert(0, ROOT)
from ml.evaluation import comparison_table, evaluate, report, rule_baseline  # noqa: E402
from ml.feature_gate import leaked, model_features  # noqa: E402
from ml.persistence import save as save_bundle  # noqa: E402

OUT_DIR = os.path.join(ROOT, "feature_extraction", "out")
TRAIN = os.path.join(OUT_DIR, "features_train.csv")
EVAL = os.path.join(OUT_DIR, "features_eval_real.csv")
PROFILE = os.path.join(OUT_DIR, "command_profile.json")
SCORED = os.path.join(OUT_DIR, "features_eval_real_supervised.csv")
RESULTS = os.path.join(ROOT, "ml", "results_supervised.csv")
BUNDLES = os.path.join(ROOT, "ml", "bundles")


def build_models(args, n_features: int) -> dict:
    """min_samples_leaf / min_child_samples above 1 on purpose: in a space this
    small a tree will otherwise carve out single-session leaves, which is
    memorisation rather than a decision boundary."""
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=args.trees,
            min_samples_leaf=args.min_leaf,
            class_weight="balanced",
            n_jobs=-1,
            random_state=args.seed,
        )
    }
    try:
        from lightgbm import LGBMClassifier
    except ImportError:
        print("[warn] lightgbm not installed -- skipping "
              "(pip install lightgbm)")
        return models

    models["LightGBM"] = LGBMClassifier(
        n_estimators=args.trees,
        min_child_samples=max(5, args.min_leaf * 5),
        # Boosting drives the loss to zero on separable data; capping depth and
        # keeping the leaf count small is what stops it fitting the generator's
        # artifacts rather than the behaviour.
        num_leaves=min(31, 2 ** max(2, n_features // 2)),
        max_depth=args.max_depth or -1,
        learning_rate=0.05,
        is_unbalance=True,
        n_jobs=-1,
        random_state=args.seed,
        verbose=-1,
    )
    return models


def main() -> int:
    ap = argparse.ArgumentParser(description="supervised bake-off (RF, LightGBM)")
    ap.add_argument("--train", default=TRAIN)
    ap.add_argument("--eval", dest="eval_path", default=EVAL)
    ap.add_argument("--with-flags", action="store_true",
                    help="feed flag_* to the models -- measures the rule "
                         "circularity, does not make the result better")
    ap.add_argument("--drop", default="",
                    help="comma-separated features to drop after gating")
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--min-leaf", type=int, default=2)
    ap.add_argument("--holdout", type=float, default=0.2,
                    help="generated fraction held out as the same-distribution control")
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
        include_flags=args.with_flags,
        drop=[c.strip() for c in args.drop.split(",") if c.strip()])
    if not features:
        raise SystemExit("no features survived the gate")
    if leaked(features):
        raise SystemExit(f"leak columns reached the feature set: {leaked(features)}")

    y_all = (train_df["label"] == "attack").astype(int).to_numpy()
    y_eval = (eval_df["label"] == "attack").astype(int).to_numpy()

    X_train, X_hold, y_train, y_hold = train_test_split(
        train_df[features], y_all, test_size=args.holdout,
        stratify=y_all, random_state=args.seed)
    print(f"\n[fit] {len(X_train)} sessions, {len(features)} features, "
          f"{len(X_hold)} held out as control")

    baseline = rule_baseline(eval_df, y_eval)
    if baseline:
        print(f"[baseline] rule layer (any flag = alert): "
              f"precision {baseline['precision']:.4f}  "
              f"recall {baseline['recall']:.4f}  "
              f"-- blind to {baseline['missed']} attacks by construction")

    profile = json.load(open(args.profile, encoding="utf-8"))

    rows, scored = [], eval_df.copy()
    for name, model in build_models(args, len(features)).items():
        model.fit(X_train, y_train)

        cv = cross_val_score(model, X_train, y_train,
                             cv=StratifiedKFold(5, shuffle=True, random_state=args.seed),
                             scoring="average_precision")
        print(f"\n[{name}] 5-fold CV PR-AUC on generated train: "
              f"{cv.mean():.4f} +/- {cv.std():.4f}")
        if cv.mean() > 0.999:
            print(f"[{name}] NOTE: training is perfectly separable. The attack "
                  f"corpus is disjoint from the benign one, so this is expected "
                  f"and is a generator limitation, not a model result.")

        hold_score = model.predict_proba(X_hold)[:, 1]
        control = report(f"{name} -- CONTROL: generated holdout",
                         y_hold, (hold_score >= 0.5).astype(int), hold_score)

        eval_score = model.predict_proba(eval_df[features])[:, 1]
        eval_pred = (eval_score >= 0.5).astype(int)
        row = evaluate(name, eval_df, y_eval, eval_score, eval_pred)

        if control and row.get("headline_pr_auc") is not None:
            gap = control["pr_auc"] - row["headline_pr_auc"]
            row["control_pr_auc"] = control["pr_auc"]
            row["domain_gap"] = gap
            print(f"\n>>> DOMAIN GAP [{name}]: PR-AUC {control['pr_auc']:.4f} "
                  f"(generated) -> {row['headline_pr_auc']:.4f} (real), "
                  f"drop {gap:.4f}")

        perm = permutation_importance(model, eval_df[features], y_eval,
                                      n_repeats=20, random_state=args.seed,
                                      scoring="average_precision", n_jobs=-1)
        importance = pd.Series(perm.importances_mean, index=features)
        print(f"\n--- {name}: permutation importance on REAL sessions ---")
        print(importance.sort_values(ascending=False).round(4).to_string())

        rows.append(row)
        scored[f"{name.lower()}_score"] = eval_score
        scored[f"{name.lower()}_pred"] = eval_pred

        # 0.5 is the estimator's own convention, not a tuned operating point.
        # It is stored so the demo path is reproducible, but the deployment
        # threshold should come from the eval set at an accepted FP rate.
        path = save_bundle(
            os.path.join(args.bundles, f"{name.lower()}.joblib"),
            model=model, features=features, profile=profile, threshold=0.5,
            model_name=name, track="supervised", metrics=row)
        print(f"[bundle] {path}")

    print(f"\n\n{'#' * 62}\n# SUPERVISED COMPARISON\n{'#' * 62}")
    table = comparison_table(
        rows, columns=["model", "control_pr_auc", "headline_pr_auc", "domain_gap",
                       "headline_p@10", "headline_p@25", "clean_pr_auc",
                       "flagless_roc_auc", "flagless_worst_rank"])
    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))

    scored.to_csv(args.out, index=False)
    # Write every metric, not the printed subset: compare.py chooses its own
    # columns, and a table that silently lacks them shows NaN for a model that
    # was in fact measured.
    pd.DataFrame(rows).to_csv(args.results, index=False)
    print(f"\n[out] scored eval -> {args.out}")
    print(f"[out] comparison   -> {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
