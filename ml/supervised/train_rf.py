#!/usr/bin/env python3
"""
train_rf.py -- Random Forest on the generated dataset, judged on real sessions.

    generated (5882, 85:15)  --80/20-->  fit  +  generated holdout  [CONTROL]
    real eval (256, 49 attacks)          ---------------------->    [HEADLINE]

WHY THE TWO EVALUATION SETS ARE BOTH REQUIRED
---------------------------------------------
The generated holdout is drawn from the same distribution the model was fitted
on, so it measures "did the forest learn its training distribution". Real eval
measures "does that transfer to sessions WALLIX actually captured". The gap
between them is the domain gap, and it is the single most important number this
script produces: a high holdout score with a low real score means the generator,
not the model, is what needs work. Reporting only the holdout would look
excellent and mean nothing (CLAUDE.md sec 10: generated trains, real judges).

WHAT THE FOREST IS ALLOWED TO SEE
---------------------------------
ml/feature_gate.py, shared with the unsupervised track. The short version:
persona/account/ip_source/target_* are label proxies and stay out; the 6 IP and
3 temporal features are constant on real eval and are gated out; flag_* is held
back as the rule-layer baseline rather than fed in, or the forest simply
re-derives wallix_rules.xml and precision@k becomes a measurement of the rules.

Five features survive. That is not a limitation of this script -- it is the lab
constraint (one login user, one client IP, one collection window) showing up
where it actually bites.

WHY class_weight="balanced" AND NOT SMOTE
-----------------------------------------
CLAUDE.md sec 11 lists SMOTE. imbalanced-learn is not installed here, and at
85:15 the imbalance is mild enough that re-weighting the impurity criterion does
the same job without synthesising feature-space points that correspond to no
real session. --smote is wired for the comparison if the package is added.

THE NUMBER THAT MATTERS
-----------------------
Not accuracy -- at a 19% base rate, calling everything benign scores 81%.
precision@k (k = the SOC's alert budget) is the headline, and the decisive slice
is the real attacks that trip NO keyword flag: the population wallix_rules.xml
structurally cannot see. If the forest ranks those above benign, ML earns its
place over the rule layer. If it does not, the five features are not enough and
command-vocabulary rarity is the next build, not more trees.
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))          # .../hps/ml/supervised
ROOT = os.path.dirname(os.path.dirname(HERE))              # .../hps

sys.path.insert(0, ROOT)
from ml.feature_gate import FLAG_FEATURES, leaked, model_features  # noqa: E402
OUT_DIR = os.path.join(ROOT, "feature_extraction", "out")
TRAIN = os.path.join(OUT_DIR, "features_train.csv")
EVAL = os.path.join(OUT_DIR, "features_eval_real.csv")
SCORED = os.path.join(OUT_DIR, "features_eval_real_rf.csv")

K_BUDGETS = [10, 25, 50]

# Real attacks run through p_admin are a collection artifact: p_admin is 100%
# attack and bastionsvc 100% benign on real eval, so any model that happens to
# score those sessions high gets them free, with no behavioural detection.
# Reported separately rather than silently included.
ARTIFACT_ACCOUNT = "p_admin"


def load(path: str, what: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise SystemExit(f"missing {what}: {path}")
    return pd.read_csv(path)


def precision_at_k(y_true: np.ndarray, score: np.ndarray, k: int) -> tuple[int, float, float]:
    order = np.argsort(-score, kind="stable")[:k]
    hits = int(y_true[order].sum())
    total = max(1, int(y_true.sum()))
    return hits, hits / k, hits / total


def report(name: str, y_true: np.ndarray, y_pred: np.ndarray,
           score: np.ndarray) -> dict:
    print(f"\n{'=' * 62}\n{name}\n{'=' * 62}")
    print(f"{len(y_true)} sessions | {int(y_true.sum())} attack "
          f"({y_true.mean():.1%} base rate)")

    if y_true.sum() == 0 or y_true.sum() == len(y_true):
        print("  single-class slice -- metrics undefined, skipping")
        return {}

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    print("\n--- CONFUSION MATRIX (threshold 0.5) ---")
    print("                 pred benign   pred attack")
    print(f"true benign      {tn:>11}   {fp:>11}")
    print(f"true attack      {fn:>11}   {tp:>11}")

    print("\n--- METRICS ---")
    print(f"Accuracy          : {accuracy_score(y_true, y_pred):.4f}"
          f"   (all-benign would score {1 - y_true.mean():.4f})")
    print(f"Balanced accuracy : {balanced_accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision (attack): {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"Recall    (attack): {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"ROC-AUC           : {roc_auc_score(y_true, score):.4f}")
    print(f"PR-AUC (avg prec) : {average_precision_score(y_true, score):.4f}")

    print("\n--- CLASSIFICATION REPORT ---")
    print(classification_report(y_true, y_pred, target_names=["benign", "attack"],
                                zero_division=0))

    print("--- PRECISION@K (the SOC-budget metric) ---")
    print("   k   hits   precision@k   recall@k")
    for k in K_BUDGETS:
        if k > len(y_true):
            continue
        hits, prec, rec = precision_at_k(y_true, score, k)
        print(f"{k:>4}   {hits:>4}   {prec:>11.4f}   {rec:>8.4f}")

    return {"pr_auc": average_precision_score(y_true, score),
            "roc_auc": roc_auc_score(y_true, score)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Random Forest on generated, judged on real")
    ap.add_argument("--train", default=TRAIN, help="generated features CSV")
    ap.add_argument("--eval", dest="eval_path", default=EVAL, help="real eval features CSV")
    ap.add_argument("--with-flags", action="store_true",
                    help="feed flag_* to the model -- measures the rule-circularity, "
                         "does not make the result better")
    ap.add_argument("--drop", default="",
                    help="comma-separated features to drop after gating "
                         "(e.g. duration_sec_feat)")
    ap.add_argument("--trees", type=int, default=400)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--min-leaf", type=int, default=2,
                    help="min_samples_leaf; >1 keeps the forest from carving out "
                         "single-session leaves in a 5-dimensional space")
    ap.add_argument("--smote", action="store_true",
                    help="oversample the attack class instead of re-weighting "
                         "(requires imbalanced-learn)")
    ap.add_argument("--holdout", type=float, default=0.2,
                    help="generated fraction held out as the same-distribution control")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=SCORED)
    args = ap.parse_args()

    train_df = load(args.train, "training features")
    eval_df = load(args.eval_path, "real eval features")

    features = model_features(
        train_df, eval_df,
        include_flags=args.with_flags,
        drop=[c.strip() for c in args.drop.split(",") if c.strip()],
    )
    if not features:
        raise SystemExit("no features survived the gate")
    if leaked(features):
        raise SystemExit(f"leak columns reached the feature set: {leaked(features)}")

    y_train_all = (train_df["label"] == "attack").astype(int).to_numpy()
    y_eval = (eval_df["label"] == "attack").astype(int).to_numpy()

    X_train, X_hold, y_train, y_hold = train_test_split(
        train_df[features], y_train_all, test_size=args.holdout,
        stratify=y_train_all, random_state=args.seed)

    if args.smote:
        try:
            from imblearn.over_sampling import SMOTE
        except ImportError:
            raise SystemExit("--smote needs: pip install imbalanced-learn")
        X_train, y_train = SMOTE(random_state=args.seed).fit_resample(X_train, y_train)
        class_weight = None
        print(f"[smote] resampled to {np.bincount(y_train)}")
    else:
        class_weight = "balanced"

    forest = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_leaf,
        class_weight=class_weight,
        n_jobs=-1,
        random_state=args.seed,
    )
    forest.fit(X_train, y_train)
    print(f"\n[fit] {len(X_train)} sessions, {len(features)} features, "
          f"{args.trees} trees, class_weight={class_weight}")

    cv = cross_val_score(forest, X_train, y_train, cv=StratifiedKFold(5, shuffle=True,
                         random_state=args.seed), scoring="average_precision")
    print(f"[cv]  5-fold PR-AUC on generated train: {cv.mean():.4f} +/- {cv.std():.4f}")

    # ---- control: same distribution as training ----
    hold_score = forest.predict_proba(X_hold)[:, 1]
    control = report("CONTROL -- generated holdout (same distribution as fit)",
                     y_hold, (hold_score >= 0.5).astype(int), hold_score)

    # ---- headline: real sessions, never trained on ----
    eval_score = forest.predict_proba(eval_df[features])[:, 1]
    eval_pred = (eval_score >= 0.5).astype(int)
    real = report("HEADLINE -- real eval sessions (generated trains, real judges)",
                  y_eval, eval_pred, eval_score)

    if control and real:
        print(f"\n>>> DOMAIN GAP: PR-AUC {control['pr_auc']:.4f} (generated) -> "
              f"{real['pr_auc']:.4f} (real), "
              f"a drop of {control['pr_auc'] - real['pr_auc']:.4f}")
        print("    A large drop indicts the generator, not the forest.")

    # ---- headline minus the account artifact ----
    if "account" in eval_df.columns:
        artifact = (eval_df["account"] == ARTIFACT_ACCOUNT) & (y_eval == 1)
        if artifact.any():
            keep = ~artifact.to_numpy()
            report(f"HEADLINE minus the {ARTIFACT_ACCOUNT} artifact "
                   f"({int(artifact.sum())} attacks excluded)",
                   y_eval[keep], eval_pred[keep], eval_score[keep])

    # ---- the decisive slice: attacks the rule layer cannot see ----
    flags_present = [c for c in FLAG_FEATURES if c in eval_df.columns]
    if flags_present:
        no_flag = eval_df[flags_present].fillna(0).max(axis=1).to_numpy() == 0
        flagless_attacks = int(((y_eval == 1) & no_flag).sum())
        print(f"\n{'=' * 62}\nDECISIVE SLICE -- the {flagless_attacks} real attacks "
              f"that trip NO keyword flag\n{'=' * 62}")
        print("These are invisible to wallix_rules.xml by construction. Ranking them\n"
              "above benign is what justifies ML over the rule layer.")

        rule_baseline = eval_df[flags_present].fillna(0).max(axis=1).to_numpy()
        print(f"\nRule-layer baseline (any flag = alert):")
        print(f"  precision {precision_score(y_eval, rule_baseline, zero_division=0):.4f}"
              f"  recall {recall_score(y_eval, rule_baseline, zero_division=0):.4f}"
              f"  -- and it misses all {flagless_attacks} by definition")

        # Rank the flagless attacks against benign only: how far up the queue do
        # the sessions the rules cannot see actually get?
        slice_mask = no_flag | (y_eval == 0)
        if flagless_attacks:
            report("Forest on {benign + flagless attacks} only",
                   y_eval[slice_mask], eval_pred[slice_mask], eval_score[slice_mask])

            ranks = pd.Series(eval_score).rank(ascending=False, method="min").to_numpy()
            hit_ranks = sorted(int(r) for r in ranks[(y_eval == 1) & no_flag])
            print(f"Ranks of the flagless attacks in the full {len(y_eval)}-session "
                  f"queue: {hit_ranks}")

    # ---- what the forest actually used ----
    print(f"\n{'=' * 62}\nFEATURE IMPORTANCE\n{'=' * 62}")
    impurity = pd.Series(forest.feature_importances_, index=features)
    perm = permutation_importance(forest, eval_df[features], y_eval,
                                  n_repeats=20, random_state=args.seed,
                                  scoring="average_precision", n_jobs=-1)
    table = pd.DataFrame({
        "impurity (on generated)": impurity.round(4),
        "permutation (on real)": pd.Series(perm.importances_mean, index=features).round(4),
    }).sort_values("permutation (on real)", ascending=False)
    print(table.to_string())
    print("\nImpurity importance is measured on the training distribution and is "
          "biased\ntoward high-cardinality features; the permutation column is what "
          "the feature\nis worth on real sessions, and is the one to quote.")

    scored = eval_df.copy()
    scored["rf_score"] = eval_score
    scored["rf_pred"] = eval_pred
    scored.to_csv(args.out, index=False)
    print(f"\n[out] scored eval -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
