#!/usr/bin/env python3
"""
evaluation.py -- one scoring report, shared by every model in the bake-off.

Four models are compared (KMeans, IsolationForest, RandomForest, LightGBM) and
they are trained on different data: the unsupervised pair fits on BENIGN ONLY,
the supervised pair fits on the labelled mix. That is exactly the situation in
which a bake-off silently stops being a comparison -- if each script computes
its own metrics, a difference in the numbers can be a difference in how they
were measured. So every model is scored here, on the same eval set, through the
same functions.

WHAT IS REPORTED, AND WHY IT IS NOT ACCURACY
--------------------------------------------
At a 19.1% base rate, calling everything benign scores 80.9% accuracy. The
headline is precision@k, with k the SOC's alert budget: of the k sessions an
analyst actually has time to open, how many were real attacks.

THREE SLICES, ALWAYS REPORTED TOGETHER
--------------------------------------
  headline          all 256 real sessions
  minus p_admin     p_admin is 100% attack and bastionsvc 100% benign on real
                    eval -- a collection artifact, not a behaviour. Any model
                    that scores p_admin high gets those 22 attacks free, so the
                    honest number excludes them.
  flagless          the real attacks tripping NO keyword flag. These are
                    invisible to wallix_rules.xml by construction, so they are
                    the population that justifies ML over the rule layer. A
                    model that wins the headline and loses here has not earned
                    deployment.

A SCORE IS A RANKING, NOT A DECISION
------------------------------------
Every model here emits a continuous score in a different, incomparable unit
(distance to a centroid, isolation depth, class probability). Only the RANKING
is comparable across models, which is why precision@k and PR-AUC carry the
comparison and the 0.5-threshold confusion matrix is reported for context only.
Binary predictions come from each model's own threshold convention.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)

K_BUDGETS = [10, 25, 50]

# See module docstring: a collection artifact, excluded from the honest number.
ARTIFACT_ACCOUNT = "p_admin"

FLAG_FEATURES = ["flag_cred_access", "flag_privesc", "flag_persistence",
                 "flag_log_tamper", "flag_recon", "flag_exfil"]


def precision_at_k(y_true: np.ndarray, score: np.ndarray, k: int) -> tuple:
    """(hits, precision@k, recall@k) over the top-k by score.

    Ties are broken by the stable sort's original order rather than at random.
    Worth knowing when reading the number: a model whose score saturates can
    produce a large tie block, in which case precision@k is measuring the tie,
    not the ranking. Check `distinct scores` in the header when a result looks
    too clean.
    """
    order = np.argsort(-score, kind="stable")[:k]
    hits = int(y_true[order].sum())
    return hits, hits / k, hits / max(1, int(y_true.sum()))


def report(name: str, y_true: np.ndarray, y_pred: np.ndarray,
           score: np.ndarray, quiet: bool = False) -> dict:
    """Print one slice's metrics and return them for the comparison table."""
    n_attacks = int(y_true.sum())
    if not quiet:
        print(f"\n{'=' * 62}\n{name}\n{'=' * 62}")
        print(f"{len(y_true)} sessions | {n_attacks} attack "
              f"({y_true.mean():.1%} base rate) | "
              f"{len(np.unique(score))} distinct scores")

    if n_attacks == 0 or n_attacks == len(y_true):
        if not quiet:
            print("  single-class slice -- metrics undefined, skipping")
        return {}

    metrics = {
        "n": len(y_true),
        "attacks": n_attacks,
        "roc_auc": roc_auc_score(y_true, score),
        "pr_auc": average_precision_score(y_true, score),
        "accuracy": accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
    }
    for k in K_BUDGETS:
        if k <= len(y_true):
            hits, prec, rec = precision_at_k(y_true, score, k)
            metrics[f"p@{k}"] = prec
            metrics[f"r@{k}"] = rec

    if quiet:
        return metrics

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    print("\n--- CONFUSION MATRIX (each model's own threshold) ---")
    print("                 pred benign   pred attack")
    print(f"true benign      {tn:>11}   {fp:>11}")
    print(f"true attack      {fn:>11}   {tp:>11}")

    print("\n--- METRICS ---")
    print(f"Accuracy          : {metrics['accuracy']:.4f}"
          f"   (all-benign would score {1 - y_true.mean():.4f})")
    print(f"Balanced accuracy : {metrics['balanced_accuracy']:.4f}")
    print(f"Precision (attack): {metrics['precision']:.4f}")
    print(f"Recall    (attack): {metrics['recall']:.4f}")
    print(f"ROC-AUC           : {metrics['roc_auc']:.4f}")
    print(f"PR-AUC (avg prec) : {metrics['pr_auc']:.4f}")

    print("\n--- PRECISION@K (the SOC-budget metric) ---")
    print("   k   hits   precision@k   recall@k")
    for k in K_BUDGETS:
        if k <= len(y_true):
            hits, prec, rec = precision_at_k(y_true, score, k)
            print(f"{k:>4}   {hits:>4}   {prec:>11.4f}   {rec:>8.4f}")

    return metrics


def flagless_mask(eval_df: pd.DataFrame) -> np.ndarray:
    """Sessions tripping no keyword flag -- what the rule layer cannot see."""
    present = [c for c in FLAG_FEATURES if c in eval_df.columns]
    if not present:
        return np.zeros(len(eval_df), dtype=bool)
    return eval_df[present].fillna(0).max(axis=1).to_numpy() == 0


def rule_baseline(eval_df: pd.DataFrame, y_true: np.ndarray) -> dict:
    """The rule layer's own precision/recall -- the bar ML has to clear."""
    present = [c for c in FLAG_FEATURES if c in eval_df.columns]
    if not present:
        return {}
    fired = eval_df[present].fillna(0).max(axis=1).to_numpy().astype(int)
    missed = int(((y_true == 1) & (fired == 0)).sum())
    return {
        "precision": precision_score(y_true, fired, zero_division=0),
        "recall": recall_score(y_true, fired, zero_division=0),
        "missed": missed,
    }


def evaluate(model_name: str, eval_df: pd.DataFrame, y_true: np.ndarray,
             score: np.ndarray, y_pred: np.ndarray) -> dict:
    """The full three-slice report for one model. Returns a flat row for the
    cross-model comparison table."""
    print(f"\n\n{'#' * 62}\n# {model_name}\n{'#' * 62}")

    headline = report(f"{model_name} -- HEADLINE (all real eval sessions)",
                      y_true, y_pred, score)

    row = {"model": model_name,
           **{f"headline_{k}": v for k, v in headline.items()}}

    if "account" in eval_df.columns:
        artifact = ((eval_df["account"] == ARTIFACT_ACCOUNT).to_numpy()
                    & (y_true == 1))
        if artifact.any():
            keep = ~artifact
            clean = report(f"{model_name} -- minus the {ARTIFACT_ACCOUNT} "
                           f"artifact ({int(artifact.sum())} attacks excluded)",
                           y_true[keep], y_pred[keep], score[keep])
            row.update({f"clean_{k}": v for k, v in clean.items()})

    no_flag = flagless_mask(eval_df)
    n_flagless = int(((y_true == 1) & no_flag).sum())
    if n_flagless:
        slice_mask = no_flag | (y_true == 0)
        decisive = report(f"{model_name} -- DECISIVE: benign + the {n_flagless} "
                          f"attacks with NO keyword flag",
                          y_true[slice_mask], y_pred[slice_mask], score[slice_mask])
        row.update({f"flagless_{k}": v for k, v in decisive.items()})

        ranks = pd.Series(score).rank(ascending=False, method="min").to_numpy()
        hit_ranks = sorted(int(r) for r in ranks[(y_true == 1) & no_flag])
        print(f"\nRanks of the flagless attacks in the {len(y_true)}-session "
              f"queue: {hit_ranks}")
        row["flagless_worst_rank"] = hit_ranks[-1]

    return row


def comparison_table(rows: list, columns: list | None = None) -> pd.DataFrame:
    """Side-by-side across models, on the numbers that decide deployment."""
    columns = columns or [
        "model",
        "headline_pr_auc", "headline_p@10", "headline_p@25",
        "clean_pr_auc", "clean_p@10",
        "flagless_roc_auc", "flagless_p@25", "flagless_worst_rank",
    ]
    frame = pd.DataFrame(rows)
    return frame[[c for c in columns if c in frame.columns]]
