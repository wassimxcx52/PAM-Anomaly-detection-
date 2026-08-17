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

import collections
import re

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

# The rules in wallix_rules.xml that assert "this session did something bad".
# The other reserved IDs are deliberately NOT here and the distinction carries
# the whole measurement: 100500 is the base if_sid anchor and fires on 6228 of
# 7506 events, 100502/100503 are session open/close lifecycle, 100540 suppresses
# GUI polling noise. Counting any of them as a detection yields ~100% recall and
# measures nothing.
DETECTION_RULES = {100510, 100512, 100514, 100516, 100518, 100520,
                   100530, 100532, 100534}


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


def _fired_detection_rule(eval_df: pd.DataFrame) -> np.ndarray | None:
    """Per session: did any DETECTION_RULES rule fire? None if unavailable.

    The column is a list per row (built by build_eval_set.py); it survives a CSV
    round-trip as its repr, so parse defensively rather than assuming a list.
    """
    if "fired_rule_ids" not in eval_df.columns:
        return None

    def hit(value) -> bool:
        if isinstance(value, str):
            found = {int(n) for n in re.findall(r"\d+", value)}
        elif isinstance(value, (list, tuple, set)):
            found = {int(n) for n in value}
        else:
            return False
        return bool(found & DETECTION_RULES)

    return eval_df["fired_rule_ids"].map(hit).to_numpy()


def rule_id_baseline(eval_df: pd.DataFrame, y_true: np.ndarray) -> dict:
    """The DEPLOYED rule layer's precision/recall, from the rule IDs that
    actually fired in Wazuh.

    This is the number the thesis rests on, and it is deliberately kept separate
    from rule_baseline() above. That one measures transform.py's keyword flags --
    a reimplementation of the detection logic, useful because it is available on
    generated sessions too. This one measures wallix_rules.xml as deployed. When
    the two agree, the flag-based slices are validated; if they ever diverge, the
    rules and their proxy have drifted and the proxy is the one to distrust.
    """
    fired = _fired_detection_rule(eval_df)
    if fired is None:
        return {}
    fired = fired.astype(int)
    missed_mask = (y_true == 1) & (fired == 0)

    result = {
        "precision": precision_score(y_true, fired, zero_division=0),
        "recall": recall_score(y_true, fired, zero_division=0),
        "missed": int(missed_mask.sum()),
        "false_positives": int(((y_true == 0) & (fired == 1)).sum()),
        "attacks": int((y_true == 1).sum()),
    }

    # Per-tactic recall. The aggregate hides which tactics the rule layer is
    # blind to, and "6 of the privesc attempts were denied sudo, so no dangerous
    # command ever ran and no rule could fire" is the report's sharpest example.
    if "scenario" in eval_df.columns:
        missed = collections.Counter(
            eval_df.loc[missed_mask, "scenario"].fillna("(none)"))
        totals = collections.Counter(
            eval_df.loc[y_true == 1, "scenario"].fillna("(none)"))
        result["missed_by_scenario"] = dict(missed.most_common())
        result["recall_by_scenario"] = {
            tactic: round((total - missed.get(tactic, 0)) / total, 4)
            for tactic, total in sorted(totals.items())
        }
    return result


def rule_miss_recovery(eval_df: pd.DataFrame, y_true: np.ndarray,
                       score: np.ndarray, budget: int = 50) -> dict:
    """Of the attacks the DEPLOYED rules missed, where does this model rank them?

    This is the project's thesis reduced to one number. Everything else compares
    models to each other; this compares the model to the rule layer on precisely
    the population the rule layer cannot see -- the attacks that fired no
    detection rule at all. A model that scores well everywhere except here has
    added nothing to what Wazuh already does.

    Distinct from the `flagless` slice: that one is defined by transform.py's
    keyword flags (a proxy, available on generated data), this one by the rule
    IDs that actually fired in production.
    """
    fired = _fired_detection_rule(eval_df)
    if fired is None:
        return {}
    missed = (y_true == 1) & ~fired.astype(bool)
    if not missed.any():
        return {}

    # Rank over ALL sessions: an analyst works one queue, not a filtered one.
    order = pd.Series(score).rank(ascending=False, method="min").to_numpy()
    ranks = np.sort(order[missed])

    return {
        "n": int(missed.sum()),
        "in_budget": int((ranks <= budget).sum()),
        "budget": budget,
        "median_rank": float(np.median(ranks)),
        "best_rank": int(ranks[0]),
        "worst_rank": int(ranks[-1]),
    }


def report_baselines(eval_df: pd.DataFrame, y_true: np.ndarray) -> dict:
    """Print both baselines side by side and return them for the results table."""
    flags = rule_baseline(eval_df, y_true)
    rules = rule_id_baseline(eval_df, y_true)

    print(f"\n\n{'#' * 62}\n# RULE LAYER -- the bar ML has to clear\n{'#' * 62}")
    print(f"{'baseline':<28}{'precision':>10}{'recall':>9}{'missed':>8}")
    if rules:
        print(f"{'Wazuh rules (rule_id)':<28}{rules['precision']:>10.4f}"
              f"{rules['recall']:>9.4f}{rules['missed']:>8}")
    if flags:
        print(f"{'keyword-flag proxy':<28}{flags['precision']:>10.4f}"
              f"{flags['recall']:>9.4f}{flags['missed']:>8}")
    if not rules:
        print("  no fired_rule_ids column -- rebuild eval_real.jsonl with "
              "ml/unsupervised/build_eval_set.py to measure the deployed rules")

    if rules.get("recall_by_scenario"):
        print("\n  rule-layer recall by tactic (attacks the rules never saw):")
        print(f"  {'tactic':<16}{'recall':>8}{'missed':>8}")
        missed = rules["missed_by_scenario"]
        for tactic, recall in rules["recall_by_scenario"].items():
            print(f"  {tactic:<16}{recall:>8.2f}{missed.get(tactic, 0):>8}")

    out = {}
    if rules:
        out.update({f"rules_{k}": v for k, v in rules.items()
                    if not isinstance(v, dict)})
    if flags:
        out.update({f"flagproxy_{k}": v for k, v in flags.items()})
    return out


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

    recovery = rule_miss_recovery(eval_df, y_true, score)
    if recovery:
        print(f"\nRULE-MISS RECOVERY -- the {recovery['n']} attacks the deployed "
              f"rules never saw:")
        print(f"  {recovery['in_budget']} of {recovery['n']} ranked in the top "
              f"{recovery['budget']} of {len(y_true)} sessions "
              f"(median rank {recovery['median_rank']:.0f}, "
              f"best {recovery['best_rank']}, worst {recovery['worst_rank']})")
        row.update({f"rulemiss_{k}": v for k, v in recovery.items()})

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
