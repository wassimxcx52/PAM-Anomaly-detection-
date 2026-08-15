#!/usr/bin/env python3
"""
feature_gate.py -- the single definition of "a column a model is allowed to see".

Imported by both ML tracks (supervised/ and unsupervised/) for the same reason
command_safety.py is imported by both dataset sides: if each track picked its own
columns, a difference in their scores could be a difference in their inputs, and
the bake-off would be measuring the wrong thing.

TWO SEPARATE FILTERS, IN ORDER
------------------------------
1. LEAK GATE (static, this file). Columns that would hand the model its own
   label. Not a judgement call -- each one is measured in
   docs/session_2026-08-09_unsupervised_precision.md:

     persona              NaN on all 49 real attack sessions, populated on all
                          207 benign -- a perfect label proxy, and missing at
                          scoring time for exactly the sessions being hunted.
     account              p_admin is 100% attack and bastionsvc 100% benign on
                          real eval (an artifact of the collection scenarios).
     ip_source            one-sided by construction in generate_attacks.py:
                          home/vpn/jump for benign, wrong_team_subnet/
                          unseen_vpn/external for attacks.
     target_group,        generator knobs.
     target_criticality   criticality is the IMPACT weight in
                          risk = anomaly x impact, applied after scoring, never
                          an input to the anomaly score itself.
     composition,         how generate_attacks.py built the session. Evaluation
     attack_command_count slices ("does it only catch the loud ones?"), not
     campaign_id, mitre,  inputs.
     tactics
     real_*, *_is_synthetic   provenance and audit trail.
     source, split, label     provenance and the target itself.

2. DOMAIN GATE (dynamic, needs both frames). Keep a column only if it varies in
   BOTH the training and the evaluation set.

   The lab produces one login user, one client IP, and one collection window, so
   on real eval 5 of the 14 candidate features are literally constant and 4 more
   take two distinct values across 256 sessions. A constant column cannot rank
   anything; it only adds a dimension over which every real session sits in the
   same out-of-support corner, diluting the features that do carry signal
   (ECOD/COPOD sum per-dimension tail probabilities, so this is a direct
   precision cost).

   `min_share` exists because "has variance" is too weak a test at n=256: a
   column where 255 rows agree and one differs passes nunique>1 while being
   degenerate in every way that matters.

TRANSDUCTIVE, AND DELIBERATELY SO
---------------------------------
The domain gate inspects the evaluation set. It reads column variance only,
never labels, so it cannot leak class information -- but it is technically
transductive and must be stated as such in the report. It is accepted because
those columns are degenerate for a STRUCTURAL reason known a priori (one user,
one IP, one collection window), not because of anything about this particular
eval sample. The stricter alternative is to measure variance on a held-out
real-benign slice instead.

FLAGS ARE NOT INPUTS
--------------------
flag_* stays out by default. Fed to a model, it re-derives wallix_rules.xml
100510-100520 and precision@k becomes a measurement of the rule layer, not of
behavioural detection (CLAUDE.md sec 8, circularity). They are kept as the
RULE-LAYER BASELINE to beat. `include_flags=True` exists to quantify that
circularity on purpose, not to improve a score.
"""

from __future__ import annotations

import pandas as pd

# Every numeric feature transform.py computes, before any gating.
CANDIDATE_FEATURES = [
    "duration_sec_feat",
    "start_hour",
    "off_hours_flag",
    "is_weekend",
    "command_count",
    "unique_command_ratio",
    "avg_command_length",
    "command_entropy",
    "new_source_ip_for_user",
    "new_source_ip_globally",
    "ip_foreign_to_user",
    "distinct_source_ips_prior",
    "distinct_source_ips_24h",
    "source_ip_entropy",
    # Vocabulary rarity against a benign profile fitted on training data only
    # (feature_extraction/command_profile.py). These are the first features that
    # look at WHICH commands were typed rather than at session shape, and they
    # are behavioural, not a keyword lookup -- the distinction the report has to
    # defend against "the ML just re-ranks the rules".
    "cmd_oov_rate",
    "cmd_mean_surprisal",
    "cmd_max_surprisal",
    "cmd_mean_novelty",
    "cmd_max_novelty",
]

FLAG_FEATURES = [
    "flag_cred_access", "flag_privesc", "flag_persistence",
    "flag_log_tamper", "flag_recon", "flag_exfil",
]

# See module docstring. Not a heuristic list -- each entry is measured.
LEAK_COLUMNS = {
    "label", "source", "split", "tactics", "persona", "account",
    "ip_source", "target_group", "target_criticality",
    "composition", "attack_command_count", "campaign_id", "mitre",
    "scenario", "expected_rule_ids", "session_tag",
    "identity_is_synthetic", "ip_is_synthetic", "ts_is_synthetic",
    "real_user", "real_client_ip", "real_target_ip", "real_target_hostname",
}


# A float column can be "constant" only up to floating-point noise: cosine
# novelty for a command that IS in the profile computes as -0.0000000002 rather
# than exactly 0, which defeats an exact nunique test while carrying no
# information whatsoever. Anything varying by less than this is treated as flat.
FLAT_ABS_TOL = 1e-9


def _degenerate(series: pd.Series, min_share: float) -> bool:
    """True if the column is constant, constant to within floating-point noise,
    or so nearly constant that its variance is a single stray row rather than a
    distribution."""
    values = series.dropna()
    if values.nunique() <= 1:
        return True
    if pd.api.types.is_numeric_dtype(values):
        spread = float(values.max()) - float(values.min())
        if spread < FLAT_ABS_TOL:
            return True
    modal_share = values.value_counts(normalize=True).iloc[0]
    return (1.0 - modal_share) < min_share


def domain_gate(train: pd.DataFrame, evaluation: pd.DataFrame,
                candidates: list[str] | None = None,
                min_share: float = 0.01) -> tuple[list[str], dict[str, str]]:
    """(kept, dropped) where dropped maps column -> why.

    Both frames are required: a column constant in training is useless to fit on,
    and a column constant at scoring time is useless to score with. Either one
    disqualifies it.
    """
    candidates = candidates or CANDIDATE_FEATURES
    kept, dropped = [], {}

    for column in candidates:
        if column not in train.columns:
            dropped[column] = "absent from train"
        elif column not in evaluation.columns:
            dropped[column] = "absent from eval"
        elif _degenerate(train[column], min_share):
            dropped[column] = f"degenerate in train (nunique={train[column].nunique()})"
        elif _degenerate(evaluation[column], min_share):
            dropped[column] = f"degenerate in eval (nunique={evaluation[column].nunique()})"
        else:
            kept.append(column)

    return kept, dropped


def reference_class_gate(train: pd.DataFrame, candidates: list[str],
                         min_share: float = 0.01,
                         reference: str = "benign") -> dict[str, str]:
    """Drop columns that are constant WITHIN the training benign class.

    A column can vary across the training set as a whole while being identically
    valued for every benign row -- and that is worse than useless, it is a
    perfect separator handed to the model by construction rather than learned.

    The case this was written for: cmd_oov_rate is exactly 0.0000 for all 5000
    generated benign sessions, because the generator draws from a CLOSED
    vocabulary of 850 command types and the profile is fitted on that same
    vocabulary. Cross-fitting does not fix it -- holding out 20% of sessions
    still leaves every command type in the profile. Real benign, drawn from open
    human behaviour, has a 1.4% OOV rate. So a model trained on that column
    learns "oov > 0 implies attack", which is true in the generated world and
    false in the real one, and every real benign session using an unlisted
    command becomes a false positive.

    The whole-column domain gate cannot see this: the column varies in train
    (attacks differ) and varies in eval. Only the within-benign view exposes it.
    """
    if "label" not in train.columns:
        return {}
    benign = train[train["label"] == reference]
    if benign.empty:
        return {}
    return {c: f"constant within training {reference} "
               f"(={benign[c].dropna().iloc[0]!r}) -- separator by construction"
            for c in candidates
            if c in benign.columns and _degenerate(benign[c], min_share)}


def model_features(train: pd.DataFrame, evaluation: pd.DataFrame, *,
                   include_flags: bool = False, drop: list[str] | None = None,
                   min_share: float = 0.01, verbose: bool = True) -> list[str]:
    """The full selection: candidates -> domain gate -> explicit drops.

    `drop` is for provisional, reversible removals recorded in the session log --
    e.g. duration_sec_feat, whose real spread (sigma 5.16) the generator's uniform
    per-command pacing cannot reproduce, so any error there converts straight into
    false positives.
    """
    candidates = CANDIDATE_FEATURES + (FLAG_FEATURES if include_flags else [])
    kept, dropped = domain_gate(train, evaluation, candidates, min_share)

    for column, reason in reference_class_gate(train, kept, min_share).items():
        kept.remove(column)
        dropped[column] = reason

    for column in (drop or []):
        if column in kept:
            kept.remove(column)
            dropped[column] = "explicitly dropped (--drop)"

    if verbose:
        print(f"[gate] {len(kept)} features kept: {kept}")
        for column, reason in dropped.items():
            print(f"[gate]   dropped {column:26s} {reason}")
        if not include_flags:
            print("[gate]   flag_* held out as the rule-layer baseline "
                  "(--with-flags to measure the circularity)")
    return kept


def leaked(columns) -> list[str]:
    """Any column in `columns` that must never reach a model. A guard for callers
    that build a feature list some other way."""
    return sorted(set(columns) & LEAK_COLUMNS)
