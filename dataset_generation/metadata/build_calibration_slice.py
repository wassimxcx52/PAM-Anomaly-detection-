#!/usr/bin/env python3
"""
build_calibration_slice.py -- freeze the boundary between the real benign sessions
used to CALIBRATE the generator and those kept to EVALUATE the model.

WHY THIS FILE EXISTS AT ALL
---------------------------
fit_generator.py tunes the synthetic benign distribution until it matches the real
one. That means real benign data informs the generator, and any real session used
for calibration is no longer a naive judge of it. CLAUDE.md sec 10's rule
("generated TRAINS, real JUDGES") survives only if the two sets are disjoint AND
the split is fixed once -- a fresh random draw per run would silently move the
evaluation set under the metrics, and nobody would see it happen.

So the split is computed here, once, and committed as calibration_slice.json.
Everything downstream reads that file; nothing re-draws.

WHAT ELSE IT FREEZES
--------------------
The eval set is not just "real benign minus the slice". Two accounts are perfect
label proxies in the collected data (measured, not assumed):

    p_admin      22 attack /  0 benign   -- 100% attack
    bastionsvc    0 attack / 53 benign   -- 100% benign
    p_dev / p_dba / p_audit  ~15% attack -- clean, near the 19% base rate

p_admin is an artifact of how simulate_sessions.py was scripted (attacks default to
it, sec 6), not a property of the world. Its 22 attacks are free wins for any model
that happens to score p_admin high, so they are excluded from the headline metric
and reported separately as a known lab artifact. bastionsvc BENIGN stays: benign
sessions inflate nothing, they only make the task harder and more honest.

The surviving 27 attacks still cover all six scenarios, so no attack type is lost.

CALIBRATION IS GLOBAL, NOT PER-PERSONA. 50 sessions over 4 personas is 12 each --
too thin to fit four separate distributions without fitting noise. Documented
limitation, not an oversight.

Output: calibration_slice.json (session ids + moment targets + eval definition)
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_REAL = os.path.join(HERE, "..", "..", "feature_extraction", "out",
                         "features_eval_real.csv")
OUT = os.path.join(HERE, "calibration_slice.json")

# Accounts whose label distribution is degenerate in the collected data. Attacks
# on these are excluded from the headline metric; see module docstring.
ARTIFACT_ATTACK_ACCOUNTS = ["p_admin"]

# Features the generator is fitted against. Ordered by how much they matter:
# avg_command_length separates attacks at +1.32sd from a corrected benign centre,
# unique_command_ratio at +0.95sd. command_count is measured and reported but is a
# weak third (-0.54sd) and has no clean knob -- see fit_generator.py.
TARGET_FEATURES = ["avg_command_length", "unique_command_ratio", "command_count"]

# Measured too, so the residual is on record, but NOT fitted:
#   command_entropy   -- derived from the two above, fitting it directly would
#                        double-count the same knobs
#   duration_sec_feat -- weak (-0.34sd) and its real spread (sd 5.16 vs the
#                        generator's 2.38) is not reproducible by the current
#                        per-command uniform pacing model
DIAGNOSTIC_FEATURES = ["command_entropy", "duration_sec_feat"]

# A slice that is not representative of the sessions it is carved from would
# calibrate the generator toward the wrong centre. 0.5sd is generous; the observed
# worst-case drift is 0.19sd.
MAX_ACCEPTABLE_DRIFT_SD = 0.5


def stratified_slice(benign: pd.DataFrame, n: int, seed: int) -> list:
    """Sample n benign sessions, proportionally per account.

    Stratified rather than plain random so the calibration targets are not pulled
    toward whichever persona happens to be over-drawn -- each account carries a
    different command profile, and the generator is fitted on the pooled moments.
    """
    picked: list = []
    for account, group in benign.groupby("account"):
        take = max(1, round(len(group) * n / len(benign)))
        picked += list(group.sample(n=take, random_state=seed).index)
    return picked


def moments(frame: pd.DataFrame, features: list) -> dict:
    return {f: {"mean": round(float(frame[f].mean()), 4),
                "std": round(float(frame[f].std()), 4)}
            for f in features}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--eval-real", default=EVAL_REAL)
    ap.add_argument("--n", type=int, default=50,
                    help="calibration slice size (rest stays for evaluation)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    real = pd.read_csv(args.eval_real)
    benign = real[real["label"] == "benign"]
    attacks = real[real["label"] == "attack"]

    calibration_idx = stratified_slice(benign, args.n, args.seed)
    calibration = benign.loc[calibration_idx]
    remaining = benign.drop(calibration_idx)

    # Representativeness: how far the slice sits from what it left behind, in the
    # remainder's own sd. Large drift means the split itself is biased.
    all_features = TARGET_FEATURES + DIAGNOSTIC_FEATURES
    drift = {f: round(float((calibration[f].mean() - remaining[f].mean())
                            / remaining[f].std()), 3)
             for f in all_features}
    worst = max(drift, key=lambda f: abs(drift[f]))
    if abs(drift[worst]) > MAX_ACCEPTABLE_DRIFT_SD:
        raise SystemExit(f"slice is not representative: {worst} drifts "
                         f"{drift[worst]:+.2f}sd (limit {MAX_ACCEPTABLE_DRIFT_SD})")

    eval_attacks = attacks[~attacks["account"].isin(ARTIFACT_ATTACK_ACCOUNTS)]
    excluded = attacks[attacks["account"].isin(ARTIFACT_ATTACK_ACCOUNTS)]

    artifact = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": os.path.normpath(args.eval_real),
        "seed": args.seed,
        "method": "stratified by account, proportional allocation",
        "calibration": {
            "n": len(calibration),
            "per_account": calibration["account"].value_counts().to_dict(),
            "session_ids": sorted(calibration["session_id"].tolist()),
        },
        "evaluation": {
            "benign": len(remaining),
            "attacks": len(eval_attacks),
            "base_rate": round(len(eval_attacks)
                               / (len(remaining) + len(eval_attacks)), 4),
            "excluded_attacks": {
                "n": len(excluded),
                "accounts": ARTIFACT_ATTACK_ACCOUNTS,
                "reason": "account is a perfect label proxy in the collected data "
                          "(100% attack); a lab artifact of simulate_sessions.py's "
                          "default account, reported separately not in the headline",
                "scenarios_still_covered": sorted(
                    eval_attacks["scenario"].dropna().unique().tolist()),
            },
        },
        # What fit_generator.py aims at.
        "targets": moments(calibration, TARGET_FEATURES),
        "diagnostics": moments(calibration, DIAGNOSTIC_FEATURES),
        "representativeness_drift_sd": drift,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2)
        fh.write("\n")

    print(f"calibration slice: {len(calibration)} sessions "
          f"{calibration['account'].value_counts().to_dict()}")
    print(f"evaluation set:    {len(remaining)} benign + {len(eval_attacks)} attacks "
          f"(base rate {artifact['evaluation']['base_rate']:.1%}), "
          f"{len(excluded)} attacks excluded as artifact")
    print(f"worst drift:       {worst} {drift[worst]:+.2f}sd")
    print(f"targets:           " + ", ".join(
        f"{f}={artifact['targets'][f]['mean']}" for f in TARGET_FEATURES))
    print(f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
