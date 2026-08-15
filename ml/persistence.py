#!/usr/bin/env python3
"""
persistence.py -- save and load a scoring bundle.

A model alone is not deployable here. Scoring one session needs four things that
must agree with each other, and three of them are not inside the estimator:

  model          the fitted estimator
  scaler         fitted on TRAINING data only (unsupervised track)
  features       the exact column list the gate produced, in order -- a
                 different order silently scores the wrong columns
  command_profile  the vocabulary the cmd_* features are measured against

THE FAILURE THIS PREVENTS
-------------------------
A model paired with the wrong command_profile is not broken, it is silently
wrong: every score is computed against a vocabulary the model was not trained
for, and nothing raises. Since the profile changes on every regeneration
(1273 distinct commands today, a different set tomorrow), pairing them by
convention would fail quietly and soon. So the profile is stored INSIDE the
bundle, not referenced by path, and a fingerprint of it is checked on load.

The threshold rides along too. It is a property of the fitted training
distribution, not of the model object, and re-deriving it at serving time
against live data would let the alert rate drift with whatever traffic happens
to be arriving.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

import joblib

BUNDLE_VERSION = 1


def profile_fingerprint(profile: dict) -> str:
    """Stable hash of the profile's vocabulary and counts."""
    payload = json.dumps(profile.get("counts", {}), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def save(path: str, *, model, features: list, profile: dict,
         scaler=None, threshold: float | None = None,
         model_name: str = "", track: str = "", metrics: dict | None = None) -> str:
    """Write one self-contained scoring bundle."""
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "model_name": model_name,
        "track": track,
        "model": model,
        "scaler": scaler,
        "features": list(features),
        "threshold": threshold,
        "command_profile": profile,
        "profile_fingerprint": profile_fingerprint(profile),
        # What the bundle scored when it was built. Not used at inference --
        # kept so a deployed bundle can always be traced to the run that
        # produced it, which is the question asked first when a score looks wrong.
        "metrics": metrics or {},
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    return path


def load(path: str) -> dict:
    """Load a bundle and verify it is internally consistent."""
    bundle = joblib.load(path)

    if bundle.get("bundle_version") != BUNDLE_VERSION:
        raise ValueError(f"bundle version {bundle.get('bundle_version')} != "
                         f"expected {BUNDLE_VERSION}: {path}")

    expected = bundle.get("profile_fingerprint")
    actual = profile_fingerprint(bundle["command_profile"])
    if expected != actual:
        raise ValueError(f"command_profile does not match its fingerprint "
                         f"({actual} != {expected}) -- the bundle is corrupt")

    return bundle


def describe(bundle: dict) -> str:
    profile = bundle["command_profile"]
    return (f"{bundle['model_name']} ({bundle['track']}), "
            f"saved {bundle['saved_at'][:19]}\n"
            f"  features ({len(bundle['features'])}): {bundle['features']}\n"
            f"  threshold: {bundle['threshold']}\n"
            f"  profile: {profile['vocabulary_size']} distinct commands from "
            f"{profile['n_sessions']} benign sessions "
            f"[{bundle['profile_fingerprint']}]")
