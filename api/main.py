#!/usr/bin/env python3
"""
main.py -- the scoring service. FastAPI in front of a saved bundle.

    POST /score    sessions (sessions.jsonl shape) -> ranked anomaly scores
    GET  /model    which bundle is loaded, and what it scored when it was built
    GET  /health   liveness, for compose/k8s

WHY THE FEATURES ARE COMPUTED BY transform.py AND NOT RE-IMPLEMENTED HERE
------------------------------------------------------------------------
A serving-side copy of the feature code is the classic source of train/serve
skew: it starts identical and drifts on the first bug fix applied to only one
side. This service calls transform.build_features_from_sessions -- the same
function that produced the training matrix -- so a feature can only change in
both places at once.

The consequence is that the image must ship feature_extraction/ and ml/, not
just a pickle. That is the correct trade: the model is not the artifact, the
(model + scaler + feature order + command profile) bundle is, and the code that
produces those features is part of the contract.

STATELESS, BY DESIGN
--------------------
Each request is scored independently. The cross-session features
(new_source_ip_for_user, distinct_source_ips_24h) are computed within the
request's own batch and are therefore only meaningful when a caller sends a
user's sessions together -- which the batch scorer does and a per-session live
call does not. Those columns are gated out of the deployed feature set anyway
(they are constant on real lab telemetry), so nothing is silently wrong today.
When they matter, they need a state store, and that belongs outside this
service, not in a module global.

NOT INCLUDED: authentication
----------------------------
There is none. This binds inside the compose network and must not be exposed.
auth.py (RBAC) is Security-owned and unbuilt; wiring an unauthenticated /score
to a public port would publish privileged session content.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "feature_extraction"))

from ml.persistence import load as load_bundle  # noqa: E402
from api import store  # noqa: E402
from api import grafana_api  # noqa: E402

BUNDLE_PATH = os.environ.get(
    "BUNDLE_PATH", os.path.join(ROOT, "ml", "bundles", "isolationforest.joblib"))

app = FastAPI(title="PAM anomaly scoring",
              description="WALLIX privileged-session anomaly scoring",
              version="1.0.0")

# The dashboard (visualisation/dashboard/) is a static page opened from the file
# system or a throwaway `python -m http.server`, so its browser Origin never
# matches this service's host. Without CORS the browser blocks the /score fetch
# before it leaves the tab. This is a lab convenience only -- it does NOT make
# the service safe to expose: /score is still unauthenticated (see the module
# docstring), and a permissive CORS policy on a public port would let any page
# read privileged session scores. Keep it bound inside the compose network.
# Override the allow-list with DASHBOARD_ORIGINS (comma-separated) if serving the
# page from a fixed origin; "*" is the default only because a file:// page sends
# Origin: null, which no explicit list can match.
_origins_env = os.environ.get("DASHBOARD_ORIGINS", "*")
_allow_origins = [o.strip() for o in _origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_state: dict[str, Any] = {}

# Grafana read/ingest surface (/grafana/*). Reads hit the SQLite store only;
# only /grafana/ingest touches the model. See api/grafana_api.py.
app.include_router(grafana_api.router)


class Session(BaseModel):
    """One session, in extract.py's sessions.jsonl shape.

    Only the fields the features actually need are required. Everything else is
    accepted and passed through, so a caller can post the record it already has
    without stripping it.
    """
    session_id: str
    commands: list[str] = Field(default_factory=list)
    protocol: str = "SSH"
    session_start: str | None = None
    session_end: str | None = None
    duration_sec: float | None = None
    user: str | None = None
    account: str | None = None
    client_ip: str | None = None
    target_ip: str | None = None
    target_hostname: str | None = None

    model_config = {"extra": "allow"}


class ScoreRequest(BaseModel):
    sessions: list[Session]


class ScoredSession(BaseModel):
    session_id: str
    score: float
    alert: bool
    rank: int
    features: dict[str, float | None]


class ScoreResponse(BaseModel):
    model_name: str
    threshold: float | None
    profile_fingerprint: str
    scored: int
    results: list[ScoredSession]


@app.on_event("startup")
def _load() -> None:
    import command_profile

    bundle = load_bundle(BUNDLE_PATH)
    _state["bundle"] = bundle
    # The scorer rebuilds its TF-IDF from the profile's command list, which
    # takes a moment; doing it once at startup keeps it off the request path.
    scorer = command_profile.Scorer(bundle["command_profile"])
    _state["scorer"] = scorer
    print(f"[startup] loaded {bundle['model_name']} ({bundle['track']}) "
          f"from {BUNDLE_PATH}, profile {bundle['profile_fingerprint']}")

    # Wire the Grafana router: give it the shared scoring function (so ingest
    # runs the exact same model path) and the profile's per-command surprisal
    # (for the audit log), then initialise the scored-session store.
    grafana_api.configure(
        score_fn=score_sessions,
        surprisal_fn=scorer.surprisal,
        db_path=store.DEFAULT_PATH,
    )
    print(f"[startup] grafana store at {store.DEFAULT_PATH}")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": "bundle" in _state}


@app.get("/model")
def model_info() -> dict:
    bundle = _state.get("bundle")
    if bundle is None:
        raise HTTPException(503, "no bundle loaded")
    profile = bundle["command_profile"]
    return {
        "model_name": bundle["model_name"],
        "track": bundle["track"],
        "saved_at": bundle["saved_at"],
        "features": bundle["features"],
        "threshold": bundle["threshold"],
        "profile_fingerprint": bundle["profile_fingerprint"],
        "profile_vocabulary": profile["vocabulary_size"],
        "profile_sessions": profile["n_sessions"],
        # What this bundle scored on the real eval set when it was built. The
        # first question when a live score looks wrong is "which model is this
        # and how good was it", and the answer should not require the repo.
        "metrics_at_build": bundle.get("metrics", {}),
    }


def score_sessions(sessions: list[dict]) -> tuple[list[dict], str, float | None]:
    """The one place inference happens. Batch of session dicts -> ranked results.

    Shared by POST /score and the Grafana ingest path so both compute features
    and run the model identically -- there is no second scoring code path to
    drift. Returns (results, model_name, threshold) with results already ranked
    by score descending; each result is a plain dict:
        {session_id, score, alert, rank, features}
    Raises HTTPException(422) for sessions that carry no scorable telemetry.
    """
    bundle, scorer = _state.get("bundle"), _state.get("scorer")
    if bundle is None:
        raise HTTPException(503, "no bundle loaded")
    if not sessions:
        raise HTTPException(400, "no sessions supplied")

    from transform import add_rarity_features, build_features_from_sessions

    frame = pd.DataFrame(sessions)
    features = build_features_from_sessions(frame)
    features = add_rarity_features(features, scorer)

    wanted = bundle["features"]
    missing = [c for c in wanted if c not in features.columns]
    if missing:
        raise HTTPException(422, f"cannot compute features: {missing}")

    X = features[wanted]
    if X.isna().any().any():
        bad = X.columns[X.isna().any()].tolist()
        # Almost always a protocol carrying no command telemetry (RDP). Refusing
        # is correct: an imputed 0 would score as "perfectly ordinary".
        raise HTTPException(
            422, f"NaN in {bad} -- these sessions carry no command telemetry "
                 f"and cannot be scored by this bundle")

    if bundle.get("scaler") is not None:
        X = bundle["scaler"].transform(X)

    model = bundle["model"]
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(X)[:, 1]
    elif hasattr(model, "score_samples"):
        scores = -model.score_samples(X)
    else:
        scores = model.transform(X).min(axis=1)

    threshold = bundle.get("threshold")
    features["score"] = scores
    ranked = features.sort_values("score", ascending=False).reset_index(drop=True)

    results = [
        {
            "session_id": row["session_id"],
            "score": float(row["score"]),
            "alert": bool(threshold is not None and row["score"] > threshold),
            "rank": position + 1,
            "features": {c: (None if pd.isna(row[c]) else float(row[c])) for c in wanted},
        }
        for position, row in ranked.iterrows()
    ]
    return results, bundle["model_name"], threshold


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest) -> ScoreResponse:
    results, model_name, threshold = score_sessions(
        [s.model_dump() for s in request.sessions])
    bundle = _state["bundle"]
    return ScoreResponse(
        model_name=model_name,
        threshold=threshold,
        profile_fingerprint=bundle["profile_fingerprint"],
        scored=len(results),
        results=[ScoredSession(**r) for r in results],
    )
