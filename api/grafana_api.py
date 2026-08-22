#!/usr/bin/env python3
"""
grafana_api.py -- the Grafana-facing surface of the scoring service.

TWO KINDS OF ENDPOINT, ONE HARD RULE
------------------------------------
  POST /grafana/ingest      -- WRITE path. Runs the model ONCE per session and
                               persists the result. Called by the collector
                               (every N minutes, or on session close), NOT by
                               Grafana.
  GET  /grafana/*           -- READ paths. Plain SQL against store.py. Grafana's
                               auto-refresh hammers these; none of them ever
                               loads the model. This is what makes 5s refresh
                               safe.

All GET responses are flat JSON arrays of objects -- the shape the Grafana
Infinity datasource parses with zero configuration (root = "", columns inferred).

TIME FILTERING
--------------
Grafana passes the picker range as ${__from}/${__to} (epoch ms). The Infinity
queries forward them as ?from=&to=. Every windowed endpoint honours them, so
"Last 15m / 1h / 24h" is enforced in SQL, not in the browser.
"""

from __future__ import annotations

import sys
from typing import Callable

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from . import store

router = APIRouter(prefix="/grafana", tags=["grafana"])

# Injected by main.py at startup so the router can score without importing the
# app's module-global _state (avoids a circular import).
_score_fn: Callable | None = None
_surprisal_fn: Callable | None = None
DB_PATH = store.DEFAULT_PATH


def configure(*, score_fn: Callable, surprisal_fn: Callable, db_path: str) -> None:
    global _score_fn, _surprisal_fn, DB_PATH
    _score_fn, _surprisal_fn, DB_PATH = score_fn, surprisal_fn, db_path
    store.init(db_path)


# ─────────────────────── per-command enrichment (audit log) ─────────────────
def _classify_command(command: str) -> str:
    """Best-effort risk category for ONE command, reusing transform's keyword map
    so the audit-log flags line up with the Wazuh rule categories. '' if clean."""
    from transform import RISK_KEYWORDS, _keyword_hit
    text = command.lower()
    for category, keywords in RISK_KEYWORDS.items():
        if any(_keyword_hit(kw, text) for kw in keywords):
            return category
    return ""


def _command_rows(session: dict) -> list[dict]:
    """Turn a session's command list into audit rows with timestamps + risk.

    HONEST LIMITATION: sessions.jsonl carries no per-command timestamp (only
    session_start/end), so execution times are INTERPOLATED evenly across the
    session window. When the collector is wired to events.jsonl (which has a
    real timestamp per KBD_INPUT), swap this for the real per-event times.
    """
    cmds = session.get("commands") or []
    start = session.get("start_ms")
    end = session.get("end_ms") or start
    n = len(cmds)
    rows = []
    for i, cmd in enumerate(cmds):
        if start is not None and end is not None and n > 1:
            ts = int(start + (end - start) * i / (n - 1))
        else:
            ts = start
        surprisal = None
        if _surprisal_fn is not None:
            try:
                surprisal = float(_surprisal_fn(cmd))
            except Exception:
                surprisal = None
        rows.append({"seq": i + 1, "ts_ms": ts, "command": cmd,
                     "risk_flag": _classify_command(cmd), "surprisal": surprisal})
    return rows


# ───────────────────────────── ingest (write) ──────────────────────────────
class IngestSession(BaseModel):
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


class IngestRequest(BaseModel):
    sessions: list[IngestSession]


def _to_ms(iso: str | None) -> int | None:
    if not iso:
        return None
    import pandas as pd
    try:
        return int(pd.to_datetime(iso, utc=True).timestamp() * 1000)
    except Exception:
        return None


@router.post("/ingest")
def ingest(req: IngestRequest) -> dict:
    """Score a batch ONCE and persist it. This is the only model call in this file."""
    if _score_fn is None:
        raise HTTPException(503, "scoring not configured")
    if not req.sessions:
        raise HTTPException(400, "no sessions supplied")

    raw = [s.model_dump() for s in req.sessions]
    scored, model_name, threshold = _score_fn(raw)          # runs the model
    by_id = {s["session_id"]: s for s in raw}

    written = 0
    for r in scored:
        src = by_id[r["session_id"]]
        src["start_ms"] = _to_ms(src.get("session_start"))
        src["end_ms"] = _to_ms(src.get("session_end"))
        store.upsert_session(
            DB_PATH,
            session=src,
            score=r["score"],
            alert=r["alert"],
            model_name=model_name,
            threshold=threshold,
            features=r["features"],
            commands=_command_rows(src),
        )
        written += 1
    return {"ingested": written, "model_name": model_name, "threshold": threshold}


# ─────────────────────────────── reads (Grafana) ───────────────────────────
def _range(frm: int | None, to: int | None):
    return frm, to


@router.get("/summary")
def g_summary(frm: int | None = Query(None, alias="from"),
              to: int | None = Query(None, alias="to")) -> list[dict]:
    # Returned as a single-row array so Infinity + the Stat panel read it uniformly.
    return [store.summary(DB_PATH, frm, to)]


@router.get("/ranked")
def g_ranked(frm: int | None = Query(None, alias="from"),
             to: int | None = Query(None, alias="to"),
             identity: str | None = Query(None),
             limit: int = 100) -> list[dict]:
    return store.ranked(DB_PATH, frm, to, identity, limit)


@router.get("/distribution")
def g_distribution(frm: int | None = Query(None, alias="from"),
                   to: int | None = Query(None, alias="to"),
                   identity: str | None = Query(None)) -> list[dict]:
    return store.distribution(DB_PATH, frm, to, identity)


@router.get("/ratio")
def g_ratio(frm: int | None = Query(None, alias="from"),
            to: int | None = Query(None, alias="to")) -> list[dict]:
    return store.ratio(DB_PATH, frm, to)


@router.get("/features")
def g_features(session_id: str = Query(...)) -> list[dict]:
    return store.features_for(DB_PATH, session_id)


@router.get("/commands")
def g_commands(session_id: str = Query(...)) -> list[dict]:
    return store.commands_for(DB_PATH, session_id)


# Template-variable feeds. Grafana's Infinity variable query reads these.
@router.get("/vars/identities")
def g_var_identities(frm: int | None = Query(None, alias="from"),
                     to: int | None = Query(None, alias="to")) -> list[dict]:
    return [{"__text": i, "__value": i} for i in store.identities(DB_PATH, frm, to)]


@router.get("/vars/sessions")
def g_var_sessions(frm: int | None = Query(None, alias="from"),
                   to: int | None = Query(None, alias="to"),
                   identity: str | None = Query(None)) -> list[dict]:
    return store.session_ids(DB_PATH, frm, to, identity)
