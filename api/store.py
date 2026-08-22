#!/usr/bin/env python3
"""
store.py -- the scored-session cache that sits between the ML service and Grafana.

WHY THIS EXISTS
---------------
Grafana panels poll on the dashboard's auto-refresh interval. At a 5s refresh
with ~7 panels that is >80 requests/minute, and every one of them would
otherwise re-run feature extraction + model inference on the whole window. That
is the fastest way to melt the scoring service.

So inference happens exactly ONCE per session -- at ingest -- and the result is
written here. Every Grafana read is a plain indexed SQL query against this
store and never loads the model. Auto-refresh is now cheap by construction.

SQLite is deliberate: one file, no server, WAL mode for concurrent reads while a
single writer ingests. If the deployment outgrows it, the query surface in
grafana_api.py is small enough to repoint at Postgres/OpenSearch without
touching Grafana.

Timestamps are stored as epoch MILLISECONDS (INTEGER) throughout, because that
is exactly what Grafana passes as ${__from}/${__to} -- no parsing on the read
path.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable

DEFAULT_PATH = os.environ.get(
    "SCORES_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scores.db"),
)

_lock = threading.Lock()   # SQLite tolerates concurrent readers; serialise writers.

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    identity        TEXT,          -- displayed identity (account, falls back to user)
    login_user      TEXT,
    account         TEXT,
    client_ip       TEXT,
    target_hostname TEXT,
    protocol        TEXT,
    start_ms        INTEGER,       -- session_start, epoch ms
    end_ms          INTEGER,
    duration_sec    REAL,
    score           REAL,
    alert           INTEGER,       -- 0/1
    model_name      TEXT,
    threshold       REAL,
    scored_ms       INTEGER        -- when this row was written
);
CREATE INDEX IF NOT EXISTS ix_sessions_start ON sessions(start_ms);
CREATE INDEX IF NOT EXISTS ix_sessions_identity ON sessions(identity);

CREATE TABLE IF NOT EXISTS features (
    session_id TEXT,
    name       TEXT,
    value      REAL,
    PRIMARY KEY (session_id, name)
);

CREATE TABLE IF NOT EXISTS commands (
    session_id TEXT,
    seq        INTEGER,        -- order within the session
    ts_ms      INTEGER,        -- execution time (interpolated, see grafana_api)
    command    TEXT,           -- raw command as typed (audit-faithful)
    risk_flag  TEXT,           -- '' or a category: recon/privesc/cred_access/...
    surprisal  REAL,           -- per-command surprisal from the command profile
    PRIMARY KEY (session_id, seq)
);
CREATE INDEX IF NOT EXISTS ix_commands_session ON commands(session_id);
"""


@contextmanager
def _connect(path: str):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()


def init(path: str = DEFAULT_PATH) -> None:
    with _connect(path) as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def upsert_session(
    path: str,
    *,
    session: dict[str, Any],
    score: float,
    alert: bool,
    model_name: str,
    threshold: float | None,
    features: dict[str, float | None],
    commands: list[dict[str, Any]],
) -> None:
    """Idempotent write of one scored session and its children.

    Re-ingesting the same session_id overwrites it (a later, more complete pull
    of the same session should win), so the collector can re-score safely
    without duplicating rows or double-alerting.
    """
    now = int(time.time() * 1000)
    identity = session.get("account") or session.get("user") or "unknown"
    with _lock, _connect(path) as conn:
        conn.execute(
            """INSERT INTO sessions
               (session_id, identity, login_user, account, client_ip,
                target_hostname, protocol, start_ms, end_ms, duration_sec,
                score, alert, model_name, threshold, scored_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET
                 identity=excluded.identity, login_user=excluded.login_user,
                 account=excluded.account, client_ip=excluded.client_ip,
                 target_hostname=excluded.target_hostname, protocol=excluded.protocol,
                 start_ms=excluded.start_ms, end_ms=excluded.end_ms,
                 duration_sec=excluded.duration_sec, score=excluded.score,
                 alert=excluded.alert, model_name=excluded.model_name,
                 threshold=excluded.threshold, scored_ms=excluded.scored_ms""",
            (
                session["session_id"], identity, session.get("user"),
                session.get("account"), session.get("client_ip"),
                session.get("target_hostname"), session.get("protocol", "SSH"),
                session.get("start_ms"), session.get("end_ms"),
                session.get("duration_sec"), float(score), int(bool(alert)),
                model_name, threshold, now,
            ),
        )
        sid = session["session_id"]
        conn.execute("DELETE FROM features WHERE session_id=?", (sid,))
        conn.executemany(
            "INSERT INTO features (session_id, name, value) VALUES (?,?,?)",
            [(sid, k, (None if v is None else float(v))) for k, v in features.items()],
        )
        conn.execute("DELETE FROM commands WHERE session_id=?", (sid,))
        conn.executemany(
            "INSERT INTO commands (session_id, seq, ts_ms, command, risk_flag, surprisal)"
            " VALUES (?,?,?,?,?,?)",
            [(sid, c["seq"], c["ts_ms"], c["command"], c["risk_flag"], c["surprisal"])
             for c in commands],
        )
        conn.commit()


# ─────────────────────────────── read side ──────────────────────────────────
# Every function below is what Grafana hits. All are indexed lookups; none load
# the model. `frm`/`to` are epoch ms; None means unbounded.

def _window(frm: int | None, to: int | None) -> tuple[str, list]:
    clauses, params = [], []
    if frm is not None:
        clauses.append("start_ms >= ?"); params.append(frm)
    if to is not None:
        clauses.append("start_ms <= ?"); params.append(to)
    return (" AND ".join(clauses) or "1=1"), params


def summary(path: str, frm: int | None, to: int | None) -> dict:
    where, params = _window(frm, to)
    with _connect(path) as conn:
        row = conn.execute(
            f"""SELECT COUNT(*) AS scored,
                       SUM(alert) AS alerts,
                       MAX(model_name) AS model_name,
                       MAX(threshold) AS threshold
                FROM sessions WHERE {where}""", params).fetchone()
    return {
        "model_name": row["model_name"] or "none",
        "threshold": row["threshold"],
        "scored": row["scored"] or 0,
        "alerts": row["alerts"] or 0,
        "benign": (row["scored"] or 0) - (row["alerts"] or 0),
    }


def ranked(path: str, frm: int | None, to: int | None,
           identity: str | None = None, limit: int = 100) -> list[dict]:
    where, params = _window(frm, to)
    if identity and identity != "All":
        where += " AND identity = ?"; params.append(identity)
    with _connect(path) as conn:
        rows = conn.execute(
            f"""SELECT session_id, identity, score, alert, threshold, start_ms
                FROM sessions WHERE {where}
                ORDER BY score DESC LIMIT ?""", [*params, limit]).fetchall()
    out = []
    for i, r in enumerate(rows, 1):
        out.append({
            "rank": i,
            "session_id": r["session_id"],
            "identity": r["identity"],
            "label": f'{r["identity"]} | {r["session_id"][:12]}',
            "score": r["score"],
            "alert": bool(r["alert"]),
            "status": "Attack" if r["alert"] else "Benign",
            "threshold": r["threshold"],
            "time": r["start_ms"],
        })
    return out


def distribution(path: str, frm: int | None, to: int | None,
                 identity: str | None = None) -> list[dict]:
    """One row per session: its score. Grafana's Histogram panel buckets it."""
    where, params = _window(frm, to)
    if identity and identity != "All":
        where += " AND identity = ?"; params.append(identity)
    with _connect(path) as conn:
        rows = conn.execute(
            f"SELECT session_id, score, alert FROM sessions WHERE {where}",
            params).fetchall()
    return [{"session_id": r["session_id"], "score": r["score"],
             "status": "Attack" if r["alert"] else "Benign"} for r in rows]


def ratio(path: str, frm: int | None, to: int | None) -> list[dict]:
    s = summary(path, frm, to)
    return [{"status": "Attack (>= threshold)", "count": s["alerts"]},
            {"status": "Benign", "count": s["benign"]}]


def features_for(path: str, session_id: str) -> list[dict]:
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT name, value FROM features WHERE session_id=? ORDER BY ABS(value) DESC",
            (session_id,)).fetchall()
    return [{"feature": r["name"], "value": r["value"]} for r in rows]


def commands_for(path: str, session_id: str) -> list[dict]:
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT seq, ts_ms, command, risk_flag, surprisal FROM commands"
            " WHERE session_id=? ORDER BY seq", (session_id,)).fetchall()
    return [{"seq": r["seq"], "time": r["ts_ms"], "command": r["command"],
             "risk_flag": r["risk_flag"] or "-", "surprisal": r["surprisal"]}
            for r in rows]


def identities(path: str, frm: int | None, to: int | None) -> list[str]:
    where, params = _window(frm, to)
    with _connect(path) as conn:
        rows = conn.execute(
            f"SELECT DISTINCT identity FROM sessions WHERE {where} ORDER BY identity",
            params).fetchall()
    return [r["identity"] for r in rows if r["identity"]]


def session_ids(path: str, frm: int | None, to: int | None,
                identity: str | None = None) -> list[dict]:
    where, params = _window(frm, to)
    if identity and identity != "All":
        where += " AND identity = ?"; params.append(identity)
    with _connect(path) as conn:
        rows = conn.execute(
            f"""SELECT session_id, identity, score FROM sessions WHERE {where}
                ORDER BY score DESC""", params).fetchall()
    # __text is what the dropdown shows, __value is what ${session} resolves to.
    return [{"__text": f'{r["identity"]} | {r["session_id"][:12]}',
             "__value": r["session_id"]} for r in rows]
