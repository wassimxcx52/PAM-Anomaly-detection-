#!/usr/bin/env python3
"""
extract.py — WALLIX/Wazuh event extractor for the insider-threat feature pipeline
=================================================================================

Pulls raw WALLIX session events from the Wazuh **indexer** (OpenSearch, port 9200)
and normalises them to the project's schema-contract fields. Emits both:

  * raw events    -> one normalised event dict per line (events.jsonl)
  * sessionized   -> events grouped by session_id into session objects (sessions.jsonl)

Design decisions baked in (see decision_log.md):
  * SOURCE = archives, not alerts. The ML pipeline must see EVERY command to compute
    command_entropy / command_count, not only the rule-triggering ones. Alerts as the
    source would impose a structural recall ceiling.
  * source= flag {fixture | generated | indexer} so transform.py can be built and
    tested WITHOUT live-system access (dependency isolation).
  * search_after pagination — the 10,000-hit window cap makes from/size unusable for
    bulk historical pulls.
  * as_of / time-window params — prevent future leakage when computing baselines.

Credentials: dev defaults hardcoded, overridable by environment variables.

Usage
-----
  # live pull from the indexer, last 15 minutes, both outputs
  python extract.py --source indexer --since 15m --out-dir ./out

  # explicit window (prevents future leakage for baseline builds)
  python extract.py --source indexer --from 2026-07-24T00:00:00Z --to 2026-07-24T13:00:00Z

  # offline development against a saved fixture
  python extract.py --source fixture --fixture-file sample_events.jsonl

  # only raw events, no sessionization
  python extract.py --source indexer --since 1h --no-sessionize

Enabling the archives index (required for --source indexer against archives)
---------------------------------------------------------------------------
Wazuh writes archives to /var/ossec/logs/archives/archives.json but does NOT ship
them to the indexer by default. To create the wazuh-archives-* index:
  1. ossec.conf:   <logall_json>yes</logall_json>
  2. In the manager's filebeat.yml, enable the archives input
     (filebeat.modules -> wazuh -> archives: enabled: true), or set
     `archives.enabled: true` in /etc/filebeat/filebeat.yml, then restart filebeat.
  3. Create the index pattern wazuh-archives-* in the dashboard.
If the index is absent, this script says so and (optionally) falls back to alerts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import requests
    from requests.auth import HTTPBasicAuth
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[extract] missing dependency: pip install requests urllib3", file=sys.stderr)
    raise


# ─────────────────────────── configuration ─────────────────────────────────
# Dev defaults; every one is overridable by the matching env var.
INDEXER_URL   = os.environ.get("WAZUH_INDEXER_URL", "https://192.168.1.32:9200")
INDEXER_USER  = os.environ.get("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS  = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
VERIFY_TLS    = os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"

ARCHIVES_INDEX = os.environ.get("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
ALERTS_INDEX   = os.environ.get("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

PAGE_SIZE = int(os.environ.get("WAZUH_PAGE_SIZE", "1000"))
REQUEST_TIMEOUT = int(os.environ.get("WAZUH_HTTP_TIMEOUT", "30"))

# WALLIX events carry these decoded fields under _source.data.* (from wallix_decoder).
# We map them to the schema-contract names. Left = schema field, right = source path.
FIELD_MAP = {
    "session_id":      "data.session_id",
    "user":            "data.srcuser",       # Bastion login user
    "account":         "data.dstuser",       # vaulted target account
    "client_ip":       "data.srcip",
    "target_ip":       "data.dstip",
    "target_hostname": "data.dsthost",
    "protocol":        "data.protocol",
    "event_type":      "data.wallix_event",
    "command":         "data.command",
    "duration_raw":    "data.duration",      # H:MM:SS on SESSION_DISCONNECTION
}


# ─────────────────────────── helpers ───────────────────────────────────────
def _dig(doc: Dict[str, Any], dotted: str) -> Optional[Any]:
    """Fetch a nested value by dotted path, returning None if any hop is missing."""
    cur: Any = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a WALLIX/Wazuh timestamp ('...T...±HHMM') into an aware datetime.
    Returns None if absent/unparseable so callers can skip it safely."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            return None


def _parse_duration(raw: Optional[str]) -> Optional[int]:
    """'H:MM:SS' -> total seconds. Returns None if absent/unparseable."""
    if not raw or not isinstance(raw, str):
        return None
    parts = raw.split(":")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) == 3:
        h, m, s = nums
    elif len(nums) == 2:
        h, m, s = 0, nums[0], nums[1]
    else:
        return None
    return h * 3600 + m * 60 + s


# A typed command may contain a double quote, which WALLIX escapes as \" inside
# data=""/command_line="". The decoder's original [^"]* capture stopped at that
# escaped quote and truncated the command; wallix_decoder.xml now uses the
# escape-aware form below. This module keeps its own copy for two reasons:
#   * REPAIR. full_log preserves the complete line, so events already collected
#     under the old decoder are recoverable without re-running any sessions --
#     which matters because the sessions themselves cannot be re-collected.
#   * INDEPENDENCE. It makes extract.py correct regardless of which decoder
#     version is deployed on the live manager, and the two copies are checked
#     against each other by the 244-event corpus documented in the decoder.
_DATA_FIELD_RE = re.compile(r'(?:data|command_line)="((?:[^"\\]|\\.)*)"')


def _unescape(value: str) -> str:
    r"""Undo WALLIX's transport escaping (\" -> ", \\ -> \).

    The escapes are an artifact of the syslog field encoding, not something the
    operator typed, so they must not reach command_entropy / avg_command_length.
    full_log keeps the escaped original for audit.
    """
    return value.replace('\\"', '"').replace("\\\\", "\\")


def repair_command(event: Dict[str, Any]) -> Dict[str, Any]:
    """Recover a command truncated by the old decoder, using full_log.

    Only replaces the decoder's value when the re-parsed one EXTENDS it (the
    decoder's value is a prefix). That way a correctly decoded command is never
    overwritten, and a genuinely different parse is left alone rather than
    silently preferred -- if the two disagree in any other way, that is a decoder
    bug to investigate, not something to paper over here.
    """
    full_log, command = event.get("full_log"), event.get("command")
    if not full_log or not isinstance(command, str):
        return event

    match = _DATA_FIELD_RE.search(full_log)
    if not match:
        return event

    recovered = match.group(1)
    if recovered != command and recovered.startswith(command):
        event["command"] = _unescape(recovered)
        event["command_was_truncated"] = True
    elif "\\" in command:
        event["command"] = _unescape(command)
    return event


def normalise(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Map one indexer hit (_source) to schema-contract fields."""
    src = hit.get("_source", hit)
    out: Dict[str, Any] = {}
    for schema_field, path in FIELD_MAP.items():
        out[schema_field] = _dig(src, path)

    # timestamp: prefer the event timestamp, fall back to predecoder time
    out["timestamp"] = src.get("timestamp") or _dig(src, "predecoder.timestamp")

    # rule metadata is present when reading from alerts; harmless (None) for archives
    out["rule_id"] = _dig(src, "rule.id")
    out["rule_level"] = _dig(src, "rule.level")

    # keep the raw log line for auditing / debugging the decoder
    out["full_log"] = src.get("full_log")

    # derived
    out["duration_sec"] = _parse_duration(out.pop("duration_raw", None))

    return repair_command(out)


# ─────────────────────────── sources ───────────────────────────────────────
def _resolve_since(since: str) -> str:
    """Turn a shorthand like '15m'/'2h'/'1d' into an OpenSearch date-math string."""
    return f"now-{since}"


def _build_query(time_from: Optional[str], time_to: Optional[str],
                 since: Optional[str]) -> Dict[str, Any]:
    """Range query on @timestamp. Prefers explicit from/to; else since; else all."""
    rng: Dict[str, Any] = {}
    if time_from:
        rng["gte"] = time_from
    if time_to:
        rng["lte"] = time_to
    if not rng and since:
        rng["gte"] = _resolve_since(since)

    if rng:
        query = {"bool": {"filter": [{"range": {"@timestamp": rng}}]}}
    else:
        query = {"match_all": {}}

    # Restrict to WALLIX events regardless of index: decoder name or program.
    # This keeps appliance OS noise (sudo/sshd/cron) out even if the archives
    # index still contains it.
    wallix_filter = {
        "bool": {
            "should": [
                {"term": {"decoder.name": "wallix"}},
                {"term": {"predecoder.program_name": "sshproxy"}},
                {"term": {"predecoder.program_name": "rdpproxy"}},
            ],
            "minimum_should_match": 1,
        }
    }
    if "bool" in query:
        query["bool"].setdefault("filter", []).append(wallix_filter)
    else:
        query = {"bool": {"filter": [wallix_filter]}}
    return query


def _index_exists(session: requests.Session, index: str) -> bool:
    url = f"{INDEXER_URL}/{index}"
    try:
        r = session.head(url, timeout=REQUEST_TIMEOUT)
        return r.status_code == 200
    except requests.RequestException:
        return False


def from_indexer(index: str, time_from: Optional[str], time_to: Optional[str],
                 since: Optional[str], max_events: Optional[int]) -> Iterable[Dict[str, Any]]:
    """Yield normalised events from the indexer, paginating with search_after."""
    session = requests.Session()
    session.auth = HTTPBasicAuth(INDEXER_USER, INDEXER_PASS)
    session.verify = VERIFY_TLS
    session.headers.update({"Content-Type": "application/json"})

    # Resolve which index to actually hit, with a clear message if archives absent.
    target = index
    if index == ARCHIVES_INDEX and not _index_exists(session, ARCHIVES_INDEX):
        print(f"[extract] WARNING: '{ARCHIVES_INDEX}' not found on the indexer.",
              file=sys.stderr)
        print("[extract] Archives are not being shipped to the indexer. Either enable "
              "the archives Filebeat module (see module docstring), or re-run with "
              "--source indexer --index alerts to use alerts instead.", file=sys.stderr)
        if _index_exists(session, ALERTS_INDEX):
            print(f"[extract] Falling back to '{ALERTS_INDEX}' for this run.",
                  file=sys.stderr)
            target = ALERTS_INDEX
        else:
            print("[extract] Neither archives nor alerts index is reachable. Aborting.",
                  file=sys.stderr)
            return

    query = _build_query(time_from, time_to, since)
    body: Dict[str, Any] = {
        "size": PAGE_SIZE,
        "query": query,
        # deterministic sort required for search_after; tiebreak on _id
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
    }

    url = f"{INDEXER_URL}/{target}/_search"
    emitted = 0
    search_after: Optional[List[Any]] = None

    while True:
        if search_after is not None:
            body["search_after"] = search_after
        try:
            r = session.post(url, data=json.dumps(body), timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"[extract] request error: {e}", file=sys.stderr)
            return
        if r.status_code != 200:
            print(f"[extract] indexer returned {r.status_code}: {r.text[:300]}",
                  file=sys.stderr)
            return

        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            yield normalise(h)
            emitted += 1
            if max_events and emitted >= max_events:
                return

        # advance the cursor
        search_after = hits[-1].get("sort")
        if search_after is None:
            break


def from_fixture(path: str) -> Iterable[Dict[str, Any]]:
    """Read events from a saved JSONL file. Accepts either raw indexer hits
    (_source present) or already-normalised events."""
    if not os.path.isfile(path):
        print(f"[extract] fixture not found: {path}", file=sys.stderr)
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # if it looks like a raw hit, normalise; else pass through.
            # Already-normalised events still go through repair_command: a
            # fixture saved under the old decoder carries truncated commands and
            # full_log alongside them, which is exactly the recoverable case.
            if "_source" in obj or "data" in obj:
                yield normalise(obj if "_source" in obj else {"_source": obj})
            else:
                yield repair_command(obj)


def from_generated(path: str) -> Iterable[Dict[str, Any]]:
    """Alias for fixture semantics, but intended for synthetically generated data
    (e.g. from the attack/benign generators re-serialised as events). Kept separate
    so the source of truth is explicit in logs and in downstream provenance."""
    yield from from_fixture(path)


# ─────────────────────────── sessionize ────────────────────────────────────
def sessionize(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group normalised events by session_id into session objects.

    Each session object carries the stable identity fields plus the ordered list
    of commands and a few conveniences transform.py will want. Events with no
    session_id are grouped under a synthetic '_no_session' bucket so nothing is
    silently dropped.

    session_start/session_end/duration_sec are primarily set from the
    SESSION_ESTABLISHED_SUCCESSFULLY/SESSION_DISCONNECTION lifecycle events. If
    WALLIX never forwards those (e.g. the SIEM Integration filter only has
    KBD_INPUT checked), they fall back to the min/max timestamp seen across the
    session's own events -- an approximation (misses idle time before the first
    keystroke and after the last), flagged via *_is_estimated so transform.py can
    tell real boundaries from inferred ones.
    """
    sessions: Dict[str, Dict[str, Any]] = {}

    for ev in events:
        sid = ev.get("session_id") or "_no_session"
        s = sessions.get(sid)
        if s is None:
            s = {
                "session_id": sid,
                "user": ev.get("user"),
                "account": ev.get("account"),
                "client_ip": ev.get("client_ip"),
                "target_ip": ev.get("target_ip"),
                "target_hostname": ev.get("target_hostname"),
                "protocol": ev.get("protocol"),
                "session_start": None,
                "session_end": None,
                "duration_sec": None,
                "session_start_is_estimated": False,
                "session_end_is_estimated": False,
                "duration_sec_is_estimated": False,
                "commands": [],
                "event_types": [],
                "raw_event_count": 0,
                "file_transfer_bytes": 0,  # populated later if a FILE event carries it
                "_first_ts": None,
                "_last_ts": None,
            }
            sessions[sid] = s

        # backfill identity fields if the first event lacked them
        for k in ("user", "account", "client_ip", "target_ip",
                  "target_hostname", "protocol"):
            if not s.get(k) and ev.get(k):
                s[k] = ev[k]

        etype = ev.get("event_type")
        if etype:
            s["event_types"].append(etype)

        # lifecycle markers
        ts = ev.get("timestamp")
        if etype == "SESSION_ESTABLISHED_SUCCESSFULLY" and ts:
            s["session_start"] = ts
        if etype == "SESSION_DISCONNECTION":
            if ts:
                s["session_end"] = ts
            if ev.get("duration_sec") is not None:
                s["duration_sec"] = ev["duration_sec"]

        # track first/last seen timestamp regardless of event type, as a
        # fallback for sessions where WALLIX never forwards the lifecycle
        # events (see sessionize docstring)
        ts_parsed = _parse_ts(ts)
        if ts_parsed is not None:
            if s["_first_ts"] is None or ts_parsed < s["_first_ts"]:
                s["_first_ts"] = ts_parsed
            if s["_last_ts"] is None or ts_parsed > s["_last_ts"]:
                s["_last_ts"] = ts_parsed

        # collect commands in arrival order
        if etype == "KBD_INPUT" and ev.get("command") is not None:
            s["commands"].append(ev["command"])

        s["raw_event_count"] += 1

    for s in sessions.values():
        first_ts, last_ts = s.pop("_first_ts"), s.pop("_last_ts")
        if s["session_start"] is None and first_ts is not None:
            s["session_start"] = first_ts.isoformat()
            s["session_start_is_estimated"] = True
        if s["session_end"] is None and last_ts is not None:
            s["session_end"] = last_ts.isoformat()
            s["session_end_is_estimated"] = True
        if s["duration_sec"] is None and first_ts is not None and last_ts is not None:
            s["duration_sec"] = max(0, round((last_ts - first_ts).total_seconds()))
            s["duration_sec_is_estimated"] = True

    return list(sessions.values())


# ─────────────────────────── output ────────────────────────────────────────
def write_jsonl(path: str, rows: Iterable[Dict[str, Any]]) -> int:
    """Overwrite: write rows to path, replacing any existing content."""
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def _read_existing(path: str) -> List[Dict[str, Any]]:
    """Load previously-written rows from a JSONL file. Returns [] if absent."""
    if not os.path.isfile(path):
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _event_key(ev: Dict[str, Any]) -> str:
    """Composite dedup key for a single event: session + timestamp + event type
    + command. Two identical events pulled in overlapping windows collapse to one."""
    return "||".join(str(ev.get(k, "")) for k in
                     ("session_id", "timestamp", "event_type", "command"))


def merge_append(path: str, new_rows: List[Dict[str, Any]],
                 key_fn, kind: str) -> int:
    """Append new_rows to whatever is already in `path`, de-duplicating by key_fn.

    Existing rows are kept as-is; a new row is written only if its key hasn't been
    seen. For sessions, the key is session_id: a re-pulled session does NOT append a
    duplicate. (If you want re-pulled sessions to REPLACE the old copy — e.g. because
    more commands arrived since — see the note in the README; this implementation
    keeps the first-seen copy to stay append-only and deterministic.)

    Returns the number of rows actually added.
    """
    existing = _read_existing(path)
    seen = {key_fn(r) for r in existing}

    added = 0
    merged = list(existing)
    for r in new_rows:
        k = key_fn(r)
        if k in seen:
            continue
        seen.add(k)
        merged.append(r)
        added += 1

    write_jsonl(path, merged)
    print(f"[extract] {kind}: {len(existing)} existing + {added} new "
          f"= {len(merged)} total -> {path}", file=sys.stderr)
    return added


# ─────────────────────────── main ──────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="WALLIX/Wazuh event extractor")
    p.add_argument("--source", choices=["indexer", "fixture", "generated"],
                   default="indexer",
                   help="where to read events from (default: indexer)")
    p.add_argument("--index", choices=["archives", "alerts"], default="archives",
                   help="indexer index to query when --source indexer (default: archives)")
    p.add_argument("--since", default=None,
                   help="relative window, e.g. 15m / 2h / 1d (ignored if --from given)")
    p.add_argument("--from", dest="time_from", default=None,
                   help="ISO8601 start, e.g. 2026-07-24T00:00:00Z (as_of lower bound)")
    p.add_argument("--to", dest="time_to", default=None,
                   help="ISO8601 end (as_of upper bound; prevents future leakage)")
    p.add_argument("--max-events", type=int, default=None,
                   help="stop after N events (debugging)")
    p.add_argument("--fixture-file", default="sample_events.jsonl",
                   help="path for --source fixture/generated")
    p.add_argument("--out-dir", default="./out", help="output directory")
    p.add_argument("--no-sessionize", action="store_true",
                   help="skip writing the sessionized view")
    p.add_argument("--overwrite", action="store_true",
                   help="replace existing output files instead of appending "
                        "(default is append + de-duplicate, so data accumulates "
                        "across runs)")
    args = p.parse_args(argv)

    if args.time_from and not args.time_to:
        print("[extract] note: --from without --to; using open-ended upper bound "
              "(may include future events if the clock/window overlaps).",
              file=sys.stderr)

    os.makedirs(args.out_dir, exist_ok=True)

    # pick the source
    if args.source == "indexer":
        index = ARCHIVES_INDEX if args.index == "archives" else ALERTS_INDEX
        print(f"[extract] source=indexer index={index} "
              f"since={args.since} from={args.time_from} to={args.time_to}",
              file=sys.stderr)
        gen = from_indexer(index, args.time_from, args.time_to, args.since,
                           args.max_events)
    elif args.source == "fixture":
        print(f"[extract] source=fixture file={args.fixture_file}", file=sys.stderr)
        gen = from_fixture(args.fixture_file)
    else:  # generated
        print(f"[extract] source=generated file={args.fixture_file}", file=sys.stderr)
        gen = from_generated(args.fixture_file)

    events = list(gen)
    print(f"[extract] {len(events)} events extracted this run", file=sys.stderr)

    events_path = os.path.join(args.out_dir, "events.jsonl")
    if args.overwrite:
        n_ev = write_jsonl(events_path, events)
        print(f"[extract] OVERWROTE with {n_ev} events -> {events_path}",
              file=sys.stderr)
    else:
        merge_append(events_path, events, _event_key, "events")

    if not args.no_sessionize:
        sessions = sessionize(events)
        sessions_path = os.path.join(args.out_dir, "sessions.jsonl")
        if args.overwrite:
            n_s = write_jsonl(sessions_path, sessions)
            print(f"[extract] OVERWROTE with {n_s} sessions -> {sessions_path}",
                  file=sys.stderr)
        else:
            merge_append(sessions_path, sessions,
                         lambda s: str(s.get("session_id", "")), "sessions")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())