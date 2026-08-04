#!/usr/bin/env python3
"""
extract_raw.py — raw Wazuh indexer dump for WALLIX events (diagnostic tool)
=============================================================================

Companion to extract.py. Where extract.py normalises events to the schema-contract
fields, this script does NOT touch the data at all — it pulls whatever the indexer
has for WALLIX (or literally everything, with --no-filter) and writes the untouched
_source straight to a JSONL file, one raw hit per line.

Purpose: answer questions extract.py's normalised view can hide, e.g. "does
SESSION_ESTABLISHED_SUCCESSFULLY / SESSION_DISCONNECTION ever actually arrive?",
"what rule IDs are firing?", "what does a line Wazuh couldn't decode look like?".

Also prints a quick distribution summary (event_type counts, rule.id counts) to
stderr so you don't have to open the file to get the headline answer.

Usage
-----
  # last 30 minutes, WALLIX-filtered, alerts index (default)
  python extract_raw.py --since 30m

  # everything in the window, no WALLIX filter at all (catches undecoded lines too)
  python extract_raw.py --since 30m --no-filter

  # explicit window, archives index
  python extract_raw.py --from 2026-07-31T00:00:00Z --to 2026-07-31T23:59:59Z --index archives

Credentials: same env vars as extract.py (WAZUH_INDEXER_URL/USER/PASS, WAZUH_VERIFY_TLS).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

try:
    import requests
    from requests.auth import HTTPBasicAuth
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[extract_raw] missing dependency: pip install requests urllib3", file=sys.stderr)
    raise


INDEXER_URL  = os.environ.get("WAZUH_INDEXER_URL", "https://192.168.1.32:9200")
INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
VERIFY_TLS   = os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"

ARCHIVES_INDEX = os.environ.get("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
ALERTS_INDEX   = os.environ.get("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

PAGE_SIZE = int(os.environ.get("WAZUH_PAGE_SIZE", "1000"))
REQUEST_TIMEOUT = int(os.environ.get("WAZUH_HTTP_TIMEOUT", "30"))


def _dig(doc: Dict[str, Any], dotted: str) -> Optional[Any]:
    cur: Any = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resolve_since(since: str) -> str:
    return f"now-{since}"


def _build_query(time_from: Optional[str], time_to: Optional[str],
                 since: Optional[str], apply_filter: bool) -> Dict[str, Any]:
    rng: Dict[str, Any] = {}
    if time_from:
        rng["gte"] = time_from
    if time_to:
        rng["lte"] = time_to
    if not rng and since:
        rng["gte"] = _resolve_since(since)

    if rng:
        query: Dict[str, Any] = {"bool": {"filter": [{"range": {"@timestamp": rng}}]}}
    else:
        query = {"match_all": {}} if not apply_filter else {"bool": {"filter": []}}

    if apply_filter:
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
    try:
        r = session.head(f"{INDEXER_URL}/{index}", timeout=REQUEST_TIMEOUT)
        return r.status_code == 200
    except requests.RequestException:
        return False


def fetch_raw(index: str, time_from: Optional[str], time_to: Optional[str],
              since: Optional[str], apply_filter: bool,
              max_events: Optional[int]) -> Iterable[Dict[str, Any]]:
    """Yield raw indexer hits (untouched _source, plus _index/_id/sort) as-is."""
    session = requests.Session()
    session.auth = HTTPBasicAuth(INDEXER_USER, INDEXER_PASS)
    session.verify = VERIFY_TLS
    session.headers.update({"Content-Type": "application/json"})

    if not _index_exists(session, index):
        print(f"[extract_raw] index '{index}' not found on the indexer.", file=sys.stderr)
        return

    query = _build_query(time_from, time_to, since, apply_filter)
    body: Dict[str, Any] = {
        "size": PAGE_SIZE,
        "query": query,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
    }

    url = f"{INDEXER_URL}/{index}/_search"
    emitted = 0
    search_after: Optional[List[Any]] = None

    while True:
        if search_after is not None:
            body["search_after"] = search_after
        try:
            r = session.post(url, data=json.dumps(body), timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"[extract_raw] request error: {e}", file=sys.stderr)
            return
        if r.status_code != 200:
            print(f"[extract_raw] indexer returned {r.status_code}: {r.text[:300]}",
                  file=sys.stderr)
            return

        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            row = dict(h.get("_source", {}))
            row["_index"] = h.get("_index")
            row["_id"] = h.get("_id")
            yield row
            emitted += 1
            if max_events and emitted >= max_events:
                return

        search_after = hits[-1].get("sort")
        if search_after is None:
            break


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Raw Wazuh indexer dump for WALLIX events (diagnostic)")
    p.add_argument("--index", choices=["archives", "alerts"], default="alerts",
                   help="indexer index to query (default: alerts)")
    p.add_argument("--since", default=None, help="relative window, e.g. 15m / 2h / 1d")
    p.add_argument("--from", dest="time_from", default=None, help="ISO8601 start")
    p.add_argument("--to", dest="time_to", default=None, help="ISO8601 end")
    p.add_argument("--no-filter", action="store_true",
                   help="skip the WALLIX decoder/program_name filter (pulls everything "
                        "in the window, including undecoded/non-WALLIX lines)")
    p.add_argument("--max-events", type=int, default=None, help="stop after N hits")
    p.add_argument("--out", default="./out/raw_events.jsonl", help="output path")
    args = p.parse_args(argv)

    index = ARCHIVES_INDEX if args.index == "archives" else ALERTS_INDEX
    apply_filter = not args.no_filter

    print(f"[extract_raw] index={index} since={args.since} from={args.time_from} "
          f"to={args.time_to} filter={'on' if apply_filter else 'off'}", file=sys.stderr)

    rows = list(fetch_raw(index, args.time_from, args.time_to, args.since,
                          apply_filter, args.max_events))
    print(f"[extract_raw] {len(rows)} raw hits fetched", file=sys.stderr)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[extract_raw] wrote {len(rows)} rows -> {args.out}", file=sys.stderr)

    # quick diagnostic summary
    event_types = Counter(_dig(r, "data.wallix_event") for r in rows)
    rule_ids = Counter(_dig(r, "rule.id") for r in rows)
    decoders = Counter(_dig(r, "decoder.name") for r in rows)

    print("\n[extract_raw] --- wallix_event distribution ---", file=sys.stderr)
    for val, count in event_types.most_common():
        print(f"  {val!r}: {count}", file=sys.stderr)

    print("\n[extract_raw] --- rule.id distribution ---", file=sys.stderr)
    for val, count in rule_ids.most_common():
        print(f"  {val!r}: {count}", file=sys.stderr)

    print("\n[extract_raw] --- decoder.name distribution ---", file=sys.stderr)
    for val, count in decoders.most_common():
        print(f"  {val!r}: {count}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
