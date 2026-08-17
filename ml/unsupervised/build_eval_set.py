#!/usr/bin/env python3
"""
build_eval_set.py -- join ground truth to extracted sessions -> eval_real.jsonl.

    python ml/unsupervised/build_eval_set.py --composed-only

Produces the ISOLATED EVALUATION SET: real sessions, labelled, split=eval, never
trained on. This is the artifact every headline metric in the project is measured
against, which is why it gets its own script rather than being assembled inline.

WHY THE JOIN KEY IS A COMMAND, NOT AN ID
----------------------------------------
WALLIX assigns its own opaque session_id and has no idea which scenario the
driver was running. simulate_sessions.py therefore makes each session announce
itself: `echo TAG:<tag>` is the first command it sends, so the tag lands in real
KBD_INPUT telemetry and travels the whole pipeline. The join is
ground_truth.session_tag <-> the TAG: marker found in sessions.commands[].

A session with no marker is unjoinable -- not an error in itself (some predate
the tagging, some were truncated), but it is COUNTED AND REPORTED rather than
silently dropped, because a shrinking evaluation set that nobody notices is how
metrics quietly stop meaning what they say.

--composed-only
---------------
Keeps only sessions carrying a `composition` field, i.e. those collected after
the generator gained buried-attack composition. Earlier sessions are all-attack
or all-benign, which makes the buried-attack slice unmeasurable. This is the
flag used for the current results.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT_DIR = os.path.join(ROOT, "feature_extraction", "out")

GROUND_TRUTH = os.path.join(OUT_DIR, "ground_truth.jsonl")
SESSIONS = os.path.join(OUT_DIR, "sessions.jsonl")
EVENTS = os.path.join(OUT_DIR, "events.jsonl")
OUT = os.path.join(OUT_DIR, "eval_real.jsonl")

TAG_RE = re.compile(r"TAG:([A-Za-z0-9_]+)")

# Fields taken verbatim from the extracted session, in output order.
SESSION_FIELDS = [
    "session_id", "user", "account", "client_ip", "target_ip", "target_hostname",
    "protocol", "session_start", "session_end", "duration_sec",
    "session_start_is_estimated", "session_end_is_estimated",
    "duration_sec_is_estimated", "commands", "event_types", "raw_event_count",
    "file_transfer_bytes",
]

# Fields taken verbatim from the ground-truth record.
GROUND_TRUTH_FIELDS = ["scenario", "expected_rule_ids", "mitre", "session_tag",
                       "composition"]


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def session_tag(session: dict) -> str | None:
    """The tag this session announced, or None if it never did."""
    for command in session.get("commands") or []:
        found = TAG_RE.search(command or "")
        if found:
            return found.group(1)
    return None


def fired_rules(events_path: str) -> dict:
    """session_id -> set of rule_ids that fired anywhere in that session.

    The rule layer's own verdict, carried alongside the label so the rules-vs-ML
    comparison reads a column instead of re-opening the events file.
    """
    by_session: dict = collections.defaultdict(set)
    if not os.path.exists(events_path):
        return by_session
    for event in load(events_path):
        rule = event.get("rule_id")
        if rule is not None:
            by_session[event["session_id"]].add(int(rule))
    return by_session


def build(truth: list[dict], sessions: list[dict], rules: dict,
          composed_only: bool) -> tuple[list[dict], dict]:
    by_tag = {}
    untagged = 0
    for session in sessions:
        tag = session_tag(session)
        if tag is None:
            untagged += 1
        else:
            by_tag[tag] = session

    rows, skipped = [], collections.Counter()
    kept_tags = set()

    for record in truth:
        tag = record["session_tag"]
        if composed_only and "composition" not in record:
            skipped["pre-composition ground truth"] += 1
            continue
        if record["status"] != "ok":
            skipped[f"driver status={record['status']}"] += 1
            continue
        if tag not in by_tag:
            skipped["no session carries this tag"] += 1
            continue
        kept_tags.add(tag)

    # Emit in sessions.jsonl order so the file is stable across runs regardless
    # of the order the driver happened to write ground truth in.
    truth_by_tag = {r["session_tag"]: r for r in truth}
    for session in sessions:
        tag = session_tag(session)
        if tag not in kept_tags:
            continue
        record = truth_by_tag[tag]
        attack = record["kind"] == "attack"

        row = {field: session.get(field) for field in SESSION_FIELDS}
        row["label"] = record["kind"]
        row["tactics"] = [record["scenario"]] if attack else []
        for field in GROUND_TRUTH_FIELDS[:3]:
            row[field] = record.get(field)
        row["source"] = "real"
        row["split"] = "eval"
        # An attack session has no persona: it is defined by its scenario, not by
        # a role. Benign sessions carry the persona that produced them.
        row["persona"] = None if attack else record["scenario"]
        row["session_tag"] = tag
        row["composition"] = record.get("composition")
        # Real sessions, real identities -- nothing was rewritten downstream.
        row["identity_is_synthetic"] = False
        row["ip_is_synthetic"] = False
        row["ts_is_synthetic"] = False
        # Denied commands: real telemetry from non-NOPASSWD sudoers accounts.
        # A refused escalation is an insider signal that trips no rule at all.
        row["fail_ratio"] = record.get("fail_ratio")
        row["commands_denied"] = record.get("commands_denied")
        # The rule layer's verdict on this session, for the ML-vs-rules baseline.
        row["fired_rule_ids"] = sorted(rules.get(session["session_id"], ()))
        rows.append(row)

    return rows, {"untagged_sessions": untagged, "skipped": skipped}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="join ground_truth.jsonl to sessions.jsonl -> eval_real.jsonl")
    ap.add_argument("--ground-truth", default=GROUND_TRUTH)
    ap.add_argument("--sessions", default=SESSIONS)
    ap.add_argument("--events", default=EVENTS)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--composed-only", action="store_true",
                    help="keep only sessions collected after buried-attack "
                         "composition existed (what the current results use)")
    ap.add_argument("--legacy-schema", action="store_true",
                    help="omit fail_ratio/commands_denied/fired_rule_ids -- "
                         "reproduces the original 28-field file byte for byte")
    args = ap.parse_args()

    truth = load(args.ground_truth)
    sessions = load(args.sessions)
    rules = {} if args.legacy_schema else fired_rules(args.events)

    rows, report = build(truth, sessions, rules, args.composed_only)

    if args.legacy_schema:
        for row in rows:
            for field in ("fail_ratio", "commands_denied", "fired_rule_ids"):
                row.pop(field, None)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    labels = collections.Counter(r["label"] for r in rows)
    print(f"wrote {len(rows)} sessions -> {args.out}")
    print(f"  labels    : {dict(labels)}")
    print(f"  ground truth in  : {len(truth)}   sessions in : {len(sessions)}")
    print(f"  sessions with no TAG marker : {report['untagged_sessions']}")
    for reason, count in report["skipped"].most_common():
        print(f"  skipped {count:>4}  {reason}")
    if not args.legacy_schema:
        with_denials = sum(1 for r in rows if (r.get("fail_ratio") or 0) > 0)
        with_rules = sum(1 for r in rows if r["fired_rule_ids"])
        print(f"  sessions with denied commands : {with_denials}")
        print(f"  sessions where a rule fired   : {with_rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
