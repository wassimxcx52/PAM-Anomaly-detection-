#!/usr/bin/env python3
"""
generate_benign.py -- sample persona_weighted.json into synthetic benign sessions,
draped over the synthetic org in metadata/identity_pool.json.

Output schema is IDENTICAL to extract.py's sessions.jsonl (session_id, account,
commands, session_start/end, duration_sec, ...) so transform.py consumes generated
and real sessions through the same code path -- the shared-substrate design. Extra
metadata columns (label/source/split/persona) ride along and pass through
transform.py's merge untouched.

SHARED, not benign-only: these sessions are the unsupervised track's training set
AND the 85% benign majority class of the supervised set. Attack sessions slot into
the same schema later; only the train-time filter differs per track.

Realism controls (calibrated against real_benign_calibration.json):
  --stickiness  P(a command re-uses one already issued this session) instead of a
                fresh draw. Real users repeat commands; without this, weighted
                sampling over ~800 distinct curated strings inflates
                unique_command_ratio above real. This is the argument-diversity
                knob that complements build_persona_weights' family-level --tail-mass.
  session length  bootstrapped from each persona's observed real lengths.

THE METADATA LAYER
------------------
Identity, IP, target and timestamp all come from identity_pool.json, and all four
are anchored PER USER, not per persona -- that is the whole point. Contextual
features (session_hour_zscore, new_source_ip_for_user, distinct_targets_24h) need
each identity to have a HISTORY they can deviate from; a per-persona placeholder
IP gives every user in a team the same baseline and those features degenerate.

Concretely, per user, drawn once and reused across their sessions:
  * home_ips     -- 1-2 sticky workstation IPs (from the pool)
  * home_targets -- 2-4 hosts drawn by their persona's target affinity, so
                    "dba touched dc-01" can be rare without being impossible
  * work hours   -- gaussian around THEIR mean/sd, with an on-call night tail

Benign sessions deliberately carry roaming IPs (~8% VPN, ~2% jump host) and a few
weekend/off-hours sessions. Without that coverage, "not the home IP" or
"off-hours" would separate benign from attack on its own once attacks land, and
the model would memorise metadata instead of learning behaviour
(build_identity_pool.py, THE GOVERNING RULE).

Metadata honesty (CLAUDE.md sec 10): every session here is synthetic on identity,
IP, target and time. The real values these substitute for are kept beside them
(real_user / real_client_ip / real_target_*) so the substitution stays auditable,
and the dataset is documented as semi-synthetic in the report.

Protocol: SSH only by default. The command vocabulary is Linux shell content, so
draping it over an RDP host would produce a session that could not exist -- and
RDP telemetry carries no per-command events anyway (transform.py, COMMAND_PROTOCOLS).
RDP targets in the pool stay unused until real RDP telemetry is verified.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import statistics
import uuid
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "commands_dataset")
WEIGHTED = os.path.join(DATA, "persona_weighted.json")
POOL = os.path.join(HERE, "metadata", "identity_pool.json")
PARAMS = os.path.join(HERE, "metadata", "generator_params.json")
OUT = os.path.join(HERE, "out", "generated_benign.jsonl")

# What the synthetic values stand in for -- the single real identity/IP/target
# every collected session actually carries (see feature_extraction/out/sessions.jsonl).
REAL_USER = "test-ssh"
REAL_CLIENT_IP = "192.168.1.32"
REAL_TARGET_IP = "192.168.1.74"
REAL_TARGET_HOST = "debian-lab"

# Per-user habitual host set: how many hosts a user normally touches, and how
# often they step outside it. Both benign -- an occasional new host is normal,
# which is exactly what stops distinct_targets_24h being a free label.
HOME_TARGETS_MIN, HOME_TARGETS_MAX = 2, 4
P_OFF_HOME_TARGET = 0.15

# Benign sessions that land on a weekend / an on-call night. Small but non-zero:
# see module docstring.
P_WEEKEND = 0.04
P_ONCALL_NIGHT = 0.06

# A privileged account is entitled for admins but not their daily driver.
PRIVILEGED_ACCOUNT_WEIGHT = 0.15


# --------------------------------------------------------------- commands ---

def load_fitted_params(path: str = PARAMS) -> dict:
    """Defaults for the two realism knobs, as fitted by fit_generator.py.

    Read rather than hardcoded so re-fitting against a new calibration slice
    changes the generator without a code edit. Missing file -> unfitted zeros,
    which reproduces the pre-calibration behaviour instead of failing.
    """
    defaults = {"length_tilt": 0.0, "stickiness": 0.0, "arg_variation": 0.0}
    try:
        with open(path, encoding="utf-8") as fh:
            return {**defaults, **json.load(fh)["params"]}
    except (OSError, KeyError, json.JSONDecodeError):
        return defaults


def tilt_weights(vocab: list[dict], beta: float) -> list[dict]:
    """Exponential tilting of the sampling weights toward longer commands.

    Standardising length within the persona's own vocabulary means beta has the
    same meaning for a 289-command vocab and a 561-command one, and keeps exp()
    away from overflow. Lives here, not in fit_generator.py, so generation and
    fitting cannot drift apart (fit_generator imports it from this module).
    """
    if beta == 0.0:
        return vocab
    lengths = [len(r["command"]) for r in vocab]
    mu = statistics.mean(lengths)
    sd = statistics.pstdev(lengths) or 1.0
    return [dict(r, weight=r["weight"] * math.exp(beta * (len(r["command"]) - mu) / sd))
            for r in vocab]


def sample_length(observed: list[int], median: int, rng: random.Random) -> int:
    if observed:
        return max(1, rng.choice(observed))
    return max(1, median)


# ---------------------------------------------------------- argument variation ---
# WHY THIS EXISTS. The curated vocabulary is ~850 fixed strings. Sampled 42k
# times they all recur constantly, so the generated benign vocabulary is CLOSED:
# no held-out benign session can ever contain a command the rest have not
# already shown. Real benign is open -- an operator greps a config they will
# never grep again -- and against the same profile real benign carries a ~1.4%
# out-of-vocabulary rate while generated benign carries exactly 0.
#
# That gap is not cosmetic. It makes cmd_oov_rate / cmd_*_novelty perfect
# separators in training (measured: 5-fold CV PR-AUC 1.0000 +/- 0.0000), so the
# model learns "an unseen command means attack" instead of a calibrated
# threshold, and every real benign session using an unlisted command becomes a
# false positive at scoring time.
#
# THE MECHANISM COPIES HOW REAL NOVELTY ARISES: novel ARGUMENTS, not novel
# programs. Real benign runs `grep` constantly and
# `grep cron /etc/rsyslog.d/50-default.conf` once. So paths, filenames and
# numeric arguments are resampled from large pools while the program and its
# flags stay exactly as curated -- the command remains something that persona
# plausibly typed, and command_safety's guarantees are untouched because no head
# and no redirection is introduced.
_VARY_DIRS = ["/var/log", "/var/lib", "/var/spool", "/etc", "/srv", "/opt",
              "/data", "/home", "/usr/share", "/usr/local", "/tmp", "/mnt"]
_VARY_SUBDIRS = ["nginx", "apache2", "postgres", "mysql", "app", "releases",
                 "backup", "archive", "reports", "exports", "cache", "conf.d",
                 "sites-available", "journal", "audit", "cron.d", "systemd",
                 "projects", "shared", "staging", "batch", "ingest"]
_VARY_STEMS = ["access", "error", "audit", "debug", "report", "export", "batch",
               "index", "summary", "config", "backup", "session", "metrics",
               "ingest", "billing", "orders", "customers", "inventory", "payroll"]
_VARY_EXTS = ["log", "txt", "conf", "csv", "json", "yaml", "sql", "dat", "bak", "sh"]

_ABS_PATH_RE = re.compile(r"(?<![\w/])/(?:[\w.-]+/)*[\w.-]+")
_FILENAME_RE = re.compile(r"(?<![\w/.])[\w-]+\.(?:txt|log|conf|csv|json|sh|sql|dat|bak)\b")
_INTEGER_RE = re.compile(r"(?<![\w.-])\d{1,4}(?![\w.-])")


def _random_path(rng: random.Random) -> str:
    path = rng.choice(_VARY_DIRS)
    for _ in range(rng.randint(0, 2)):
        path += "/" + rng.choice(_VARY_SUBDIRS)
    return path


def _random_filename(rng: random.Random) -> str:
    stem = rng.choice(_VARY_STEMS)
    if rng.random() < 0.5:
        stem += rng.choice(["_2026", "-01", "_prod", "-old", "_v2", f"_{rng.randint(1, 99)}"])
    return f"{stem}.{rng.choice(_VARY_EXTS)}"


def vary_arguments(command: str, rng: random.Random) -> str:
    """Resample the paths / filenames / small integers in one command.

    Substitutions are positional and independent, so one curated string maps to
    a large space of plausible variants -- which is what makes a generated
    session able to contain a command no other session contains.
    """
    command = _ABS_PATH_RE.sub(lambda _: _random_path(rng), command, count=2)
    command = _FILENAME_RE.sub(lambda _: _random_filename(rng), command, count=2)
    if rng.random() < 0.3:
        command = _INTEGER_RE.sub(lambda _: str(rng.randint(1, 999)), command, count=1)
    return command


def sample_commands(vocab: list[dict], length: int, stickiness: float,
                    rng: random.Random, arg_variation: float = 0.0) -> list[str]:
    cmds = [r["command"] for r in vocab]
    weights = [r["weight"] for r in vocab]
    issued: list[str] = []
    for _ in range(length):
        if issued and rng.random() < stickiness:
            issued.append(rng.choice(issued))          # re-run something already typed
        else:
            command = rng.choices(cmds, weights=weights, k=1)[0]
            # Variation applies only to a FRESH draw: stickiness means the user
            # re-ran the same thing, so a re-use must be the identical string or
            # unique_command_ratio silently stops meaning what it says.
            if arg_variation and rng.random() < arg_variation:
                command = vary_arguments(command, rng)
            issued.append(command)
    return issued


# --------------------------------------------------------------- identity ---

def weighted_targets(persona: str, pool: dict, protocols: set[str]) -> tuple[list, list]:
    """Targets reachable by this persona + their sampling weights.

    Weight is the persona's affinity for the host's GROUP, spread evenly over the
    hosts in that group, so a group's pull does not scale with how many machines
    happen to be in it.
    """
    affinity = pool["target_affinity"][persona]
    allowed = [t for t in pool["targets"] if t["protocol"] in protocols]
    per_group = {}
    for t in allowed:
        per_group[t["group"]] = per_group.get(t["group"], 0) + 1
    weights = [affinity.get(t["group"], 0.0) / per_group[t["group"]] for t in allowed]
    if not any(weights):                    # persona has no affinity for any allowed host
        weights = [1.0] * len(allowed)
    return allowed, weights


def pick_account(user: dict, pool: dict, rng: random.Random) -> str:
    """Draw a vaulted account from the user's entitlement set. Privileged accounts
    are entitled but rare in benign traffic -- they must appear, or 'borrowed
    p_admin' becomes a pure attack marker rather than an unusual-but-possible act."""
    privileged = set(pool.get("privileged_accounts", []))
    accounts = user["entitled_accounts"]
    weights = [PRIVILEGED_ACCOUNT_WEIGHT if a in privileged else 1.0 for a in accounts]
    return rng.choices(accounts, weights=weights, k=1)[0]


def pick_ip(user: dict, pool: dict, rng: random.Random) -> tuple[str, str]:
    """(client_ip, ip_source). Mostly the user's own workstation; sometimes VPN or
    a shared jump host. Jump IPs are shared across many users on purpose: it makes
    'globally known IP' and 'normal for THIS user' diverge, which is the exact
    distinction new_source_ip_for_user has to capture."""
    meta = pool["_meta"]
    roll = rng.random()
    if roll < meta["benign_vpn_rate"]:
        return f"10.99.{rng.randint(0, 255)}.{rng.randint(2, 254)}", "vpn"
    if roll < meta["benign_vpn_rate"] + meta["benign_jump_rate"]:
        return rng.choice(pool["roaming"]["jump_ips"]), "jump"
    return rng.choice(user["home_ips"]), "home"


def pick_start(user: dict, day_span: int, base: datetime,
               rng: random.Random) -> datetime:
    """Timestamp from THIS user's own hour distribution, not a flat 08-18 window.

    The gaussian tails produce genuine early/late sessions, so off_hours_flag is a
    soft signal rather than a switch. On-call users additionally get real night
    sessions: 03:00 is normal for the admin on call and anomalous for everyone
    else -- the nuance that makes session_hour_zscore earn its place over a flat
    off-hours boolean.
    """
    day = base + timedelta(days=rng.randrange(day_span))
    if day.weekday() >= 5 and rng.random() >= P_WEEKEND:
        day += timedelta(days=7 - day.weekday())       # push to the next Monday

    if user["oncall_eligible"] and rng.random() < P_ONCALL_NIGHT:
        hour = rng.choice([22, 23, 0, 1, 2, 3, 4, 5])
    else:
        hour = int(min(23.999, max(0.0, rng.gauss(user["work_hour_mean"],
                                                  user["work_hour_sd"]))))
    return day.replace(hour=hour, minute=rng.randint(0, 59),
                       second=rng.randint(0, 59))


def build_profiles(pool: dict, protocols: set[str], rng: random.Random) -> list[dict]:
    """Freeze each user's habitual host set once, so it is a stable baseline across
    all their sessions instead of being re-rolled per session."""
    profiles = []
    for user in pool["users"]:
        allowed, weights = weighted_targets(user["persona"], pool, protocols)
        if not allowed:
            continue
        k = min(rng.randint(HOME_TARGETS_MIN, HOME_TARGETS_MAX), len(allowed))
        home: list[dict] = []
        while len(home) < k:
            pick = rng.choices(allowed, weights=weights, k=1)[0]
            if pick not in home:
                home.append(pick)
        profiles.append({"user": user, "targets": allowed, "weights": weights,
                         "home_targets": home})
    return profiles


def allocate(profiles: list[dict], per_persona: int) -> dict[str, int]:
    """Split each persona's session budget across its users in proportion to
    sessions_per_workday. Uneven volume per user is deliberate: a light user is a
    thin baseline, which is the cold-start condition we want represented."""
    by_persona: dict[str, list[dict]] = {}
    for p in profiles:
        by_persona.setdefault(p["user"]["persona"], []).append(p)

    counts: dict[str, int] = {}
    for persona, group in by_persona.items():
        total_rate = sum(p["user"]["sessions_per_workday"] for p in group)
        assigned = 0
        for p in group[:-1]:
            share = p["user"]["sessions_per_workday"] / total_rate
            n = max(1, round(per_persona * share))
            counts[p["user"]["user"]] = n
            assigned += n
        # last user absorbs the rounding remainder so the persona total is exact
        counts[group[-1]["user"]["user"]] = max(1, per_persona - assigned)
    return counts


# ------------------------------------------------------------------- main ---

def main() -> int:
    fitted = load_fitted_params()

    ap = argparse.ArgumentParser()
    ap.add_argument("--per-persona", type=int, default=200,
                    help="sessions per persona, split across that persona's users")
    ap.add_argument("--stickiness", type=float, default=fitted["stickiness"],
                    help="P(re-use a command already issued this session) "
                         f"(fitted default {fitted['stickiness']})")
    ap.add_argument("--length-tilt", type=float, default=fitted["length_tilt"],
                    help="exponential tilt of the vocab toward longer commands "
                         f"(fitted default {fitted['length_tilt']})")
    ap.add_argument("--arg-variation", type=float, default=fitted["arg_variation"],
                    help="P(resample a fresh command's paths/filenames/numbers), "
                         "which is what opens the benign vocabulary "
                         f"(fitted default {fitted['arg_variation']})")
    ap.add_argument("--day-span", type=int, default=30,
                    help="spread synthetic timestamps over N days")
    ap.add_argument("--start-date", default="2026-06-01",
                    help="first day of the synthetic observation window (YYYY-MM-DD)")
    ap.add_argument("--protocols", default="SSH",
                    help="comma-separated target protocols to draw from")
    ap.add_argument("--pool", default=POOL, help="identity_pool.json")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    weighted = json.load(open(WEIGHTED, encoding="utf-8"))
    pool = json.load(open(args.pool, encoding="utf-8"))
    protocols = {p.strip().upper() for p in args.protocols.split(",") if p.strip()}
    base = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    profiles = [p for p in build_profiles(pool, protocols, rng)
                if p["user"]["persona"] in weighted]
    if not profiles:
        raise SystemExit("no pool user matches a persona in persona_weighted.json")
    budget = allocate(profiles, args.per_persona)

    n = 0
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for prof in profiles:
            user = prof["user"]
            persona = user["persona"]
            blk = weighted[persona]
            vocab = tilt_weights(blk["commands"], args.length_tilt)
            observed = blk["session_length"]["observed"]
            median = blk["session_length"]["median"]

            for _ in range(budget[user["user"]]):
                length = sample_length(observed, median, rng)
                commands = sample_commands(vocab, length, args.stickiness, rng,
                                           args.arg_variation)
                start = pick_start(user, args.day_span, base, rng)
                dur = sum(rng.uniform(0.4, 1.3) for _ in commands)
                end = start + timedelta(seconds=dur)

                if rng.random() < P_OFF_HOME_TARGET:
                    target = rng.choices(prof["targets"], weights=prof["weights"], k=1)[0]
                else:
                    target = rng.choice(prof["home_targets"])
                client_ip, ip_source = pick_ip(user, pool, rng)

                rec = {
                    "session_id": f"gen-{uuid.UUID(int=rng.getrandbits(128)).hex[:24]}",
                    "user": user["user"],
                    "account": pick_account(user, pool, rng),
                    "client_ip": client_ip,
                    "target_ip": target["target_ip"],
                    "target_hostname": target["target_hostname"],
                    "protocol": target["protocol"],
                    "session_start": start.isoformat(),
                    "session_end": end.isoformat(),
                    "duration_sec": round(dur, 2),
                    "commands": commands,
                    "event_types": ["KBD_INPUT"] * len(commands),
                    "raw_event_count": len(commands),
                    "file_transfer_bytes": 0,
                    # --- ride-along metadata (shared substrate) ---
                    "label": "benign",
                    "tactics": [],
                    "source": "generated",
                    "split": "train",
                    "persona": persona,
                    "ip_source": ip_source,
                    "target_group": target["group"],
                    # evaluation metadata for risk = anomaly x impact, NOT a model
                    # input feature (build_identity_pool.py, TARGETS)
                    "target_criticality": target["criticality"],
                    # --- auditability of the synthetic substitution ---
                    "identity_is_synthetic": True,
                    "ip_is_synthetic": True,
                    "ts_is_synthetic": True,
                    "real_user": REAL_USER,
                    "real_client_ip": REAL_CLIENT_IP,
                    "real_target_ip": REAL_TARGET_IP,
                    "real_target_hostname": REAL_TARGET_HOST,
                }
                fh.write(json.dumps(rec) + "\n")
                n += 1

    print(f"wrote {n} benign sessions -> {args.out} "
          f"(stickiness={args.stickiness}, length_tilt={args.length_tilt}, "
          f"arg_variation={args.arg_variation}, {args.per_persona}/persona, "
          f"{len(profiles)} users, protocols={sorted(protocols)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
