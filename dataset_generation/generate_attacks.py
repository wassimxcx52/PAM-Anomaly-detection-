#!/usr/bin/env python3
"""
generate_attacks.py -- synthetic ATTACK sessions, in the same schema and over the
same synthetic org as generate_benign.py.

Schema is identical to extract.py's sessions.jsonl, so transform.py consumes
benign and attack sessions through one code path. Only the ride-along metadata
differs: label="attack", plus `tactics` / `mitre` / `composition` / `intensity`
recording HOW the session was built, which is evaluation metadata, not model
input.

THE ONE RULE THIS FILE IS ORGANISED AROUND
------------------------------------------
An attack session must differ from a benign one BEHAVIOURALLY, and in nothing
else. Every incidental difference -- a filler vocabulary drawn with different
knobs, an always-off-hours timestamp, an always-foreign IP, an always-privileged
account -- is a shortcut the model will take instead of learning behaviour, and
it inflates every metric invisibly. So:

  * benign filler comes from the SAME persona_weighted.json, sampled with the
    SAME stickiness and length_tilt (generator_params.json) as generate_benign.py
  * 70% of attacks run from the actor's own home IP (identity_pool.json,
    attack_from_home_ip_rate) -- an insider mostly sits at their own desk
  * most attacks are in business hours; the off-hours rate is raised, not pinned
  * the account is drawn from the actor's normal entitlements by the same
    pick_account() as benign, so "borrowed p_admin" stays a weak hint rather than
    a label

The residual differences that DO remain (attack commands are longer and rarer
than benign ones) are the signal the detector is supposed to find.

THE FIVE DIVERSITY AXES (CLAUDE.md sec 10)
------------------------------------------
  composition  ~70% BURIED: 1-2 attack commands hidden inside an otherwise
               ordinary session. The rest are BURSTs: a short benign preamble
               then a concentrated run. Buried is the hard case and therefore
               the majority -- a dataset of pure-attack sessions trains a
               detector that only catches the easy ones.
  persona      the actor is a pool user acting under their own identity, drawn
               with the same per-persona budget split as benign.
  temporal     spread over the same observation window; off-hours/weekend rate
               raised (P_ATTACK_OFF_HOURS) but far from certain.
  pacing       fast bursts vs LOW-AND-SLOW campaigns: --campaign-rate of actors
               spread one or two attack commands per session across several
               consecutive days, which is what the cross-session features
               (distinct_source_ips_24h, session_hour_zscore) exist to catch.
  intensity    how many attack commands land, 1..MAX_BURST -- an obvious-to-
               subtle gradient rather than one fixed dose.

ATTACK CONTENT
--------------
commands_dataset/attack_commands_curated.json (Atomic Red Team + GTFOBins,
curated by curate_*.py, six tactics matching the wallix_rules.xml taxonomy).
Atomic tests are shell SCRIPTS; usable_lines() flattens them to single typed
command lines and drops what an operator would never type at a prompt
(#{input} placeholders, PathToAtomicsFolder, block-structure keywords).

Commands are NOT filtered to those that trip transform.py's RISK_KEYWORDS. That
filter would make flag_* a near-perfect label, the model would re-learn
wallix_rules.xml, and precision@k would be a measurement of the rules
(CLAUDE.md sec 8, circularity). Real collected attacks trip a flag roughly half
the time; the coverage this script produces is printed at the end so the number
stays honest and checkable.

Nothing here is executed -- these are dataset rows. The safety filter in
command_safety.py applies to the collector, not to this file.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

from generate_benign import (
    DATA,
    HERE,
    POOL,
    REAL_CLIENT_IP,
    REAL_TARGET_HOST,
    REAL_TARGET_IP,
    REAL_USER,
    WEIGHTED,
    allocate,
    build_profiles,
    load_fitted_params,
    pick_account,
    pick_start,
    sample_commands,
    sample_length,
    tilt_weights,
)

ATTACKS = os.path.join(DATA, "attack_commands_curated.json")
OUT = os.path.join(HERE, "out", "generated_attacks.jsonl")

# Composition split. Buried is deliberately the majority -- see module docstring.
P_BURIED = 0.70
BURIED_MIN, BURIED_MAX = 1, 2          # attack commands hidden in a normal session
BURST_MIN, BURST_MAX = 3, 6            # attack commands in a concentrated run
BURST_PREAMBLE_MIN, BURST_PREAMBLE_MAX = 1, 3

# Timing. Raised over benign (P_WEEKEND=0.04 / P_ONCALL_NIGHT=0.06) but nowhere
# near certain, so off_hours_flag stays a weak feature rather than the label.
P_ATTACK_OFF_HOURS = 0.35
OFF_HOURS = [22, 23, 0, 1, 2, 3, 4, 5]

# Low-and-slow campaigns: one actor, consecutive days, a trickle per session.
CAMPAIGN_MIN, CAMPAIGN_MAX = 2, 4
CAMPAIGN_PACE_MULTIPLIER = (3.0, 12.0)  # inter-command think time vs a fast session

# Multi-tactic sessions: a real intrusion chains recon -> cred_access -> exfil.
P_SECOND_TACTIC = 0.30

# Lines an operator would never type at a prompt: templating, repo-relative paths
# from the Atomic harness, and shell block structure left over from flattening.
_PLACEHOLDERS = ("#{", "PathToAtomicsFolder", "$PathToAtomics", "${PathToAtomics}")
_BLOCK_KEYWORDS = ("if ", "fi", "then", "else", "elif ", "do ", "done", "esac",
                   "case ", "while ", "for ", "{", "}")


# ---------------------------------------------------------- attack content ---

def usable_lines(attacks: dict) -> dict[str, list[dict]]:
    """{tactic: [{command, technique}]} -- Atomic test scripts flattened to the
    individual command lines a human would actually type, deduplicated.

    Multi-line tests become several independent lines rather than one giant
    pseudo-command: WALLIX emits one KBD_INPUT per typed line, so keeping them
    joined would inflate avg_command_length into a class marker of its own.
    """
    out: dict[str, list[dict]] = {}
    for tactic, tests in attacks.items():
        seen: set[str] = set()
        keep: list[dict] = []
        for test in tests:
            for line in (test.get("command") or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if any(p in line for p in _PLACEHOLDERS):
                    continue
                if line.startswith(_BLOCK_KEYWORDS) or line in ("fi", "done", "esac"):
                    continue
                if line in seen:
                    continue
                seen.add(line)
                keep.append({"command": line, "technique": test.get("technique")})
        if keep:
            out[tactic] = keep
    return out


def draw_attack_commands(pool: dict[str, list[dict]], tactics: list[str],
                         k: int, rng: random.Random) -> tuple[list[str], list[str]]:
    """k attack command lines spread over the given tactics. Returns
    (commands, techniques)."""
    commands, techniques = [], []
    for i in range(k):
        tactic = tactics[i % len(tactics)]
        pick = rng.choice(pool[tactic])
        commands.append(pick["command"])
        if pick["technique"] and pick["technique"] not in techniques:
            techniques.append(pick["technique"])
    return commands, techniques


def pick_tactics(pool: dict[str, list[dict]], rng: random.Random) -> list[str]:
    """One tactic, sometimes two -- a chained intrusion. Uniform over tactics
    rather than over the corpus: the curated corpus is ~60% cred_access (GTFOBins
    is mostly credential/file reads), and sampling it proportionally would make
    the attack class almost single-tactic."""
    available = sorted(pool)
    tactics = [rng.choice(available)]
    if len(available) > 1 and rng.random() < P_SECOND_TACTIC:
        second = rng.choice([t for t in available if t != tactics[0]])
        tactics.append(second)
    return tactics


# --------------------------------------------------------------- placement ---

def bury(benign: list[str], attack: list[str], rng: random.Random) -> list[str]:
    """Insert attack commands at random interior positions of a benign session.

    Never at index 0: a session opens with something ordinary (the actor lands in
    a shell and looks around first), and a fixed position would be a free
    positional feature for any sequence model added later.
    """
    out = list(benign)
    for command in attack:
        pos = rng.randint(1, len(out)) if out else 0
        out.insert(pos, command)
    return out


# ---------------------------------------------------------------- identity ---

def pick_attack_ip(user: dict, pool: dict, rng: random.Random) -> tuple[str, str]:
    """(client_ip, ip_source) for an attack session.

    Mostly the actor's own workstation -- an insider abusing their access is
    physically where they always are, and if attacks always arrived from a
    strange address, ip_foreign_to_user alone would separate the classes.

    The anomalous minority uses identity_pool.json's anomaly_ip_modes, weighted
    toward wrong_team_subnet: a real workstation IP belonging to ANOTHER team is
    the strong insider signal (globally known, foreign to this identity), whereas
    an external address is loud and trivially caught by a firewall rule.
    """
    if rng.random() < pool["_meta"]["attack_from_home_ip_rate"]:
        return rng.choice(user["home_ips"]), "home"

    mode = rng.choices(["wrong_team_subnet", "unseen_vpn", "external"],
                       weights=[0.6, 0.25, 0.15], k=1)[0]
    if mode == "wrong_team_subnet":
        others = [u for u in pool["users"] if u["team_subnet"] != user["team_subnet"]]
        if others:
            return rng.choice(rng.choice(others)["home_ips"]), mode
        mode = "unseen_vpn"
    if mode == "unseen_vpn":
        return f"10.99.{rng.randint(0, 255)}.{rng.randint(2, 254)}", mode
    return f"203.0.113.{rng.randint(2, 254)}", "external"


def pick_attack_start(user: dict, day_span: int, base: datetime,
                      rng: random.Random) -> datetime:
    """Business hours most of the time, an off-hours tail more often than benign.

    Off-hours attacks reuse the benign night-hour set on purpose: the anomaly is
    that THIS user is active at 03:00, not that anyone is. An on-call admin's
    03:00 session is benign and must stay indistinguishable on the timestamp
    alone -- that is precisely what session_hour_zscore has to resolve.
    """
    start = pick_start(user, day_span, base, rng)
    if rng.random() < P_ATTACK_OFF_HOURS:
        start = start.replace(hour=rng.choice(OFF_HOURS))
    return start


def pick_target(profile: dict, rng: random.Random) -> dict:
    """Attacks reach outside the actor's habitual host set more often than benign
    (P_OFF_HOME_TARGET=0.15) -- looking around is half of what an intrusion is --
    but the habitual hosts stay the majority, so distinct_targets_* is a signal
    and not a switch."""
    if rng.random() < 0.35:
        return rng.choices(profile["targets"], weights=profile["weights"], k=1)[0]
    return rng.choice(profile["home_targets"])


# ----------------------------------------------------------------- session ---

def build_session(profile: dict, pool: dict, vocab: list[dict], observed: list[int],
                  median: int, attack_pool: dict, args, base: datetime,
                  rng: random.Random, *, forced_start: datetime | None = None,
                  forced_intensity: int | None = None,
                  campaign_id: str | None = None) -> dict:
    """One attack session as a sessions.jsonl-shaped record."""
    user = profile["user"]
    tactics = pick_tactics(attack_pool, rng)

    buried = rng.random() < P_BURIED
    if forced_intensity is not None:
        intensity = forced_intensity
        composition = "buried"
    elif buried:
        intensity = rng.randint(BURIED_MIN, BURIED_MAX)
        composition = "buried"
    else:
        intensity = rng.randint(BURST_MIN, BURST_MAX)
        composition = "burst"

    attack_cmds, techniques = draw_attack_commands(attack_pool, tactics, intensity, rng)

    if composition == "buried":
        filler = sample_commands(vocab, sample_length(observed, median, rng),
                                 args.stickiness, rng, args.arg_variation)
        commands = bury(filler, attack_cmds, rng)
    else:
        preamble = sample_commands(
            vocab, rng.randint(BURST_PREAMBLE_MIN, BURST_PREAMBLE_MAX),
            args.stickiness, rng, args.arg_variation)
        commands = preamble + attack_cmds

    start = forced_start or pick_attack_start(user, args.day_span, base, rng)

    # Low-and-slow sessions are paced like someone being careful, not like a script.
    pace = rng.uniform(*CAMPAIGN_PACE_MULTIPLIER) if campaign_id else 1.0
    dur = sum(rng.uniform(0.4, 1.3) * pace for _ in commands)
    end = start + timedelta(seconds=dur)

    target = pick_target(profile, rng)
    client_ip, ip_source = pick_attack_ip(user, pool, rng)

    return {
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
        "label": "attack",
        "tactics": tactics,
        "mitre": techniques,
        "source": "generated",
        "split": "train",
        "persona": user["persona"],
        "ip_source": ip_source,
        "target_group": target["group"],
        "target_criticality": target["criticality"],
        # --- how this session was built: EVALUATION metadata, not model input.
        # Slicing precision@k by composition/intensity is how "does it only catch
        # the loud ones?" gets answered.
        "composition": composition,
        "attack_command_count": len(attack_cmds),
        "campaign_id": campaign_id,
        # --- auditability of the synthetic substitution ---
        "identity_is_synthetic": True,
        "ip_is_synthetic": True,
        "ts_is_synthetic": True,
        "real_user": REAL_USER,
        "real_client_ip": REAL_CLIENT_IP,
        "real_target_ip": REAL_TARGET_IP,
        "real_target_hostname": REAL_TARGET_HOST,
    }


# ------------------------------------------------------------------- main ---

def main() -> int:
    fitted = load_fitted_params()

    ap = argparse.ArgumentParser(description="synthetic attack sessions")
    ap.add_argument("--count", type=int, default=None,
                    help="total attack sessions; overrides --benign-count/--attack-share")
    ap.add_argument("--benign-count", type=int, default=None,
                    help="size of the benign set these will be mixed with; the "
                         "attack count is derived from --attack-share")
    ap.add_argument("--attack-share", type=float, default=0.15,
                    help="attack fraction of the combined set (locked at 0.15)")
    ap.add_argument("--campaign-rate", type=float, default=0.20,
                    help="fraction of attack sessions belonging to low-and-slow "
                         "multi-session campaigns")
    ap.add_argument("--stickiness", type=float, default=fitted["stickiness"],
                    help="benign-filler repetition; MUST match generate_benign.py")
    ap.add_argument("--length-tilt", type=float, default=fitted["length_tilt"],
                    help="benign-filler length tilt; MUST match generate_benign.py")
    ap.add_argument("--arg-variation", type=float, default=fitted["arg_variation"],
                    help="benign-filler argument variation; MUST match "
                         "generate_benign.py -- closed-vocabulary filler inside "
                         "attack sessions would separate the classes by itself")
    ap.add_argument("--day-span", type=int, default=30,
                    help="spread synthetic timestamps over N days")
    ap.add_argument("--start-date", default="2026-06-01",
                    help="first day of the synthetic observation window (YYYY-MM-DD)")
    ap.add_argument("--protocols", default="SSH",
                    help="comma-separated target protocols to draw from")
    ap.add_argument("--pool", default=POOL, help="identity_pool.json")
    ap.add_argument("--weighted", default=WEIGHTED, help="persona_weighted.json")
    ap.add_argument("--attacks", default=ATTACKS, help="attack_commands_curated.json")
    ap.add_argument("--seed", type=int, default=43,
                    help="distinct from generate_benign.py's default so the two "
                         "runs do not draw correlated identities")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    if args.count is not None:
        total = args.count
    elif args.benign_count is not None:
        # benign is (1 - share) of the combined set, attacks are the rest
        total = round(args.benign_count * args.attack_share / (1 - args.attack_share))
    else:
        raise SystemExit("give --count or --benign-count")

    rng = random.Random(args.seed)
    weighted = json.load(open(args.weighted, encoding="utf-8"))
    pool = json.load(open(args.pool, encoding="utf-8"))
    attack_pool = usable_lines(json.load(open(args.attacks, encoding="utf-8")))
    if not attack_pool:
        raise SystemExit("no usable attack commands after flattening")

    protocols = {p.strip().upper() for p in args.protocols.split(",") if p.strip()}
    base = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    profiles = [p for p in build_profiles(pool, protocols, rng)
                if p["user"]["persona"] in weighted]
    if not profiles:
        raise SystemExit("no pool user matches a persona in persona_weighted.json")

    # Same per-persona allocation as benign, so the attack class is not
    # concentrated in one persona (which would make persona the label).
    per_persona = max(1, round(total / len({p["user"]["persona"] for p in profiles})))
    budget = allocate(profiles, per_persona)

    records: list[dict] = []
    for prof in profiles:
        blk = weighted[prof["user"]["persona"]]
        vocab = tilt_weights(blk["commands"], args.length_tilt)
        observed = blk["session_length"]["observed"]
        median = blk["session_length"]["median"]

        remaining = budget[prof["user"]["user"]]
        while remaining > 0:
            if remaining >= CAMPAIGN_MIN and rng.random() < args.campaign_rate:
                # low-and-slow: one actor, consecutive days, a trickle each time
                n = min(rng.randint(CAMPAIGN_MIN, CAMPAIGN_MAX), remaining)
                campaign_id = f"camp-{uuid.UUID(int=rng.getrandbits(128)).hex[:8]}"
                day0 = pick_attack_start(prof["user"], args.day_span, base, rng)
                for i in range(n):
                    records.append(build_session(
                        prof, pool, vocab, observed, median, attack_pool, args, base,
                        rng, forced_start=day0 + timedelta(days=i,
                                                           minutes=rng.randint(-90, 90)),
                        forced_intensity=1, campaign_id=campaign_id))
                remaining -= n
            else:
                records.append(build_session(prof, pool, vocab, observed, median,
                                             attack_pool, args, base, rng))
                remaining -= 1

    # allocate() rounds per persona, so trim/extend to the exact requested total
    rng.shuffle(records)
    while len(records) > total:
        records.pop()
    while len(records) < total:
        prof = rng.choice(profiles)
        blk = weighted[prof["user"]["persona"]]
        records.append(build_session(
            prof, pool, tilt_weights(blk["commands"], args.length_tilt),
            blk["session_length"]["observed"], blk["session_length"]["median"],
            attack_pool, args, base, rng))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")

    buried = sum(1 for r in records if r["composition"] == "buried")
    campaigns = {r["campaign_id"] for r in records if r["campaign_id"]}
    off_hours = sum(1 for r in records
                    if datetime.fromisoformat(r["session_start"]).hour < 8
                    or datetime.fromisoformat(r["session_start"]).hour >= 18)
    home_ip = sum(1 for r in records if r["ip_source"] == "home")
    by_tactic: dict[str, int] = {}
    for rec in records:
        for tactic in rec["tactics"]:
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

    print(f"wrote {len(records)} attack sessions -> {args.out}")
    print(f"  usable attack lines : "
          f"{ {t: len(v) for t, v in sorted(attack_pool.items())} }")
    print(f"  composition         : {buried} buried / {len(records) - buried} burst")
    print(f"  campaigns           : {len(campaigns)} low-and-slow "
          f"({sum(1 for r in records if r['campaign_id'])} sessions)")
    print(f"  off-hours           : {off_hours} ({off_hours / len(records):.1%})")
    print(f"  from own home IP    : {home_ip} ({home_ip / len(records):.1%})")
    print(f"  tactics             : {dict(sorted(by_tactic.items()))}")
    print(f"  filler knobs        : stickiness={args.stickiness}, "
          f"length_tilt={args.length_tilt}, arg_variation={args.arg_variation} "
          f"(must match generate_benign.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
