#!/usr/bin/env python3
"""
build_identity_pool.py -- the metadata layer (CLAUDE.md sec 10, phase 2).

Emits identity_pool.json: the synthetic org that generated sessions are draped
over. Deterministic (seeded), so the pool is reproducible and reviewable as a
versioned artifact rather than re-rolled on every generator run.

THE GOVERNING RULE
------------------
Every attribute is anchored to an identity's own history; an anomaly is a
deviation from THAT identity's baseline, never a globally-unseen value. If any
single metadata axis (IP, target, hour, account) separates benign from attack on
its own, the model memorises metadata and never learns behaviour. Concretely,
that forces two things the generator must honour and which are easy to get wrong:

  * ~70% of ATTACK sessions come from the attacker's OWN home IP. Real insiders
    work from their own laptop. If attacks always came from odd IPs, client_ip
    alone would solve the task.
  * ~10% of BENIGN sessions come from roaming (VPN/jump) IPs, so "not the home
    IP" is not a label either.

The same symmetry applies to targets: every host must carry both benign and
attack sessions or target_hostname becomes a label proxy (CLAUDE.md sec 10,
"honest lab constraints").

HONESTY
-------
This pool is SYNTHETIC. Real sessions carry one login user (test-ssh), one client
IP and two targets; generated sessions keep real_user/real_ip/real_target beside
the synthetic values so the substitution stays auditable, and the dataset is
documented as semi-synthetic in the report.
"""

from __future__ import annotations

import argparse
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "identity_pool.json")

# ---------------------------------------------------------------- personas ---
# Deliberately uneven headcount: real orgs are, and it stresses cold-start /
# peer-group baselines (a 3-person cohort is a weaker baseline than a 6-person
# one, which is exactly the condition we want represented).
HEADCOUNT = {"dev": 6, "dba": 3, "admin": 3, "auditor": 4}

# Per-team workstation subnets. Users are STICKY to 1-2 IPs inside their own
# team subnet; a known-good IP attached to the WRONG identity is the strongest
# insider signal available here, and it only exists because subnets are
# team-scoped rather than random.
TEAM_SUBNET = {"dev": "10.20.10", "dba": "10.20.20",
               "auditor": "10.20.30", "admin": "10.20.40"}
VPN_SUBNET = "10.99"        # /16, legitimate roaming
JUMP_SUBNET = "10.30.0"     # shared jump host / kiosk, legitimate

# Roaming rates for BENIGN sessions. Non-zero on purpose: see module docstring.
BENIGN_VPN_RATE = 0.08
BENIGN_JUMP_RATE = 0.02

# Fraction of ATTACK sessions launched from the actor's own home IP.
ATTACK_FROM_HOME_IP = 0.70

# ----------------------------------------------------------------- targets ---
# ~20 hosts with a function prefix, a criticality tier and a protocol. Protocol
# is a property of the HOST (Linux -> SSH, Windows -> RDP), which is what makes
# protocol diversity fall out of target affinity instead of being drawn
# independently. Criticality feeds the report's "risk = anomaly x impact"
# argument (CLAUDE.md sec 11) -- it is NOT a model input feature.
TARGETS = [
    # name,          group,     subnet,     tier, protocol
    ("db-prod-01",   "db",      "10.10.20", 3, "SSH"),
    ("db-prod-02",   "db",      "10.10.20", 3, "SSH"),
    ("db-prod-03",   "db",      "10.10.20", 3, "SSH"),
    ("db-stg-01",    "db",      "10.10.20", 1, "SSH"),
    ("web-prod-01",  "web",     "10.10.30", 2, "SSH"),
    ("web-prod-02",  "web",     "10.10.30", 2, "SSH"),
    ("web-stg-01",   "web",     "10.10.30", 1, "SSH"),
    ("web-stg-02",   "web",     "10.10.30", 1, "SSH"),
    ("dev-01",       "dev",     "10.10.40", 1, "SSH"),
    ("dev-02",       "dev",     "10.10.40", 1, "SSH"),
    ("dev-03",       "dev",     "10.10.40", 1, "SSH"),
    ("dev-04",       "dev",     "10.10.40", 1, "SSH"),
    ("dev-05",       "dev",     "10.10.40", 1, "RDP"),
    ("build-01",     "dev",     "10.10.40", 2, "SSH"),
    ("dc-01",        "infra",   "10.10.50", 3, "RDP"),
    ("dc-02",        "infra",   "10.10.50", 3, "RDP"),
    ("file-01",      "infra",   "10.10.50", 2, "RDP"),
    ("backup-01",    "infra",   "10.10.50", 3, "SSH"),
    ("mon-01",       "infra",   "10.10.50", 1, "SSH"),
    ("adm-jump-01",  "infra",   "10.10.50", 2, "RDP"),
]

# persona -> weight over target GROUPS. Sums need not be 1 (normalised on use).
# Auditor is deliberately wide-but-shallow: broad reach, few sessions per host.
# Admin is broad by role, which is what makes "admin touched a new host" a weak
# signal and "dba touched dc-01" a strong one -- the asymmetry is the point.
TARGET_AFFINITY = {
    "dev":     {"dev": 0.70, "web": 0.25, "db": 0.05, "infra": 0.00},
    "dba":     {"db": 0.80, "infra": 0.10, "web": 0.10, "dev": 0.00},
    "admin":   {"infra": 0.45, "web": 0.20, "db": 0.20, "dev": 0.15},
    "auditor": {"infra": 0.30, "db": 0.30, "web": 0.20, "dev": 0.20},
}

# ---------------------------------------------------------------- accounts ---
# The borrowed privileged identity -- distinct from `user`, and the feature no
# comparable paper has (CLAUDE.md sec 13). Anomaly = borrowing an account
# outside the entitlement set, or one this user has never used before.
# Names are the REAL vaulted accounts on debian-lab (CLAUDE.md sec 1) so
# generated sessions stay schema-identical to extracted ones.
ENTITLEMENTS = {
    "dev":     ["p_dev"],
    "dba":     ["p_dba"],
    "auditor": ["p_audit"],
    "admin":   ["bastionsvc", "p_admin"],
}
# p_admin is the high-privilege account: a non-admin borrowing it is the
# escalation signal the supervised track should be able to pick up.
PRIVILEGED_ACCOUNTS = ["p_admin"]

# ------------------------------------------------------------------- hours ---
# Per-persona working-hour distribution (mean hour, sd) + session rate per
# working day. Admins carry an on-call rotation: a 03:00 admin session is normal
# FOR THE ADMIN ON CALL THAT WEEK and anomalous for anyone else. That nuance is
# what makes session_hour_zscore earn its place over a flat off_hours_flag.
HOURS = {
    "dev":     {"mean": 11.0, "sd": 2.4, "rate": 3.5, "oncall": False},
    "dba":     {"mean": 10.0, "sd": 2.0, "rate": 2.5, "oncall": True},
    "admin":   {"mean": 10.5, "sd": 3.0, "rate": 4.0, "oncall": True},
    "auditor": {"mean": 14.0, "sd": 1.8, "rate": 1.5, "oncall": False},
}

FIRST_NAMES = ["amine", "sara", "yassine", "leila", "omar", "nadia", "karim",
               "salma", "reda", "imane", "hamza", "ghita", "mehdi", "asma",
               "youssef", "khadija"]


def build(seed: int) -> dict:
    rng = random.Random(seed)
    names = FIRST_NAMES[:]
    rng.shuffle(names)

    users = []
    for persona, n in HEADCOUNT.items():
        for _ in range(n):
            login = names.pop()
            subnet = TEAM_SUBNET[persona]
            # 1-2 sticky workstation IPs; the second (if any) is a laptop/dock.
            host_octets = rng.sample(range(20, 200), rng.choice([1, 1, 1, 2]))
            hours = HOURS[persona]
            users.append({
                "user": login,
                "persona": persona,
                "home_ips": [f"{subnet}.{o}" for o in host_octets],
                "team_subnet": f"{subnet}.0/24",
                "entitled_accounts": ENTITLEMENTS[persona],
                "work_hour_mean": hours["mean"],
                # per-user jitter so users are not clones of their persona;
                # without it, per-user z-scores collapse onto the cohort mean.
                "work_hour_sd": round(hours["sd"] * rng.uniform(0.8, 1.25), 2),
                "sessions_per_workday": round(hours["rate"] * rng.uniform(0.7, 1.4), 2),
                "oncall_eligible": hours["oncall"],
            })

    targets = []
    for i, (name, group, subnet, tier, proto) in enumerate(TARGETS):
        targets.append({
            "target_hostname": name,
            "group": group,
            "target_ip": f"{subnet}.{10 + i}",
            "criticality": tier,        # evaluation metadata, NOT a model feature
            "protocol": proto,
        })

    return {
        "_meta": {
            "seed": seed,
            "synthetic": True,
            "note": "Synthetic org. Real telemetry has 1 login user, 1 client IP, "
                    "2 targets. Generated sessions keep real_user/real_ip/real_target "
                    "alongside these values; dataset is semi-synthetic.",
            "attack_from_home_ip_rate": ATTACK_FROM_HOME_IP,
            "benign_vpn_rate": BENIGN_VPN_RATE,
            "benign_jump_rate": BENIGN_JUMP_RATE,
        },
        "users": users,
        "targets": targets,
        "target_affinity": TARGET_AFFINITY,
        "roaming": {
            "vpn_cidr": f"{VPN_SUBNET}.0.0/16",
            "jump_cidr": f"{JUMP_SUBNET}.0/24",
            # A fixed jump-host set: shared IPs seen by MANY users, so
            # "IP seen before globally" and "IP normal for this user" diverge --
            # which is the distinction new_source_ip_for_user has to capture.
            "jump_ips": [f"{JUMP_SUBNET}.{o}" for o in (11, 12)],
        },
        "privileged_accounts": PRIVILEGED_ACCOUNTS,
        "anomaly_ip_modes": {
            # ascending signal strength; the generator picks among these for the
            # ~30% of attacks that do NOT come from the actor's home IP
            "unseen_vpn": "unused address in the VPN /16 -- weak, happens benignly",
            "wrong_team_subnet": "a real workstation IP from ANOTHER persona's "
                                 "subnet -- strongest insider signal",
            "external": "address outside every known range -- loud and easy",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    pool = build(args.seed)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(pool, fh, indent=2, ensure_ascii=False)

    per_persona = {}
    for u in pool["users"]:
        per_persona[u["persona"]] = per_persona.get(u["persona"], 0) + 1
    print(f"[identity_pool] {len(pool['users'])} users {per_persona}, "
          f"{len(pool['targets'])} targets -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
