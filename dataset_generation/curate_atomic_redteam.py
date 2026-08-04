#!/usr/bin/env python3
"""
curate_atomic_redteam.py — turn Atomic Red Team technique YAMLs into
scenario-bucketed attack command pools for simulate_sessions.py.

Source: https://github.com/redcanaryco/atomic-red-team (atomics/T####/T####.yaml
per technique, fetched directly via raw.githubusercontent.com — not cloning the
whole repo). MITRE IDs match ATTACK_SCENARIOS in simulate_sessions.py exactly:
  recon:        T1082, T1087.001
  cred_access:  T1003, T1552
  privesc:      T1548.003
  persistence:  T1053.003, T1098, T1136.001
  log_tamper:   T1070, T1070.003
  exfil:        T1048, T1041

Unlike the benign curation (curate_linux_commands.py), we are NOT filtering out
rule-matching commands here -- these ARE attack scenarios, matching the rules is
the point. The safety bar instead is: self-cleaning / non-destructive to a
SHARED lab, and automatable without a TTY (no interactive editors).

Concretely excluded, regardless of technique:
  - Direct writes to /etc/sudoers (not /etc/sudoers.d/), /etc/passwd, /etc/shadow,
    /etc/ssh/sshd_config, /etc/pam.d/*, /etc/fstab, /boot/*, grub -- real ART
    tests do this with NO cleanup_command (confirmed by inspection: T1548.003's
    "Unlimited sudo cache timeout" test sed -i's /etc/sudoers directly and never
    reverts it). Too risky for a lab other people/scripts also depend on.
  - Interactive editors (vim/vi/nano/emacs/ee) -- would hang waiting on a TTY,
    same class of bug as the `systemctl status` pager issue hit earlier.
  - Destructive ops: reboot/shutdown/halt/mkfs/dd/fdisk/parted, iptables -F,
    ufw reset, fork-bomb-shaped patterns.
  - External network fetches (http(s):// to anything but 127.0.0.1/localhost) --
    avoid live internet calls during simulation.
  - Any state-changing command (has a write indicator: useradd, crontab, mkdir,
    sed -i, chmod, echo >>, etc.) that has NO cleanup_command paired with it.
  - Tests requiring package installation as a prerequisite (dependencies that
    `apt-get install`/`pkg install`/etc.) -- adds risk/complexity, skip.

#{placeholder} args are resolved using each test's input_arguments defaults.
Tests with placeholders that don't resolve are skipped rather than guessed at.

This is a MUCH higher-risk source than the benign dataset (these are real
attack techniques, several genuinely can break a shared system) -- treat the
output as a candidate list requiring manual review before wiring into
ATTACK_SCENARIOS, not a drop-in.
"""

from __future__ import annotations

import glob
import json
import os
import re

try:
    import yaml
except ImportError:
    raise SystemExit("pip install pyyaml")

RAW_DIR = "commands_dataset/atomic_raw"
OUT_PATH = "commands_dataset/attack_commands_curated.json"

TECHNIQUE_TO_SCENARIO = {
    "T1082": "recon", "T1087.001": "recon",
    # cred_access: parent files are Windows-only; the Linux content lives in
    # these sub-techniques (proc filesystem, /etc/passwd+shadow, creds/keys/history).
    "T1003": "cred_access", "T1552": "cred_access",
    "T1003.007": "cred_access", "T1003.008": "cred_access",
    "T1552.001": "cred_access", "T1552.003": "cred_access", "T1552.004": "cred_access",
    # privesc: T1548.003 (sudo) is all FreeBSD or direct /etc/sudoers writes;
    # setuid/setgid, LD_PRELOAD and file-permission abuse give Linux-safe coverage.
    "T1548.003": "privesc", "T1548.001": "privesc",
    "T1574.006": "privesc", "T1222.002": "privesc",
    "T1053.003": "persistence", "T1098": "persistence", "T1136.001": "persistence",
    "T1543.002": "persistence", "T1546.004": "persistence",
    "T1070": "log_tamper", "T1070.003": "log_tamper",
    # exfil: parents are Windows/external-host; these add unencrypted-protocol,
    # web-service and data-size-limit Linux tests.
    "T1048": "exfil", "T1041": "exfil",
    "T1048.003": "exfil", "T1567.002": "exfil", "T1030": "exfil",
}

SENSITIVE_FILES_RE = re.compile(
    r"/etc/sudoers(?!\.d)|/etc/passwd|/etc/shadow|/etc/ssh/sshd_config"
    r"|/etc/pam\.d|/etc/fstab|/boot/|grub"
)
DESTRUCTIVE_RE = re.compile(
    r"\breboot\b|\bshutdown\b|\bhalt\b|\bmkfs\b|\bdd\s+if=|\bfdisk\b|\bparted\b"
    r"|iptables\s+-F|ufw\s+reset|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}"
)
EXTERNAL_NET_RE = re.compile(r"https?://(?!127\.0\.0\.1|localhost)")
EXTERNAL_HOST_RE = re.compile(
    r"@?(?:target\.example\.com|example\.com|8\.8\.8\.8|attacker[\w.]*\.com)"
)
INTERACTIVE_EDITOR_RE = re.compile(r"\b(?:vim|vi|nano|emacs|ee)\s+/")
# Bash-history tampering (rm/echo/cat/ln/truncate on ~/.bash_history or $HISTFILE)
# is state-changing but session-ephemeral: a fresh per-session shell regenerates
# its own history, so ART ships no cleanup_command. These are exactly the
# rule-blind log-tamper variants we want, so allow them without a cleanup as long
# as they touch ONLY history state, not system paths / users / persistence.
HISTORY_TOKEN_RE = re.compile(r"\.bash_history|HISTFILE|HISTSIZE|set\s+\+o\s+history")
NON_HISTORY_WRITE_RE = re.compile(
    r"/etc/|/var/|/usr/|/boot/|/root/|useradd|usermod|groupadd|crontab"
    r"|systemctl|passwd\b"
)
WRITE_INDICATOR_RE = re.compile(
    r">>?\s|touch\s|useradd|usermod|groupadd|crontab|mkdir\s|mv\s|cp\s|sed\s+-i"
    r"|chmod\s|chown\s|systemctl\s+enable|ln\s+-s|rm\s|passwd\b"
)
# ART scaffolding vars / tools not present on a minimal Debian target and not
# worth installing just for a template session (FreeBSD-only tools, docker).
UNAVAILABLE_RE = re.compile(
    r"\$PathToAtomicsFolder|\bpw\s+(?:useradd|usermod)|\brmuser\b|\bkldstat\b|\bdocker\b"
)
PLACEHOLDER_RE = re.compile(r"#\{([\w.]+)\}")


def is_history_only(command: str) -> bool:
    """True if the command tampers with bash history and nothing else — safe to
    run without a cleanup_command in an ephemeral per-session shell."""
    if not HISTORY_TOKEN_RE.search(command):
        return False
    return not NON_HISTORY_WRITE_RE.search(command)


def rewrite_to_loopback(command: str) -> tuple[str, bool]:
    """Rewrite external exfil destinations to 127.0.0.1 so the command SHAPE is
    preserved (real exfil telemetry) without any live off-box network call — the
    same 127.0.0.1-only convention the hand-built exfil scenario already uses
    (CLAUDE.md §6). Returns (command, changed)."""
    new = re.sub(r"https?://(?!127\.0\.0\.1|localhost)[^\s\"'`]+", "http://127.0.0.1", command)
    new = re.sub(r"target\.example\.com|(?<!\d\.)\bexample\.com|8\.8\.8\.8|attacker[\w.]*\.com",
                 "127.0.0.1", new)
    return new, (new != command)


def resolve_placeholders(text: str, input_args: dict) -> str | None:
    """Substitute #{name} with its default value. Returns None if anything
    can't be resolved (skip rather than guess)."""
    if not text:
        return text

    def _sub(m):
        name = m.group(1)
        arg = input_args.get(name, {})
        default = arg.get("default")
        return str(default) if default is not None else None

    out = []
    pos = 0
    for m in PLACEHOLDER_RE.finditer(text):
        default = _sub(m)
        if default is None:
            return None
        out.append(text[pos:m.start()])
        out.append(default)
        pos = m.end()
    out.append(text[pos:])
    return "".join(out)


def has_install_dependency(test: dict) -> bool:
    for dep in test.get("dependencies", []) or []:
        get_prereq = (dep.get("get_prereq_command") or "").lower()
        if re.search(r"apt-get install|apt install|yum install|pkg install|pip install", get_prereq):
            return True
    return False


def is_unsafe(command: str, cleanup: str | None) -> str | None:
    """Returns a reason string if unsafe, else None."""
    if SENSITIVE_FILES_RE.search(command) or (cleanup and SENSITIVE_FILES_RE.search(cleanup)):
        return "touches sensitive system file"
    if DESTRUCTIVE_RE.search(command):
        return "destructive op"
    if EXTERNAL_NET_RE.search(command):
        return "external network fetch"
    if EXTERNAL_HOST_RE.search(command):
        return "targets an external placeholder host"
    if INTERACTIVE_EDITOR_RE.search(command):
        return "interactive editor (would hang on TTY)"
    if UNAVAILABLE_RE.search(command):
        return "requires a tool/scaffolding not on the target"
    if WRITE_INDICATOR_RE.search(command) and not cleanup and not is_history_only(command):
        return "state-changing with no cleanup_command"
    return None


def main() -> int:
    buckets: dict[str, list] = {s: [] for s in set(TECHNIQUE_TO_SCENARIO.values())}
    stats = {"total_tests": 0, "not_linux_sh": 0, "unresolved_placeholder": 0,
              "install_dependency": 0, "unsafe": 0, "kept": 0}

    for path in sorted(glob.glob(f"{RAW_DIR}/*.yaml")):
        technique = os.path.basename(path).removesuffix(".yaml")
        if technique not in TECHNIQUE_TO_SCENARIO:
            continue
        scenario = TECHNIQUE_TO_SCENARIO[technique]

        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not doc:
            continue

        for test in doc.get("atomic_tests", []):
            stats["total_tests"] += 1
            platforms = test.get("supported_platforms", [])
            executor = test.get("executor", {})
            name = test.get("name", "")
            if "linux" not in platforms or executor.get("name") not in ("sh", "bash"):
                stats["not_linux_sh"] += 1
                continue
            if "freebsd" in name.lower() or "aws" in name.lower():
                stats["not_linux_sh"] += 1
                continue
            if has_install_dependency(test):
                stats["install_dependency"] += 1
                continue

            input_args = test.get("input_arguments", {}) or {}
            command = resolve_placeholders(executor.get("command", ""), input_args)
            cleanup = resolve_placeholders(executor.get("cleanup_command"), input_args)
            if command is None or (executor.get("cleanup_command") and cleanup is None):
                stats["unresolved_placeholder"] += 1
                continue

            # exfil: rewrite external destinations to loopback (see rewrite_to_loopback).
            lab_rewritten = False
            if scenario == "exfil":
                command, lab_rewritten = rewrite_to_loopback(command)

            reason = is_unsafe(command, cleanup)
            if reason:
                stats["unsafe"] += 1
                continue

            buckets[scenario].append({
                "technique": technique,
                "test_name": test.get("name"),
                "command": command.strip(),
                "cleanup_command": cleanup.strip() if cleanup else None,
                "source": "atomic-red-team",
                "lab_rewritten": lab_rewritten,
            })
            stats["kept"] += 1

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(buckets, fh, indent=2, ensure_ascii=False)

    print(f"stats: {stats}")
    for scenario, items in buckets.items():
        print(f"  {scenario:12s} {len(items)} candidate tests")
    print(f"-> {OUT_PATH}")
    print("\nNOTE: manual review required before wiring into ATTACK_SCENARIOS --")
    print("these are real attack techniques, not vetted like the hand-built scenarios.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
