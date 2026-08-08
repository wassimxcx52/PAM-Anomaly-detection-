#!/usr/bin/env python3
"""
command_safety.py -- the single definition of "a benign command we will accept".

Used by BOTH sides of the dataset, for two different reasons that happen to want
the same rule:

  * feature_extraction/simulate_sessions.py -- SAFETY. Benign filler is executed
    for real, as root, on a shared lab host. It must not write, delete, install,
    or fail to terminate.

  * dataset_generation/build_persona_weights.py -- PARITY. Generated sessions are
    never executed, so nothing there is dangerous. But if the generator can emit
    `mv /usr/local/bin/* /opt/bin/` and the collector cannot, the two benign
    vocabularies diverge, and that divergence shows up as a domain marker in
    ml/unsupervised/train.py's gate -- a seam between the datasets masquerading
    as a behavioural signal.

One definition, imported by both, so the vocabularies cannot drift apart.

WHY IT EXISTS AT ALL
--------------------
curate_linux_commands.py filtered the public corpus against wallix_rules.xml (so
benign content does not trip a detection rule) but never against destructiveness.
It is a corpus of REAL Linux commands, so it contains real commands that change
state. Observed live on 2026-08-07: a collected session ran
`mv /usr/local/bin/* /opt/bin/` as root on debian-lab. No damage resulted, but
only because /usr/local/bin happened to be empty -- nothing had stopped it.

Denylist rather than allowlist: the corpus is ~3200 commands across personas and
an allowlist would gut it. Anything that writes, deletes, moves, installs,
changes permissions, manages services/users, or redirects output is rejected.
"""

from __future__ import annotations

import os
import re

_MUTATING_HEADS = {
    "rm", "rmdir", "mv", "cp", "dd", "mkdir", "touch", "truncate", "install",
    "ln", "shred", "chmod", "chown", "chgrp", "chattr", "setfacl",
    "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "tar",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd", "chpasswd",
    "apt", "apt-get", "aptitude", "dpkg", "yum", "dnf", "rpm", "snap", "pip",
    "pip3", "npm", "make", "systemctl", "service", "systemd-run",
    "kill", "killall", "pkill", "reboot", "shutdown", "halt", "poweroff", "init",
    "mount", "umount", "swapon", "swapoff", "mkfs", "fdisk", "parted", "mkswap",
    "iptables", "nft", "ufw", "route", "ifconfig", "modprobe", "insmod", "rmmod",
    "crontab", "at", "tee", "sed", "patch", "wget", "sysctl", "update-alternatives",
    "hostnamectl", "timedatectl", "localectl", "visudo", "vi", "vim",
    "nano", "emacs", "less", "more", "top", "htop",   # also: interactive, would hang
}

# Substrings that make even a read-looking command dangerous.
_UNSAFE_PATTERNS = (">", ">>", "|&", "--delete", "-delete", "-exec", "--force",
                    "mkfifo", "chroot", "$(", "`")

# Commands that never return. The driver waits for a shell prompt after each
# command, so one of these hangs the session until STEP_TIMEOUT and truncates
# everything after it -- a silent hole in the collected data rather than a crash.
# `free -s 1` and `vmstat 1` are the easy ones to miss: they look read-only, and
# they are, but they poll forever.
_HANGING_HEADS = {"watch", "yes", "sleep", "screen", "tmux", "man", "info",
                  "telnet", "ftp", "sftp", "mysql", "psql", "python", "python3",
                  "irb", "node", "gdb", "strace", "ltrace"}


def _hangs(words: list) -> bool:
    head = os.path.basename(words[0])
    if head in _HANGING_HEADS and len(words) == 1:      # bare REPL / pager
        return True
    if head in _HANGING_HEADS - {"python", "python3", "node"}:
        return True
    if head in ("free", "vmstat", "iostat", "mpstat", "sar", "pidstat") and "-s" in words:
        return True
    if head in ("vmstat", "iostat", "mpstat") and any(w.isdigit() for w in words[1:]):
        return True
    if head in ("tail", "journalctl") and ("-f" in words or "--follow" in words):
        return True
    if head == "ping" and not any(w == "-c" or w.startswith("-c") for w in words):
        return True
    if head in ("nc", "ncat", "netcat") and "-l" in words:
        return True
    if head == "tcpdump" and not any(w == "-c" for w in words):
        return True
    return False


def is_safe_benign(command: str) -> bool:
    """Read-only, non-interactive, terminating, and safe to run as root on the
    shared lab host."""
    if not command or not command.strip():
        return False
    if any(p in command for p in _UNSAFE_PATTERNS):
        return False
    # Every segment of a compound command must independently be safe.
    for segment in re.split(r"[;|]|&&|\|\|", command):
        words = segment.strip().split()
        if not words:
            continue
        head = words[0]
        if head in ("sudo", "doas", "env", "nohup", "time"):
            words = words[1:]
            if not words:
                return False
            head = words[0]
        if os.path.basename(head) in _MUTATING_HEADS:
            return False
        if _hangs(words):
            return False
    return True


def filter_corpus(corpus: dict, label: str = "") -> dict:
    """{persona: [commands]} -> same, keeping only accepted commands. Reports what
    it removed: a silent filter is how the original path bug went unnoticed."""
    safe, dropped = {}, 0
    for persona, commands in corpus.items():
        keep = [c for c in commands if is_safe_benign(c)]
        dropped += len(commands) - len(keep)
        safe[persona] = keep
    if dropped:
        prefix = f"[{label}] " if label else ""
        print(f"{prefix}command_safety: dropped {dropped} state-changing/interactive "
              f"commands, kept {sum(len(v) for v in safe.values())}")
    return safe
