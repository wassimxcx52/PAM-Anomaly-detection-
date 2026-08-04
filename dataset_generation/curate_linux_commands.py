#!/usr/bin/env python3
"""
curate_linux_commands.py — turn the mecha-org/linux-command-dataset into
persona-bucketed benign command pools for simulate_sessions.py.

Source: https://huggingface.co/datasets/mecha-org/linux-command-dataset
(8,669 NL->command pairs, benign sysadmin commands). We only use the
"output" column (the command); the natural-language "input" is discarded.

Two filters are applied, in order:
  1. RULE_PATTERNS -- mirrors wallix_rules.xml's command regexes exactly.
     Anything matching would trigger a custom rule (privesc/cred_access/
     persistence/log_tamper/recon/exfil) if run in a "benign" session,
     contaminating the ground truth. Excluded, not just for realism but for
     labeling integrity -- a benign session that fires an attack rule is a
     contradiction in the dataset, not a useful "false positive" example
     (that's a different, deliberate experiment, not this one).
  2. EXTRA_DANGEROUS -- destructive/identity-management ops not covered by
     the rules above but still inappropriate for a shared lab or for a
     supposedly-unprivileged persona to run (group management, su, kill,
     mount/fdisk, rm, shutdown/reboot).

Remaining commands are bucketed into personas by base-utility keyword
matching (best-effort; not authoritative -- eyeball the output before
wiring it into BENIGN_PERSONAS).
"""

import json
import re
from collections import defaultdict

RAW_PATH = "commands_dataset/linuxcommands_raw.json"
OUT_PATH = "commands_dataset/persona_commands_curated.json"

# Mirrors wallix_rules.xml <field name="command"> regexes verbatim.
RULE_PATTERNS = [
    r"/etc/shadow|/etc/passwd|/etc/gshadow|id_rsa|id_ed25519|\.aws/credentials|mimikatz|lsass|secretsdump|hashdump",
    r"useradd|usermod|adduser|visudo|/etc/sudoers|chmod\s+u\+s|chmod\s+[0-7]*[4267][0-7][0-7]|setcap",
    r"crontab|/etc/cron|systemctl\s+enable|/etc/rc\.local|authorized_keys|/etc/systemd/system",
    r"history\s+-c|unset\s+HISTFILE|>\s*/var/log|rm\s+.*/var/log|shred|/var/log/wtmp|auditctl|>\s*\.bash_history",
    r"^whoami|^id$|^who$|^w$|^last|netstat|^ss\s|^arp|ifconfig|^ip\s+a|nmap|uname\s+-a|^lsof",
    r"^scp\s|^rsync\s|curl.*(?:-T|--upload)|wget.*--post|^nc\s|tar.*\|\s*(?:nc|ssh)|base64.*\|",
]
RULE_RE = re.compile("|".join(f"(?:{p})" for p in RULE_PATTERNS))

# Not in wallix_rules.xml, but excluded anyway: destructive, identity
# management beyond what a benign persona should touch, or privilege-adjacent.
EXTRA_DANGEROUS_BASES = {
    "rm", "dd", "mkfs", "shutdown", "reboot", "halt", "init", "poweroff",
    "groupadd", "groupdel", "groupmod", "gpasswd", "passwd", "su", "sudo",
    "kill", "pkill", "killall", "mount", "umount", "fdisk", "parted",
    "userdel", "chown", "chgrp", "chpasswd", "iptables", "ufw", "systemctl",
    # not dangerous, but real durations in this dataset run up to 600s+ --
    # blows past simulate_sessions.py's 15s per-command timeout and hangs a
    # session for no diversity benefit (confirmed live: "sleep 600" timed out).
    "sleep",
}

# Best-effort persona keyword buckets. A command can land in multiple
# personas; buckets are for building diverse BENIGN_PERSONAS pools, not a
# strict taxonomy.
PERSONA_KEYWORDS = {
    "dev": {"git", "python", "python3", "pip", "npm", "node", "make", "gcc",
            "diff", "grep", "sed", "awk", "tar", "gzip", "bzip2", "zip",
            "unzip", "chmod", "touch", "cat", "head", "tail", "find", "wc"},
    "dba": {"du", "df", "find", "cat", "grep", "wc", "sort", "uniq", "cut",
            "tar", "gzip", "sleep", "date", "cp", "mv"},
    "auditor": {"ls", "cat", "find", "stat", "file", "diff", "grep", "wc",
                "date", "sort", "uniq"},
    "admin": {"free", "df", "du", "ping", "traceroute", "dig", "mtr", "host",
              "nslookup", "curl", "wget", "cp", "mv", "touch", "mkdir",
              "ls", "cd", "sleep", "date", "gzip", "zip"},
}


DANGEROUS_ANYWHERE_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(b) for b in EXTRA_DANGEROUS_BASES) + r")\b"
)

# Network utilities (ping/dig/curl/wget/nslookup/traceroute/...) in this dataset
# often target real-looking placeholder domains (amazon.com, ftp.example.com) --
# that's live outbound internet traffic from the lab, not just a harmless local
# no-op. Exclude any URL scheme and any bare domain-looking token, except
# loopback/localhost/private-range destinations.
EXTERNAL_NETWORK_RE = re.compile(
    r"[a-z]+://(?!127\.0\.0\.1|localhost)"          # any scheme:// (http, ftp, ...)
    r"|\b(?:[\w-]+\.)+(?:com|org|net|io|gov|edu|co)\b"  # bare domain.tld tokens
)
# `cat > file` / `cat >> file` with no source argument reads from stdin until
# EOF -- hangs forever in a driven (non-interactive-input) session, same
# failure class as an interactive editor. Confirmed live: this exact pattern
# timed out a real run.
BARE_STDIN_RE = re.compile(r"^cat\s*>>?\s")
# `-exec`/xargs on an unscoped path (e.g. find / ... -exec md5sum {} \;) can
# walk thousands of files and blow the 15s per-command timeout. Confirmed
# live: a find+md5sum over /var/cache timed out a real run.
EXPENSIVE_WALK_RE = re.compile(r"-exec\s|\|\s*xargs\b")
# Pagers wait for interactive 'q' (same failure class as the earlier
# `systemctl status` pager bug); `tail -f` follows forever and never returns.
HANGS_ON_TTY_RE = re.compile(r"\|\s*(?:less|more)\b|\btail\s+-f\b|&\s*wait\b")
# free/ping/etc in repeat mode (-s interval -c count) can run for minutes.
REPEAT_MODE_RE = re.compile(r"-s\s+\d+\s+-c\s+\d+|-c\s+\d+\s+-s\s+\d+")
IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _is_private_ip(octets: tuple) -> bool:
    a, b = int(octets[0]), int(octets[1])
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def has_external_ip(cmd: str) -> bool:
    """ping/traceroute/etc to a real public IP (e.g. 1.1.1.1, 8.8.8.8) --
    caught separately from EXTERNAL_NETWORK_RE, which only matches domain
    names, not raw IPv4 literals."""
    for m in IPV4_RE.finditer(cmd):
        if not _is_private_ip(m.groups()):
            return True
    return False


def is_excluded(cmd: str) -> bool:
    if RULE_RE.search(cmd):
        return True
    # Whole-word match anywhere, not just the leading token -- catches
    # `find ... -exec chown ...` / `... | xargs rm` style embedded execution.
    if DANGEROUS_ANYWHERE_RE.search(cmd):
        return True
    if EXTERNAL_NETWORK_RE.search(cmd):
        return True
    if BARE_STDIN_RE.search(cmd):
        return True
    if EXPENSIVE_WALK_RE.search(cmd):
        return True
    if HANGS_ON_TTY_RE.search(cmd):
        return True
    if REPEAT_MODE_RE.search(cmd):
        return True
    return has_external_ip(cmd)


def personas_for(cmd: str) -> list:
    base = cmd.strip().split()[0] if cmd.strip() else ""
    return [p for p, kws in PERSONA_KEYWORDS.items() if base in kws]


def main() -> int:
    with open(RAW_PATH, encoding="utf-8") as fh:
        data = json.load(fh)

    seen = set()
    excluded_n = 0
    buckets = defaultdict(list)

    for row in data:
        cmd = row["output"].strip()
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        if is_excluded(cmd):
            excluded_n += 1
            continue
        for persona in personas_for(cmd):
            buckets[persona].append(cmd)

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(buckets, fh, indent=2, ensure_ascii=False)

    print(f"unique commands: {len(seen)}")
    print(f"excluded (rule-match or dangerous): {excluded_n}")
    for persona, cmds in buckets.items():
        print(f"  {persona:10s} {len(cmds)} commands")
    print(f"-> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
