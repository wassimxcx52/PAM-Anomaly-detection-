#!/usr/bin/env python3
"""
curate_gtfobins.py -- turn GTFOBins binary definitions into scenario-bucketed
attack command pools, MERGED into the same attack_commands_curated.json that
curate_atomic_redteam.py produces (append + dedup by command string).

Source: https://github.com/GTFOBins/GTFOBins.github.io  (_gtfobins/<binary> files,
Jekyll collection: extensionless, YAML frontmatter with a `functions:` map).
Fetch once as a tarball and extract to commands_dataset/gtfobins_raw/ (see the
README). We parse the frontmatter, not the repo's build output.

Why GTFOBins alongside Atomic Red Team: ART is script-shaped and Linux-thin for
several tactics (exfil, cred_access came up almost empty). GTFOBins entries are
single command-shaped snippets -- a much better fit for the one-command-per-
KBD_INPUT model the WALLIX simulator drives (CLAUDE.md §6).

SCOPE -- deliberately narrow, high-confidence functions only:
    file-read              -> cred_access   (read a sensitive file)
    upload / file-upload   -> exfil         (data leaving the host)
    sudo / suid / caps     -> privesc       (only NON-interactive snippets)

Excluded on purpose:
  - reverse-shell / bind-shell / *-shell / shell / command: spawn an interactive
    or listening shell -> would HANG the non-TTY simulator (same failure class as
    interactive editors in the ART curator). Any snippet that spawns /bin/sh,
    /bin/bash, `sh -i`, `-exec ... sh`, `:!sh`, etc. is dropped even under an
    otherwise-kept function.
  - download / file-download: ingress (tooling drop), not exfil; out of scope for
    the current 6-tactic taxonomy.
  - file-write, library-load: tactic mapping is ambiguous (persistence vs
    log_tamper vs privesc); skip rather than mislabel.

Placeholders (GTFOBins uses $LFILE/$RHOST/$RPORT/$LHOST/$LPORT and literal
`attacker.com`, `/path/to/...`, `12345`) are resolved to LAB-SAFE values:
loopback for any remote host, a real readable file for reads, /tmp for outputs.
No live off-box network call is ever emitted (same 127.0.0.1-only convention as
the ART exfil rewrite).

Output records carry source="gtfobins" and the originating binary/function so the
merged pool stays auditable. This is a CANDIDATE list -- manual review before
wiring into ATTACK_SCENARIOS, same caveat as the ART curator.
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

RAW_DIR = "commands_dataset/gtfobins_raw/_gtfobins"
MERGE_PATH = "commands_dataset/attack_commands_curated.json"

FUNCTION_TO_SCENARIO = {
    "file-read": "cred_access",
    "upload": "exfil",
    "file-upload": "exfil",
    "sudo": "privesc",
    "suid": "privesc",
    "capabilities": "privesc",
}

# Interactive / listening shell spawn -> would hang the non-TTY simulator.
SHELL_SPAWN_RE = re.compile(
    r"/bin/(?:ba)?sh\b|\bsh\s+-[ip]\b|\bbash\s+-[ip]\b|-exec\s+/?\S*sh\b"
    r"|:!\S*sh\b|\bexec\s+sh\b|reset;\s*sh|\bscript\s+/dev/null|/bin/dash"
)
# Interactive editors (hang on TTY) and listeners (hang waiting for a connection).
HANG_RE = re.compile(
    r"\b(?:vi|vim|nano|emacs|ed|less|more|man)\b"
    r"|\bnc\b[^\n]*\s-[a-z]*l|\bncat\b[^\n]*\s-[a-z]*l|\bsocat\b[^\n]*LISTEN"
)
# Still reject the genuinely destructive shapes (belt and braces; most are gone
# with the shell filter, but sudo snippets can still `rm`/`dd`).
DESTRUCTIVE_RE = re.compile(
    r"\breboot\b|\bshutdown\b|\bmkfs\b|\bdd\s+if=|\bfdisk\b|\bparted\b"
    r"|iptables\s+-F|rm\s+-rf\s+/(?!tmp)"
)

# Placeholder resolution. LFILE depends on tactic (set per-scenario below).
LOOPBACK = "127.0.0.1"
GENERIC_SUBS = [
    (re.compile(r"\$?\bRHOST\b|\battacker\.com\b|\btarget\.example\.com\b"), LOOPBACK),
    (re.compile(r"\$?\bLHOST\b"), LOOPBACK),
    (re.compile(r"\$?\bRPORT\b|\bLPORT\b|\b12345\b"), "2222"),
    (re.compile(r"/path/to/(?:input-file|file_to_send|input\.txt)"), "/etc/passwd"),
    (re.compile(r"/path/to/(?:output-file|file_to_save|output\.txt)"), "/tmp/gtfo_out"),
]
# Sensitive read target per tactic (what $LFILE / generic file placeholders become).
LFILE_BY_SCENARIO = {
    "cred_access": "/etc/shadow",   # the credential-access signal (rule 100510)
    "exfil": "/etc/passwd",         # data being exfiltrated
    "privesc": "/etc/passwd",
}
LFILE_RE = re.compile(r"\$?\bLFILE\b|/path/to/file_to_read|file_to_read")


def resolve(code: str, scenario: str) -> str:
    out = code
    for pat, repl in GENERIC_SUBS:
        out = pat.sub(repl, out)
    out = LFILE_RE.sub(LFILE_BY_SCENARIO[scenario], out)
    return out.strip()


def is_unsafe(command: str) -> str | None:
    if SHELL_SPAWN_RE.search(command):
        return "spawns interactive/listening shell"
    if HANG_RE.search(command):
        return "interactive editor or listener (would hang)"
    if DESTRUCTIVE_RE.search(command):
        return "destructive op"
    if re.search(r"\$\{?[A-Z_]{2,}\}?", command):
        return "unresolved placeholder"
    if "\n" in command.strip():
        # multi-line snippet: keep only if a single logical command; otherwise the
        # simulator would need to split it. Defer those to manual review.
        return "multi-line snippet"
    return None


def load_existing() -> dict:
    if os.path.exists(MERGE_PATH):
        with open(MERGE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def main() -> int:
    buckets = load_existing()
    for s in set(FUNCTION_TO_SCENARIO.values()):
        buckets.setdefault(s, [])

    # existing commands per bucket, for dedup across sources
    seen = {s: {item["command"] for item in items} for s, items in buckets.items()}

    stats = {"binaries": 0, "candidates": 0, "unsafe": 0, "dup": 0, "kept": 0}
    reasons: dict[str, int] = {}

    for path in sorted(glob.glob(f"{RAW_DIR}/*")):
        if os.path.isdir(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue  # Windows chokes on a few reserved/odd filenames; skip them
        # frontmatter is the whole file (--- ... ---); strip fences and parse.
        m = re.match(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL)
        block = m.group(1) if m else text
        try:
            doc = yaml.safe_load(block)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        binary = os.path.basename(path)
        stats["binaries"] += 1

        for func, entries in (doc.get("functions") or {}).items():
            scenario = FUNCTION_TO_SCENARIO.get(func)
            if not scenario or not isinstance(entries, list):
                continue
            for entry in entries:
                code = (entry or {}).get("code")
                if not code:
                    continue
                stats["candidates"] += 1
                command = resolve(code, scenario)
                reason = is_unsafe(command)
                if reason:
                    stats["unsafe"] += 1
                    reasons[reason] = reasons.get(reason, 0) + 1
                    continue
                if command in seen[scenario]:
                    stats["dup"] += 1
                    continue
                seen[scenario].add(command)
                buckets[scenario].append({
                    "technique": None,
                    "test_name": f"{binary} ({func})",
                    "command": command,
                    "cleanup_command": None,
                    "source": "gtfobins",
                    "gtfobins_binary": binary,
                    "gtfobins_function": func,
                    "lab_rewritten": command != code.strip(),
                })
                stats["kept"] += 1

    with open(MERGE_PATH, "w", encoding="utf-8") as fh:
        json.dump(buckets, fh, indent=2, ensure_ascii=False)

    print(f"stats: {stats}")
    print(f"drop reasons: {reasons}")
    for scenario in sorted(buckets):
        n = len(buckets[scenario])
        g = sum(1 for x in buckets[scenario] if x.get("source") == "gtfobins")
        print(f"  {scenario:12s} {n:3d} total ({g} from gtfobins)")
    print(f"-> {MERGE_PATH}")
    print("\nNOTE: candidate list -- manual review before wiring into ATTACK_SCENARIOS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
