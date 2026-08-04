import json
import math
import os
import re
from collections import Counter

import pandas as pd

# Keyword categories mirror the Wazuh rule taxonomy in wallix_rules.xml (100510-100520)
# so ML features and rule-layer detections stay comparable, not a competing taxonomy.
# Cross-check against the actual rule regexes if those drift.
RISK_KEYWORDS = {
    "cred_access": ["/etc/shadow", "/etc/gshadow", "id_rsa", "id_ed25519",
                    ".ssh/authorized_keys", ".aws/credentials", "mimikatz", "/etc/passwd"],
    "privesc": ["useradd", "usermod", "sudoers", "visudo", "chmod u+s", "chmod +s",
                "setcap", "setuid", "passwd root"],
    "persistence": ["crontab", "/etc/cron", "authorized_keys", "systemctl enable",
                     "/etc/systemd/system", "rc.local", "/etc/init.d"],
    "log_tamper": ["history -c", "rm /var/log", "> /var/log", "shred", "logrotate -f",
                   "unset histfile", "auditctl -e 0"],
    "recon": ["whoami", "netstat", "nmap", "arp -a", "uname -a", "id", "last", "who", "lsof"],
    "exfil": ["scp ", "rsync ", "curl -t", "curl --upload", "nc ", "wget --post", "base64 |"],
}


def load_sessions(path: str) -> pd.DataFrame:
    """sessions.jsonl is JSON-Lines (one object per line), not a single JSON array."""
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def strip_scaffolding(commands):
    """Drop simulate_sessions.py artifacts that aren't real session content:
    the `echo TAG:<tag>` marker (always the first command, used only to join
    ground_truth.jsonl to the real session) and a trailing `exit`. Left in,
    both inflate command_count/skew unique_command_ratio identically across
    every session -- not a between-class bias, but still wrong. Operates on
    a copy; extract.py's raw commands list stays untouched for audit."""
    out = [c for c in commands if not c.strip().startswith("echo TAG:")]
    if out and out[-1].strip() == "exit":
        out = out[:-1]
    return out


def normalize_commands(commands):
    """Strip WALLIX literal keystroke tokens (<NL>, <TAB>, <BACKSPACE>) before computing
    entropy/length, else e.g. "ss -tulpn<NL>w<NL>who" skews stats as one long fake command.
    This is a text-level strip, not a true backspace replay (a real <BACKSPACE> should erase
    the preceding character(s), not just vanish) - good enough for v1, revisit if it matters."""
    normalized = []
    for c in strip_scaffolding(commands):
        c = c.replace("<NL>", " ").replace("<TAB>", " ").replace("<BACKSPACE>", "")
        normalized.append(c.strip())
    return normalized

def time_parser(time_str) -> pd.Timestamp:
    """Parse WALLIX timestamp into a pandas Timestamp; None (session not yet
    closed / lifecycle not captured) becomes NaT rather than raising."""
    return pd.to_datetime(time_str, format="ISO8601", errors="coerce")

def command_entropy(commands) -> float:
    """Shannon entropy over the per-session command frequency distribution."""
    if not commands:
        return 0.0
    counts = Counter(commands)
    n = len(commands)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _keyword_hit(keyword: str, text: str) -> bool:
    # Short alnum-only keywords (id, who, last...) need word boundaries or they false-positive
    # as substrings of unrelated words (e.g. "id" inside "provider"). Path/flag-like keywords
    # (/etc/shadow, chmod u+s) aren't ambiguous, so plain substring is fine for those.
    if re.fullmatch(r"[a-z0-9_]+", keyword):
        return re.search(rf"\b{re.escape(keyword)}\b", text) is not None
    return keyword in text


def risk_flags(commands) -> dict:
    joined = " ".join(commands).lower()
    return {
        f"flag_{category}": int(any(_keyword_hit(kw, joined) for kw in keywords))
        for category, keywords in RISK_KEYWORDS.items()
    }


def per_session_features(row) -> dict:
    commands = normalize_commands(row["commands"] or [])
    n = len(commands)

    features = {
        "session_id": row["session_id"],
        "command_count": n,
        "unique_command_ratio": (len(set(commands)) / n) if n else 0.0,
        "avg_command_length": (sum(len(c) for c in commands) / n) if n else 0.0,
        "command_entropy": command_entropy(commands),
        "start_time": time_parser(row["session_start"]),
        "end_time": time_parser(row["session_end"]),
    }
    features.update(risk_flags(commands))
    return features


def build_features(sessions_path: str) -> pd.DataFrame:
    sessions = load_sessions(sessions_path)
    feature_rows = [per_session_features(row) for _, row in sessions.iterrows()]

    features = pd.DataFrame(feature_rows)
    return sessions.merge(features, on="session_id")


if __name__ == "__main__":
    os.makedirs("./out", exist_ok=True)
    result = build_features("./out/sessions.jsonl")
    cols = ["session_id","start_time", "end_time", "command_count", "unique_command_ratio", "avg_command_length",
            "command_entropy", "flag_cred_access", "flag_privesc", "flag_persistence",
            "flag_log_tamper", "flag_recon", "flag_exfil"]
    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(result[cols])

    result.to_csv("./out/features.csv", index=False)
