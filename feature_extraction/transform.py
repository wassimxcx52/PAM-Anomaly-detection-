import argparse
import json
import math
import os
import re
from collections import Counter

import numpy as np
import pandas as pd

# Protocols whose WALLIX telemetry actually carries typed commands (KBD_INPUT).
# RDP is GUI: WALLIX emits session lifecycle only (SESSION_ESTABLISHED /
# SESSION_DISCONNECTION with duration="H:MM:SS"), no per-command events, unless
# OCR/window-title capture is enabled on the connection policy. So for RDP the
# command features are NOT ZERO, they are ABSENT -- emitted as NaN so no model
# reads "entropy 0" as a real, unusually-repetitive session. See
# split_by_protocol() for why they must not share one fitted model either.
COMMAND_PROTOCOLS = {"SSH", "SFTP", "SCP", "TELNET"}

COMMAND_FEATURES = ["command_count", "unique_command_ratio",
                    "avg_command_length", "command_entropy"]

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


def duration_seconds(row, start, end) -> float:
    """Prefer WALLIX's own duration (parsed by extract.py from duration="H:MM:SS"
    on SESSION_DISCONNECTION) -- it covers the whole session including idle time.
    Fall back to end-start, which for command-only sessions spans first to last
    keystroke and so understates the session."""
    d = row.get("duration_sec")
    if d is not None and not pd.isna(d):
        return float(d)
    if pd.notna(start) and pd.notna(end):
        return max(0.0, (end - start).total_seconds())
    return float("nan")


def per_session_features(row) -> dict:
    protocol = (row.get("protocol") or "").upper()
    has_commands = protocol in COMMAND_PROTOCOLS
    commands = normalize_commands(row.get("commands") or [])
    n = len(commands)

    start = time_parser(row["session_start"])
    end = time_parser(row["session_end"])

    features = {
        # ---- protocol-agnostic (valid for SSH and RDP alike) ----
        "session_id": row["session_id"],
        "protocol": protocol or None,
        "has_command_telemetry": int(has_commands),
        "start_time": start,
        "end_time": end,
        "duration_sec_feat": duration_seconds(row, start, end),
        "start_hour": start.hour if pd.notna(start) else np.nan,
        "off_hours_flag": (int(start.hour < 8 or start.hour >= 18)
                           if pd.notna(start) else np.nan),
        "is_weekend": int(start.weekday() >= 5) if pd.notna(start) else np.nan,
        # ---- command-based (NaN when the protocol carries no commands) ----
        "command_count": n if has_commands else np.nan,
        "unique_command_ratio": ((len(set(commands)) / n) if n else 0.0) if has_commands else np.nan,
        "avg_command_length": ((sum(len(c) for c in commands) / n) if n else 0.0) if has_commands else np.nan,
        "command_entropy": command_entropy(commands) if has_commands else np.nan,
    }
    # Same rule for the risk flags: absence of evidence, not evidence of absence.
    flags = risk_flags(commands) if has_commands else {
        f"flag_{c}": np.nan for c in RISK_KEYWORDS}
    features.update(flags)
    return features


def build_features(sessions_path: str) -> pd.DataFrame:
    sessions = load_sessions(sessions_path)
    feature_rows = [per_session_features(row) for _, row in sessions.iterrows()]

    features = pd.DataFrame(feature_rows)
    # 'protocol' comes from both frames; keep the normalised one from features.
    sessions = sessions.drop(columns=["protocol"], errors="ignore")
    return sessions.merge(features, on="session_id")


def split_by_protocol(features: pd.DataFrame) -> dict:
    """One shared matrix, one model PER PROTOCOL.

    A single detector fitted across both protocols would be fitted on a feature
    space where a whole block of columns is missing for one of them -- PyOD's
    ECOD/COPOD/HBOS/IForest have no NaN handling, and imputing the command
    columns to 0 for RDP hands the model a perfect protocol proxy: it learns
    "RDP" rather than "anomalous". Splitting keeps the substrate shared (same
    extract -> same transform -> same columns) while each detector sees only
    columns that mean something for its protocol.
    """
    return {proto: grp.copy()
            for proto, grp in features.groupby(features["protocol"].fillna("UNKNOWN"))}


def usable_columns(features: pd.DataFrame) -> list:
    """Drop all-NaN columns -- i.e. the command block for an RDP-only slice."""
    return [c for c in features.columns if not features[c].isna().all()]


# Paths are anchored to this file, not the CWD, so the script runs from anywhere.
HERE = os.path.dirname(os.path.abspath(__file__))
IN_PATH = os.path.join(HERE, "..", "dataset_generation", "out", "generated_benign.jsonl")
OUT_PATH = os.path.join(HERE, "out", "features_benign.csv")

PREVIEW_COLS = ["session_id", "protocol", "start_time", "duration_sec_feat",
                "off_hours_flag", "command_count", "unique_command_ratio",
                "avg_command_length", "command_entropy", "flag_cred_access",
                "flag_privesc", "flag_persistence", "flag_log_tamper",
                "flag_recon", "flag_exfil"]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="session features (protocol-aware)")
    ap.add_argument("--in", dest="in_path", default=IN_PATH,
                    help="sessions.jsonl-shaped input (real or generated)")
    ap.add_argument("--out", dest="out_path", default=OUT_PATH,
                    help="combined output CSV; per-protocol slices are written "
                         "alongside it as <out>.<PROTOCOL>.csv")
    ap.add_argument("--no-split", action="store_true",
                    help="skip the per-protocol slices (combined CSV only)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out_path)), exist_ok=True)
    result = build_features(args.in_path)

    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(result[[c for c in PREVIEW_COLS if c in result.columns]])

    result.to_csv(args.out_path, index=False)
    print(f"[transform] {len(result)} sessions -> {args.out_path}")

    if not args.no_split:
        base, ext = os.path.splitext(args.out_path)
        for proto, slice_ in split_by_protocol(result).items():
            cols = usable_columns(slice_)
            path = f"{base}.{proto}{ext}"
            slice_[cols].to_csv(path, index=False)
            print(f"[transform]   {proto}: {len(slice_)} sessions, "
                  f"{len(cols)} usable columns -> {path}")
