import argparse
import json
import math
import os
import re
from collections import Counter

import numpy as np
import pandas as pd

import command_profile

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


def _blank(value):
    """A field absent from SOME rows comes back as NaN (float), not None, once
    pandas has squared up the frame -- real sessions.jsonl has such rows where
    WALLIX never emitted the lifecycle event. `or ""` does not catch NaN."""
    return value is None or (isinstance(value, float) and pd.isna(value))


def per_session_features(row) -> dict:
    raw_protocol = row.get("protocol")
    protocol = "" if _blank(raw_protocol) else str(raw_protocol).upper()
    has_commands = protocol in COMMAND_PROTOCOLS
    raw_commands = row.get("commands")
    commands = normalize_commands([] if _blank(raw_commands) else raw_commands)
    n = len(commands)

    start = time_parser(row.get("session_start"))
    end = time_parser(row.get("session_end"))

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


# ─────────────────────────── source-IP features ─────────────────────────────
# The first CROSS-SESSION features: everything above describes one session in
# isolation, these describe a session against that identity's own history.
#
# NO FUTURE LEAKAGE. Each session is scored using strictly EARLIER sessions only
# (`as_of` = its own session_start). A naive groupby would let a user's later
# sessions define what was "already known" at the time of an earlier one, which
# inflates every result and is invisible in the output. Hence the explicit
# time-ordered single pass rather than pandas aggregation.
#
# THE SIGNAL THESE ARE FOR. The interesting insider case is not an unknown IP --
# it is a KNOWN IP attached to the WRONG identity (`ip_foreign_to_user`): a real
# workstation address from another team's subnet. That is why "seen before
# globally" and "normal for this user" are tracked separately; jump hosts are a
# small shared IP set precisely so the two diverge.
#
# WHERE THEY ARE MEANINGFUL. Real WALLIX telemetry carries ONE login user and ONE
# client IP (lab constraint), so on real sessions these columns are constant and
# will be rejected by ml/unsupervised/train.py's domain gate -- correctly. They
# are built for the generated side and for the supervised track. Documented, not
# worked around.
#
# CAVEAT on the 24h window: generate_benign.py currently draws each timestamp
# independently, so a generated user has no real "day". distinct_source_ips_24h
# is computed correctly but its input is not yet realistic; it becomes meaningful
# once the generator emits per-user timelines.

IP_FEATURES = ["new_source_ip_for_user", "new_source_ip_globally",
               "ip_foreign_to_user", "distinct_source_ips_prior",
               "distinct_source_ips_24h", "source_ip_entropy"]


def _shannon(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    h = -sum((c / total) * math.log2(c / total) for c in counter.values())
    return abs(h)      # a single-IP history gives -0.0; write 0.0


def add_ip_features(features: pd.DataFrame) -> pd.DataFrame:
    """Per-user source-IP history features, computed as_of each session start.

    Conventions, chosen so a first session is not silently indistinguishable from
    a repeat one:
      * a user's FIRST session is new_source_ip_for_user = 1 (it is, trivially),
        with distinct_source_ips_prior = 0 and source_ip_entropy = 0.0
      * ip_foreign_to_user requires the IP to be globally known AND new to this
        user, so a genuinely first-ever IP does not count as "foreign"
      * a session with no client_ip or no parseable timestamp gets NaN, never 0 --
        absence of evidence is not evidence of absence
    """
    out = {c: [np.nan] * len(features) for c in IP_FEATURES}

    if "client_ip" not in features.columns or "user" not in features.columns:
        for column in IP_FEATURES:
            features[column] = out[column]
        return features

    # Time order is the whole point; NaT sorts last and is skipped below.
    order = features["start_time"].argsort(kind="stable")

    seen_by_user: dict[str, Counter] = {}
    history: dict[str, list] = {}        # user -> [(timestamp, ip)]
    seen_globally: set = set()

    for pos in order:
        row = features.iloc[pos]
        user, ip, start = row.get("user"), row.get("client_ip"), row.get("start_time")
        if _blank(user) or _blank(ip) or pd.isna(start):
            continue

        prior = seen_by_user.get(user, Counter())
        known_to_user = ip in prior
        known_globally = ip in seen_globally

        out["new_source_ip_for_user"][pos] = int(not known_to_user)
        out["new_source_ip_globally"][pos] = int(not known_globally)
        # known address, unknown for THIS identity -- the strong insider signal
        out["ip_foreign_to_user"][pos] = int(known_globally and not known_to_user)
        out["distinct_source_ips_prior"][pos] = len(prior)
        out["source_ip_entropy"][pos] = _shannon(prior)

        window = [i for t, i in history.get(user, [])
                  if (start - t).total_seconds() <= 86400]
        out["distinct_source_ips_24h"][pos] = len(set(window) | {ip})

        # Update AFTER scoring, so the current session never informs its own features.
        seen_by_user.setdefault(user, Counter())[ip] += 1
        seen_globally.add(ip)
        history.setdefault(user, []).append((start, ip))

    for column in IP_FEATURES:
        features[column] = out[column]
    return features


def _normalised_commands(features: pd.DataFrame) -> list:
    """Normalised command list per row, or None where the protocol carries no
    command telemetry. Computed once and reused by every rarity path."""
    out = []
    for _, row in features.iterrows():
        if not row.get("has_command_telemetry"):
            out.append(None)
        else:
            raw = row.get("commands")
            out.append(normalize_commands([] if _blank(raw) else raw))
    return out


def _score_rows(scorer, commands_per_row: list, positions) -> dict:
    scores = {}
    for pos in positions:
        commands = commands_per_row[pos]
        scores[pos] = (dict.fromkeys(command_profile.FEATURES, np.nan)
                       if commands is None else scorer.score(commands))
    return scores


def add_rarity_features(features: pd.DataFrame, scorer) -> pd.DataFrame:
    """Vocabulary-rarity columns from an already-fitted profile (scoring mode).

    Sessions whose protocol carries no command telemetry get NaN, for the same
    reason the other command features do: absence of evidence is not evidence of
    absence, and a 0 here would read as "perfectly ordinary vocabulary".
    """
    commands_per_row = _normalised_commands(features)
    scores = _score_rows(scorer, commands_per_row, range(len(features)))
    return pd.concat([features.reset_index(drop=True),
                      pd.DataFrame([scores[i] for i in range(len(features))])], axis=1)


def add_rarity_features_crossfit(features: pd.DataFrame, benign_mask: pd.Series,
                                 folds: int, seed: int) -> pd.DataFrame:
    """Rarity columns for the TRAINING set, fitted OUT OF FOLD.

    WHY THIS EXISTS. Scoring a benign session against a profile built from all
    benign sessions -- including itself -- makes cmd_oov_rate identically 0 for
    every training benign row, because its own commands are in the profile by
    construction. That is not a small bias: it is a perfect separator. Measured
    on the first attempt (2026-08-15), it drove 5-fold CV PR-AUC to 1.0000 +/-
    0.0000 and collapsed the real eval scores to 8 distinct values with 64
    sessions tied at 1.0, which makes precision@k a coin flip inside the tie
    rather than a measurement.

    The fix is the standard one for any statistic derived from the target
    population: K-fold cross-fitting. Each benign row is scored against a
    profile built from the OTHER folds, so its own vocabulary never defines its
    own normality, and its oov_rate becomes what a genuinely unseen benign
    session would score.

    Attack rows are scored against the full benign profile. They never
    contribute to it, so there is nothing to hold out -- and scoring them
    against a thinner fold-profile would inflate their rarity relative to the
    benign rows they are compared against.
    """
    commands_per_row = _normalised_commands(features)
    benign_positions = np.flatnonzero(benign_mask.to_numpy())
    other_positions = np.flatnonzero(~benign_mask.to_numpy())

    rng = np.random.default_rng(seed)
    assignment = rng.permutation(len(benign_positions)) % folds
    scores: dict = {}

    for fold in range(folds):
        held_out = benign_positions[assignment == fold]
        fit_on = benign_positions[assignment != fold]
        profile = command_profile.fit(
            [commands_per_row[p] for p in fit_on if commands_per_row[p] is not None])
        scores.update(_score_rows(command_profile.Scorer(profile),
                                  commands_per_row, held_out))

    if len(other_positions):
        full = command_profile.fit(
            [commands_per_row[p] for p in benign_positions
             if commands_per_row[p] is not None])
        scores.update(_score_rows(command_profile.Scorer(full),
                                  commands_per_row, other_positions))

    print(f"[profile] cross-fitted over {folds} folds: "
          f"{len(benign_positions)} benign scored out-of-fold, "
          f"{len(other_positions)} non-benign scored against the full profile")

    return pd.concat([features.reset_index(drop=True),
                      pd.DataFrame([scores[i] for i in range(len(features))])], axis=1)


def build_features(sessions_path: str, profile_path: str = "",
                   fit_profile_path: str = "", folds: int = 5,
                   seed: int = 42) -> pd.DataFrame:
    sessions = load_sessions(sessions_path)
    feature_rows = [per_session_features(row) for _, row in sessions.iterrows()]

    features = pd.DataFrame(feature_rows)
    # 'protocol' comes from both frames; keep the normalised one from features.
    sessions = sessions.drop(columns=["protocol"], errors="ignore")
    merged = sessions.merge(features, on="session_id")
    merged = add_ip_features(merged)

    # The profile is a model parameter fitted on BENIGN only. Two distinct modes:
    #   --fit-profile : this is the training set. Save a full-benign profile for
    #                   later scoring, but give the training rows themselves
    #                   CROSS-FITTED values (see add_rarity_features_crossfit).
    #   --profile     : this is an evaluation set. Score against the saved
    #                   profile, which contains none of these sessions.
    if fit_profile_path:
        label = merged["label"] if "label" in merged.columns else pd.Series(
            "benign", index=merged.index)
        benign_mask = label == "benign"

        commands = [normalize_commands([] if _blank(c) else c)
                    for c in merged.loc[benign_mask, "commands"]]
        profile = command_profile.fit(commands, fitted_from=sessions_path)
        command_profile.save(profile, fit_profile_path)
        print(f"[profile] fitted on {profile['n_sessions']} benign sessions, "
              f"{profile['n_commands']} commands, "
              f"{profile['vocabulary_size']} distinct -> {fit_profile_path}")

        return add_rarity_features_crossfit(merged, benign_mask, folds, seed)

    if profile_path:
        scorer = command_profile.Scorer(command_profile.load(profile_path))
        merged = add_rarity_features(merged, scorer)

    return merged


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
    ap.add_argument("--fit-profile", default="",
                    help="fit a command-rarity profile on this input's BENIGN "
                         "sessions and write it here (training data only)")
    ap.add_argument("--profile", default="",
                    help="apply an existing command-rarity profile (fitted on "
                         "training benign) and emit the cmd_* columns")
    ap.add_argument("--profile-folds", type=int, default=5,
                    help="cross-fitting folds for --fit-profile, so a training "
                         "session never defines its own normality")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out_path)), exist_ok=True)
    result = build_features(args.in_path, profile_path=args.profile,
                            fit_profile_path=args.fit_profile,
                            folds=args.profile_folds, seed=args.seed)

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
