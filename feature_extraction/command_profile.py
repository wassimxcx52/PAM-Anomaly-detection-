#!/usr/bin/env python3
"""
command_profile.py -- how unusual is this session's VOCABULARY?

Every command feature that existed before this file measures shape:
command_count (how many), avg_command_length (how long), unique_command_ratio
and command_entropy (how varied). None of them look at WHICH commands were
typed. A session of ten identical commands scores the same whether they are
`ls` or `cat /etc/shadow`.

That gap is why the forest could not see the attacks the keyword rules miss
(docs/session_2026-08-09_unsupervised_precision.md, sec 8 item 7): with no
keyword and no unusual shape, an attack is invisible to the whole feature set.
This module adds the missing axis -- rarity of the vocabulary against a profile
of normal behaviour -- and it is behavioural rather than a keyword lookup, which
is exactly the distinction the report has to defend against
"the ML just re-ranks the rules".

WHY THE PROFILE IS GLOBAL, NOT PER-PERSONA
------------------------------------------
Per-persona would be better security: `tcpdump` is routine for infra and odd for
a DBA. It is not available. `persona` is NaN on all 49 real attack sessions
(measured), so at scoring time the profile could not be selected for exactly the
sessions being hunted, and per-user degenerates to the same thing because real
telemetry carries one login user. A global profile is what transfers today;
per-persona becomes meaningful when AD lands and real per-user baselines exist
(CLAUDE.md sec 13).

FIT ON BENIGN, FROM TRAINING DATA ONLY
--------------------------------------
The profile is a model parameter, not a feature transform: fitting it on
anything the model is scored against would leak. It is fitted on the TRAINING
benign sessions, saved to JSON, and applied unchanged to eval. Training attack
rows are scored against it too -- they are supposed to look rare.

FIVE COLUMNS, TWO MECHANISMS
----------------------------
  cmd_oov_rate        share of commands never seen in the profile
  cmd_mean_surprisal  mean -log2 p(command); how unlikely the session's
                      vocabulary is under the benign distribution
  cmd_max_surprisal   the single most unusual command, so ONE rare command
                      buried in nineteen ordinary ones still registers --
                      the buried-attack case the generator spends 83% of its
                      attack budget on
  cmd_mean_novelty    1 - cosine similarity to the nearest profile command over
  cmd_max_novelty     character n-grams

The n-gram columns exist because exact matching is brittle. `cat /etc/shadow`
and `cat /etc/passwd.bak` are both "unseen", but one is a near-miss of routine
behaviour and the other is not; character n-grams give graded distance instead
of a binary hit, and they degrade gracefully when a benign user types a familiar
command with a novel argument -- which is most of what benign novelty looks like.

THE RISK THIS WAS CHECKED AGAINST FIRST
---------------------------------------
If the generated benign vocabulary and the real one differed systematically,
oov_rate would fire on every real session and measure "this data is real"
instead of "this session is unusual" -- the same seam command_safety.py exists
to prevent. Measured after the decoder repair (2026-08-15):

    real BENIGN vocabulary covered by the generated profile:  98.7%
    real ATTACK vocabulary covered by the generated profile:  61.5%

Benign is near-fully covered, so the feature does not mark real data; attack
vocabulary is 38.5% novel, which is the signal. Re-run that check whenever the
generated vocabulary changes -- it is the precondition for these columns
meaning anything.
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter

import numpy as np

# Character n-grams, not word tokens: an attack often differs from routine
# behaviour by a path or a flag rather than by the program name, and char_wb
# keeps the comparison inside word boundaries so `/etc/shadow` and `/etc/passwd`
# are near without `cat` alone making everything near.
NGRAM_RANGE = (3, 5)
ANALYZER = "char_wb"

# Add-k smoothing. A single unseen command should be surprising but not
# infinitely so -- with alpha=0.5 an unseen command in a 40k-command profile
# scores around 16 bits, roughly twice the most common command's, which keeps
# max_surprisal on a usable scale instead of dominated by one outlier.
ALPHA = 0.5

FEATURES = ["cmd_oov_rate", "cmd_mean_surprisal", "cmd_max_surprisal",
            "cmd_mean_novelty", "cmd_max_novelty"]


def fit(command_lists, *, fitted_from: str = "") -> dict:
    """Build a profile from an iterable of per-session command lists.

    Callers pass BENIGN, NORMALISED commands (transform.normalize_commands), so
    the scaffolding strip and keystroke-token cleanup have already happened and
    the profile cannot be polluted by `echo TAG:` markers.
    """
    counts: Counter = Counter()
    sessions = 0
    for commands in command_lists:
        sessions += 1
        counts.update(commands)
    return {
        "fitted_from": os.path.normpath(fitted_from) if fitted_from else "",
        "n_sessions": sessions,
        "n_commands": int(sum(counts.values())),
        "vocabulary_size": len(counts),
        "alpha": ALPHA,
        "ngram_range": list(NGRAM_RANGE),
        "counts": dict(counts),
    }


def save(profile: dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Scorer:
    """A fitted profile, ready to score sessions.

    The TF-IDF vectorizer is rebuilt from the profile's command list at load
    time rather than pickled: fitting on a few hundred strings is instant, and a
    JSON profile stays readable, diffable and committable, which a pickle is
    not.
    """

    def __init__(self, profile: dict):
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.counts = profile["counts"]
        self.total = max(1, int(profile.get("n_commands") or sum(self.counts.values())))
        self.alpha = float(profile.get("alpha", ALPHA))
        self.vocabulary = set(self.counts)

        # +1 reserves probability mass for the unseen command as a single
        # aggregate outcome, so the distribution still sums to one.
        self._denominator = self.total + self.alpha * (len(self.counts) + 1)
        self._unseen_surprisal = -math.log2(self.alpha / self._denominator)

        commands = list(self.counts)
        self._vectorizer = TfidfVectorizer(
            analyzer=profile.get("analyzer", ANALYZER),
            ngram_range=tuple(profile.get("ngram_range", NGRAM_RANGE)),
        )
        self._matrix = self._vectorizer.fit_transform(commands)
        # L2-normalised by TfidfVectorizer, so a dot product IS cosine similarity.

    def surprisal(self, command: str) -> float:
        count = self.counts.get(command)
        if count is None:
            return self._unseen_surprisal
        return -math.log2((count + self.alpha) / self._denominator)

    def novelty(self, commands: list) -> np.ndarray:
        """1 - cosine similarity to the nearest profile command, per command.

        A command sharing no n-gram with anything in the profile has similarity
        0 and novelty 1.
        """
        if not commands:
            return np.zeros(0)
        similarity = self._vectorizer.transform(commands) @ self._matrix.T
        nearest = similarity.max(axis=1).toarray().ravel()
        return 1.0 - nearest

    def score(self, commands: list) -> dict:
        """The five columns for one session.

        An empty session gets zeros, not NaN: it genuinely contains no unusual
        vocabulary. That is different from the RDP case (no command telemetry at
        all), which transform.py already emits as NaN before reaching here.
        """
        if not commands:
            return dict.fromkeys(FEATURES, 0.0)

        surprisals = [self.surprisal(c) for c in commands]
        novelties = self.novelty(commands)
        unseen = sum(1 for c in commands if c not in self.vocabulary)

        return {
            "cmd_oov_rate": unseen / len(commands),
            "cmd_mean_surprisal": float(np.mean(surprisals)),
            "cmd_max_surprisal": float(np.max(surprisals)),
            "cmd_mean_novelty": float(np.mean(novelties)),
            "cmd_max_novelty": float(np.max(novelties)),
        }
