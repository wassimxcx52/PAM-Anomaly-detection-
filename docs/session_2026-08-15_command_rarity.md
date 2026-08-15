# Session log — 2026-08-15
## Decoder truncation bug, command-rarity features, and two leaks caught

Continues `session_2026-08-09_unsupervised_precision.md`. **That document's
figures were measured on corrupted command data** (see §1) — its *reasoning*
holds, its *numbers* are superseded by this file.

Everything here is measured unless marked as a projection.

---

## 1. The decoder was silently truncating commands

Found while checking whether a vocabulary-rarity feature was viable: 21% of the
real distinct command vocabulary consisted of fragments ending in a backslash
(`awk '$1 != \`, `find /home -not -name \`).

Not a keystroke artifact — a **decoder bug**. `wallix_decoder.xml` captured
`data="([^"]*)"`. WALLIX escapes a quote inside a command as `\"`, so the regex
stopped at the *escaped* quote:

```
captured: (crontab -l 2>/dev/null; echo \
actual:   (crontab -l 2>/dev/null; echo \"*/5 * * * * /tmp/x.sh\") | crontab -
```

That is a persistence attack whose entire payload was discarded before it
reached the rules or the features.

**Scale:** 244 of 7506 KBD_INPUT events (3.3% of events, **21% of the distinct
vocabulary** — quoted `awk`/`find`/`echo` one-liners are exactly the long,
distinctive commands). **129 of the 256 eval sessions** were affected.

### Fixes

- `infra/wazuh/wallix_decoder.xml` — `data=` and `command_line=` now use
  `((?:[^"\\]|\\.)*)`, which consumes escaped pairs and stops only at the real
  closing quote. Validated against all 3835 real KBD_INPUT lines: identical
  match count, exactly the 244 corrected. Deployed and confirmed live via
  `wazuh-logtest` (rule 100514 now fires with the full command).
- `feature_extraction/extract.py` — `repair_command()` recovers truncated
  commands from `full_log`, which preserved the complete line, and unescapes the
  transport escaping. **No sessions had to be re-collected.** It only substitutes
  when the recovered value *extends* the decoder's, so a correct decode is never
  overwritten.

### Consequence for calibration

`calibration_slice.json` had been fitted to `avg_command_length` = 19.76,
computed from truncated commands. The repaired value is **21.12** — the
generator was calibrated 5% short on the strongest single feature. Re-ran
`build_calibration_slice.py` → `fit_generator.py` → regenerated everything.

---

## 2. Command-rarity features

`feature_extraction/command_profile.py`. Five columns scoring a session's
vocabulary against a benign profile: `cmd_oov_rate`, `cmd_mean_surprisal`,
`cmd_max_surprisal`, `cmd_mean_novelty`, `cmd_max_novelty` (the last two are
`1 - cosine similarity` to the nearest profile command over character n-grams,
so a near-miss of routine behaviour is not treated like a genuinely novel
command).

Every pre-existing command feature measures **shape** (how many, how long, how
varied). None looks at **which** commands were typed. That gap is why the forest
could not see the attacks the keyword rules miss.

**The profile is global, not per-persona.** Per-persona would be better security
(`tcpdump` is routine for infra, odd for a DBA) but is unavailable: `persona` is
NaN on all 49 real attack sessions, so it cannot be selected at scoring time for
exactly the sessions being hunted. Per-user degenerates to the same thing (one
real login user). Revisit when AD lands.

### Precondition, measured before building

If the generated and real benign vocabularies differed systematically,
`oov_rate` would measure "this data is real" rather than "this session is
unusual" — the same seam `command_safety.py` exists to prevent.

| | coverage by the generated profile |
|---|---|
| real **benign** vocabulary | **98.7%** |
| real **attack** vocabulary | **61.5%** |

Benign near-fully covered (no domain marker), attack 38.5% novel (the signal).

---

## 3. Leak #1 — the profile was fitted on the rows it scored

First implementation fitted the profile on all training benign, then scored
those same rows. Every training benign command is in the profile by
construction, so `cmd_oov_rate` was **exactly 0.0000 for all 5000 rows** — a
perfect label.

Symptoms: 5-fold CV PR-AUC **1.0000 ± 0.0000**; real eval collapsed to **8
distinct scores** with **64 sessions tied at 1.0**, including all 49 attacks. The
"precision@10 = 0.90" this produced was a coin flip inside the tie — the metric
was not measuring anything.

**Fix attempted:** K-fold cross-fitting (`add_rarity_features_crossfit`), the
standard treatment for any statistic derived from the target population.

**It did not work**, and the failure was the useful finding: the generator draws
from a **closed** vocabulary of 850 command types sampled 42 000 times, so
holding out 20% of *sessions* still leaves every command *type* in the profile.
Cross-fitting is still correct and retained — it is just not sufficient alone.

---

## 4. Leak #2 — a feature can be constant within one class only

The real fix was a new gate: `ml/feature_gate.py:reference_class_gate` drops any
column that is constant **within the training benign class**.

The whole-column domain gate cannot see this case — the column varies across the
training set (attacks differ) and varies in eval. Only the within-benign view
exposes that the model was handed a separator by construction rather than
learning one.

It needed a float tolerance: the novelty columns are `1.55e-16`, not `0.0`, so an
exact `nunique` test passes them (`FLAT_ABS_TOL = 1e-9`).

**Standing rule, now enforced in code:** a feature that does not vary within the
reference class is not a feature.

---

## 5. Opening the generator's vocabulary

Dropping the degenerate columns left `cmd_max_surprisal`, which still separated
training perfectly (unseen ⇒ exactly 16.379; generated benign never exceeded
10.5). The model was learning "an unseen command is present", not a threshold.

The mechanism copied is how real novelty actually arises: **novel arguments, not
novel programs.** Real benign runs `grep` constantly and
`grep cron /etc/rsyslog.d/50-default.conf` once. `generate_benign.vary_arguments`
resamples paths, filenames and small integers from large pools while leaving the
program and its flags exactly as curated — so `command_safety`'s guarantees are
untouched (no new head, no redirection).

Fitted as a third knob in `fit_generator.py` by the same bisection as the others:

```
tilt=+0.2091  stickiness=0.2912  arg_variation=0.0256
→ len=20.955  uniq=0.736  oov=0.0141   (target 0.0140)
```

### The OOV target is sample-size dependent — a trap worth recording

The same `arg_variation` yields **4.9% OOV at 150 sessions/persona and 0% at
1250**, because a thin profile shows novelty a thick one absorbs. `--oov-samples`
must therefore match `generate_benign.py --per-persona`, or the fit targets the
wrong number. Documented in the flag's help text.

Also note 22.5% ≠ 1.4%: real benign scored out-of-fold against *other real
benign* (165 sessions) gives 22.5%, while real benign against the *deployed
generated profile* (5000 sessions) gives 1.4%. Only the second is the right
target — both classes must be scored against the same profile.

Result: generated benign OOV **0.0132** vs real benign **0.0140**.

---

## 6. Results

Random Forest, fitted on generated (5882 rows, 85:15), judged on the 256 real
sessions. Same repaired data throughout; only the feature set differs.

| | shape features only | **+ rarity, closed vocab** | **+ rarity, open vocab** |
|---|---|---|---|
| Real PR-AUC | 0.417 | 0.782 | **0.921** |
| Real ROC-AUC | 0.656 | 0.956 | **0.982** |
| precision@10 | 0.70 | 0.80 | **1.00** |
| precision@25 | 0.68 | 0.72 | **0.92** |
| minus `p_admin` artifact, PR-AUC | 0.364 | 0.749 | **0.892** |
| Domain gap (generated → real) | 0.288 | 0.218 | **0.079** |
| **Flagless-16 ROC-AUC** | **0.502** | 0.944 | **0.963** |
| Flagless ranks in the 256 queue | scattered to 245 | top 66 | **top 64** |

**The thesis question (§8 item 7 of the previous log) is answered.** The 16 real
attacks carrying no keyword flag — invisible to `wallix_rules.xml` by
construction — are all ranked inside the top 64 of 256, from indistinguishable
from random. The rule layer scores precision 0.97 / recall 0.67 on the attacks it
*can* see and 0 on these.

Permutation importance on real data: `cmd_max_surprisal` 0.395,
`cmd_max_novelty` 0.121, `cmd_mean_novelty` 0.106, `cmd_oov_rate` 0.062,
`cmd_mean_surprisal` 0.054. Every shape feature is ≤ 0.008, and
`command_entropy` (−0.003) and `command_count` (−0.011) are still mildly harmful.

---

## 7. Open items

1. **Training is still perfectly separable** (CV PR-AUC 1.0000). Cause: the
   attack corpus (Atomic/GTFOBins) is *disjoint* from the benign corpus, so
   every generated attack session contains at least one unseen command — 0 of
   882 have `cmd_oov_rate == 0`. Real attacks are more varied (OOV quartiles
   0.071 / 0.286 / 0.444 / 0.75 / 1.0 against generated 0.067 / 0.10 / 0.154 /
   0.25 / 0.857). **The generator cannot currently produce a living-off-the-land
   attack** — one built entirely from ordinary commands. That is the next
   realism gap, and it is exactly what the hardest real insider case looks like.
2. **Residual error is false positives, not misses.** No real attack scores
   below 0.90; the ranking cost comes from benign sessions scoring high.
3. `command_entropy` sign inversion persists — generated attacks sit *above*
   benign, real attacks *below*. Harmful in permutation importance.
4. `ml/unsupervised/train.py` (the bake-off) still does not exist. It will hit
   its own version of §3 — fitted on benign only, every training session scores
   rarity 0 — so it must consume the cross-fitted columns, not refit a profile.
5. The transductive-gate question from the previous log is unchanged and now
   applies to `reference_class_gate` too, which reads training labels (not eval
   labels, so no evaluation leak).
