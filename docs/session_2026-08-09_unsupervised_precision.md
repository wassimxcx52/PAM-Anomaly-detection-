# Session log — 2026-08-09
## Unsupervised data strategy for precision: analysis, decisions, and generator calibration

> ⚠️ **THE NUMBERS IN THIS FILE ARE SUPERSEDED.** Every measurement here was
> taken on command data corrupted by the decoder truncation bug found on
> 2026-08-15 (`data="([^"]*)"` stopped at WALLIX's escaped quote; 244 of 7506
> KBD_INPUT events cut, 21% of the distinct vocabulary, 129 of the 256 eval
> sessions affected). The **reasoning** in this document still holds and is
> cited by `decision_log.md` and `ml/feature_gate.py`. The **figures** are
> replaced by `session_2026-08-15_command_rarity.md`. Do not quote this file's
> metrics in the report.

Working notes from a full session. Written in English because it feeds the French
report and the decision log. Everything here is measured unless explicitly marked
as a projection.

**Scope of the session:** understand the existing feature matrix → quantify the
generated-vs-real domain gap → narrow to the unsupervised track with precision as
the objective → fix the generator's benign distribution.

**Files created:** `dataset_generation/metadata/build_calibration_slice.py`,
`dataset_generation/metadata/calibration_slice.json`,
`dataset_generation/fit_generator.py`,
`dataset_generation/metadata/generator_params.json`.

**Files NOT yet modified:** `generate_benign.py` (next step),
`generated_benign.jsonl` (not yet regenerated).

---

## 1. What the 51 columns of `features_benign.csv` actually are

Only ~20 are features. The rest is passthrough identity, provenance, and audit
trail. Four groups:

**Session identity (passthrough from the generator):** `session_id`, `user`,
`account` (the borrowed vaulted identity — distinct from `user`, the core PAM
signal), `client_ip`, `target_ip`, `target_hostname`, `session_start`/`session_end`/
`duration_sec` (raw source values; the parsed versions are `start_time`/`end_time`/
`duration_sec_feat`), `commands` (raw, unnormalised, kept lossless for audit),
`event_types`, `raw_event_count`, `file_transfer_bytes`.

**Labels and provenance:** `label`, `tactics`, `source` (`generated` vs `real` —
enforces "generated trains, real judges"), `split`, `persona`, `ip_source`,
`target_group`, `target_criticality` (impact weight for risk = anomaly × impact,
*not* a model input), `identity_is_synthetic` / `ip_is_synthetic` /
`ts_is_synthetic`, and `real_user` / `real_client_ip` / `real_target_ip` /
`real_target_hostname` (the actual lab values before rewriting).

**Session-level computed features** (`transform.py:127`):
`protocol`, `has_command_telemetry`, `start_time`, `end_time`, `duration_sec_feat`,
`start_hour`, `off_hours_flag`, `is_weekend`, `command_count`,
`unique_command_ratio`, `avg_command_length`, `command_entropy`, and six
`flag_*` risk-keyword booleans.

Command features are computed on a *normalised copy*: `echo TAG:` marker and
trailing `exit` stripped, `<NL>`/`<TAB>`/`<BACKSPACE>` keystroke tokens removed.
For protocols carrying no command telemetry (RDP) they are **NaN, not 0** — so no
model reads "entropy 0" as a genuinely repetitive session.

**Cross-session IP history features** (`transform.py:203`): `new_source_ip_for_user`,
`new_source_ip_globally`, `ip_foreign_to_user` (globally known IP, new to *this*
identity — the strong insider signal), `distinct_source_ips_prior`,
`distinct_source_ips_24h`, `source_ip_entropy`. Computed in a time-ordered single
pass with state updated *after* scoring, so no future leakage.

> ⚠️ `target_group`, `target_criticality`, `ip_source`, `persona` and all `real_*`
> columns must never reach a model — they are generator knobs and would leak the
> label.

---

## 2. Does generated data affect evaluation on real data?

No leakage — `eval_real.jsonl` is never trained on. But there is real impact, and
it is measurable. Compared 1000 generated vs 256 real sessions.

### What transfers well

| feature | gen mean/std | real mean/std |
|---|---|---|
| `command_count` | 8.46 / 2.73 | 8.61 / 3.64 |
| `unique_command_ratio` | 0.68 / 0.17 | 0.76 / 0.17 |
| `avg_command_length` | 17.9 / 7.3 | 20.8 / 10.3 |
| `command_entropy` | 2.22 / 0.65 | 2.39 / 0.76 |
| `duration_sec_feat` | 7.17 / 2.38 | 7.59 / 3.93 |

### What is dead on real eval

- **All 6 IP features are constant.** `source_ip_entropy` = 0.0 everywhere (gen
  mean 0.76), `distinct_source_ips_24h` = 1, `ip_foreign_to_user` = 0 for all 256.
  Predicted by the lab constraint (one login user, one client IP).
- **All 3 temporal features are constant too.** `off_hours_flag` = 0 and
  `is_weekend` = 0 for every real session, and `start_hour` std = **0.062** — all
  256 real sessions landed in the same minute (~12:00). This was not previously
  documented in CLAUDE.md.

**The failure mode is specific:** constant features do *not* break ranking (they
shift every real session equally), so precision@k survives. They *do* break
threshold transfer — every real session sits in an out-of-support corner of 9
dimensions at once, so any cutoff learned on generated data is meaningless.

### The `flag_*` problem

Generated benign has `flag_privesc`, `flag_cred_access`, `flag_persistence`,
`flag_log_tamper`, `flag_exfil` **identically 0 across all 1000 rows** (zero
variance). On real they fire on 32/49 attacks and 1/207 benigns.

A one-class detector fit on that treats any flag=1 as maximum-extreme tail, so
those 6 columns become effectively the whole detector — the ML would be a
re-implementation of Wazuh rules 100510–100520, the exact circularity CLAUDE.md §8
warns about.

**Decision: exclude `flag_*` from model input; keep them as the rule-layer
baseline to benchmark against.**

**17 of 49 attacks trigger no keyword flag at all** — precisely the population the
rule layer structurally cannot see, and the population that justifies the platform.

---

## 3. Reframe: unsupervised only, precision as the objective

In one-class you never model attacks. The detector learns a benign region and
scores distance from it, so precision@k is decided by two properties of the
**benign** distribution:

1. **Does generated benign sit where real benign sits?** If not → real benign
   scores high → false positives.
2. **Is generated benign no *wider* than real benign?** If wider → the normal
   region swallows attacks → they never reach top-k.

### The right diagnostic is not Cohen's *d*

Cohen's *d* assumes you are separating two *modelled* classes. A one-class detector
computes **displacement from the training mean**, in training σ. Measured:

| feature | real benign | attack | separation ratio |
|---|---|---|---|
| `avg_command_length` | +0.16σ | **+1.39σ** | **8.7×** |
| `unique_command_ratio` | +0.37σ | +1.16σ | 3.1× |
| `command_count` | +0.16σ | −0.42σ | 2.6× |
| `duration_sec_feat` | +0.28σ | −0.25σ | 0.9× |
| `command_entropy` | +0.32σ | +0.01σ | **0.03×** |

**`command_entropy` was an anti-feature**: attacks land exactly on the training
mean while real benign sits a third of a σ above it — it generates false positives
and camouflages attacks simultaneously. Cohen's *d* (−0.25) hid this completely,
because *d* never asks where the training distribution is.

### Feature parsimony is a precision strategy

ECOD/COPOD sum per-dimension tail probabilities, so every weak dimension adds
benign noise and dilutes the strong ones. Fewer, better features wins.

### Other findings

- **`persona` is a perfect label proxy on real eval** — populated for all 207
  benign, NaN for all 49 attacks. Cannot be a feature, cannot route cohort models
  (it would be missing at scoring time for exactly the sessions being hunted).
- **Directional scoring is a free lever.** Only the upper tail is suspicious here
  (long commands, high variety); the lower tail (short, repetitive) is a scripted
  maintenance job — benign. ECOD/COPOD score both tails by default, spending half
  the budget flagging the most routine sessions.
- **`contamination` is a non-issue.** It only sets a binary threshold; precision@k
  is rank-based.

---

## 4. Step 1 — `account` leaks the label (measured)

```
account       attack  benign   attack_rate
bastionsvc         0      53        0.000   ← pure benign
p_admin           22       0        1.000   ← pure attack
p_audit            9      51        0.150
p_dba              9      51        0.150
p_dev              9      52        0.148
base rate = 0.191
```

An artifact of §6: attacks default to `p_admin`, and the benign `admin` persona maps
to `bastionsvc`.

### Decisions

**(a) Global model, no cohort routing.** Beyond the leak: generated training data
has only 28 `p_admin` sessions out of 1000 — too few for a stable cohort fit — and
per-cohort models produce scores on incomparable scales, which a pooled top-k
ranking cannot use.

**(b) The 22 `p_admin` attacks are excluded from the headline metric.** They are
free wins for any model that happens to score `p_admin` high, without any
behavioural detection. Reported separately as a known lab artifact.

Scenario coverage is preserved — the surviving 27 attacks still span all six
scenarios (`recon`, `privesc`, `log_tamper`, `persistence`, `cred_access`,
`exfil`), 4–5 each. The task becomes harder and more honest: attacks carried out
through ordinary role accounts, which is the insider scenario the report defends.

`bastionsvc` benign sessions are kept — benign inflates nothing.

---

## 5. Step 2 — calibration slice

50 real benign sessions, stratified by `account`, seed 42.

```
calibration: 50 sessions {bastionsvc:13, p_dev:13, p_audit:12, p_dba:12}
evaluation:  157 benign + 27 attacks → base rate 14.7%
worst drift: duration_sec_feat +0.18σ  → representative
```

Sanity check (slice vs. remainder, in the remainder's σ): worst drift 0.19σ across
all five features. The split is not biased.

### Targets the generator must hit

| feature | generator (before) | real benign target | gap |
|---|---|---|---|
| `avg_command_length` | 17.94 ± 7.25 | **19.76 ± 6.25** | +0.25σ |
| `unique_command_ratio` | 0.677 ± 0.166 | **0.735 ± 0.142** | +0.35σ |
| `command_count` | 8.46 ± 2.73 | **8.90 ± 2.95** | +0.16σ |
| `command_entropy` | 2.221 ± 0.647 | 2.455 ± 0.682 | +0.36σ |
| `duration_sec_feat` | 7.17 ± 2.38 | 8.30 ± 5.16 | +0.48σ |

### The generator's width is wrong too, in both directions

- `avg_command_length`: **too wide** (7.25 vs 6.25) → normal region too large →
  swallows attacks
- `unique_command_ratio`: slightly too wide (0.166 vs 0.142)
- `duration_sec_feat`: **too narrow** (2.38 vs 5.16, less than half) → every long
  real benign session becomes a false positive

### Projected payoff after recalibration

Real benign moves to ~0σ by construction. Attack positions relative to the
corrected centre (arithmetic projection from the measurements, not directly
measured):

| feature | attack after fix |
|---|---|
| `avg_command_length` | **+1.32σ** |
| `unique_command_ratio` | **+0.95σ** |
| `command_count` | −0.54σ |
| `duration_sec_feat` | −0.34σ |
| `command_entropy` | −0.33σ |

Note `command_entropy` **flips from harmful to mildly useful**: benign returns to 0
and attacks drop to −0.33σ in the lower direction. Recalibration repairs the
feature rather than removing it.

`duration_sec_feat` is recommended for removal even after the fix: weak (−0.34σ)
and its real spread (σ 5.16) is not reproducible by the current per-command uniform
pacing model, so any error there converts directly into false positives.

---

## 6. Step 3 — reading the generator: only two knobs exist

| target | existing knob | status |
|---|---|---|
| `unique_command_ratio` | `--stickiness` (`generate_benign.py:227`) | ✅ direct, clean |
| `command_count` | `sample_length` bootstrap (`:94`) | ✅ close (8.46 vs 8.90) |
| `avg_command_length` | **none** | ❌ |

`avg_command_length` — the strongest single feature — is a property of which strings
sit in `persona_weighted.json` and how they are weighted. No scalar controls it.

Also: `--stickiness` defaults to `0.0` but the existing output has
`unique_ratio` 0.677, so some value was used and **was never recorded anywhere** —
a reproducibility hole, and it means `generated_benign.jsonl` cannot be regenerated
from its inputs.

### Design built

**`metadata/build_calibration_slice.py` → `calibration_slice.json`** — freezes the
calibration/eval boundary, the excluded-account decision, and the moment targets.
Without a committed artifact, every re-run reshuffles the split and the evaluation
set moves silently under the metrics.

**`fit_generator.py` → `metadata/generator_params.json`** — bisection on two knobs:

- **`stickiness`** → `unique_command_ratio` (monotone decreasing)
- **`length_tilt` (β)** → `avg_command_length`, via **exponential tilting** of the
  sampling weights: `w_i × exp(β · z(len_i))`, with `z` the standardised command
  length within that persona's vocabulary. This is the maximum-entropy way to move
  a distribution's mean under a constraint — of all reweightings that hit the
  target, it distorts the original shape least. Defensible in the report.

Fitting is a separate script because the search is stochastic; running it inside
`generate_benign.py` would make generation non-reproducible. It runs once and its
output is committed and read as defaults.

### Deliberately not fitted

- **Standard deviations.** The slice is 50 sessions; an σ estimated from 50 samples
  carries ~10% relative error. Fitting to that precision fits noise. Means are
  fitted, resulting σ are measured and reported as residuals.
- **`command_count`.** Already bootstrapped from real observed lengths and only
  0.16σ off; a third knob would distort the bootstrap shape for no gain.
- **Per-persona targets.** 50 / 4 = 12 sessions each — too thin. Global fit,
  documented limitation.

### The risk that was watched

Tilting toward longer commands changes *which command families* appear, not just
their length — and the family mix is exactly what `build_persona_weights.py`
calibrated from real data. So family-level KL divergence is measured. If large, the
fallback is within-family tilting (preserving family marginals).

---

## 7. Fit results

```
targets: avg_command_length=19.765  unique_command_ratio=0.735
untilted, stickiness=0:  len=18.390  uniq=0.969
round 1: tilt=+0.1189 stickiness=0.2960 → len=19.792 uniq=0.735
round 2: tilt=+0.1183 stickiness=0.2960 → len=19.765 uniq=0.735
round 3: stable
```

**Fitted parameters: `length_tilt = +0.1183`, `stickiness = 0.2960`.** Both fitted
means hit target exactly (±0.000σ).

### Family mix preserved

```
family-mix KL (bits): dev 0.0094 | dba 0.0050 | admin 0.0032 | auditor 0.0072
```

Warning threshold was 0.15 bits — the result is **16× below it**. β = 0.118 is a
gentle tilt. **Within-family tilting is not needed.**

Also confirmed: at `stickiness=0` the ratio rises to **0.969**, so this knob does
control the feature, and the previously-used (unrecorded) value was too high — the
cause of the 0.677.

### Residuals

```
                      fitted    target
avg_command_length     19.765 = 19.765   ✅ mean | std 7.22 vs 6.25   ⚠️
unique_command_ratio    0.735 =  0.735   ✅ mean | std 0.159 vs 0.142 ⚠️
command_count           8.383 vs 8.900   −0.175σ (not fitted, known)
```

**Widths are still ~15% too large.** Quantified impact: the attack sits at +1.32σ
measured in the real σ (6.25), but the model measures in its own σ (7.22) →
**+1.14σ**, a ~14% loss of separation.

Why: generated `command_count` (8.38) is below real (8.90) → shorter sessions →
less averaging → wider spread of the per-session mean. The two residuals are linked.

**Position taken:** do not chase the 15%. The target is estimated from 50 sessions
(~10% relative error in σ alone), so tightening further fits noise. Recorded as a
known residual in the report.

---

## 8. Open items

1. **Next step (pending confirmation):** modify `generate_benign.py` to accept
   `--length-tilt` and read defaults from `generator_params.json`, then regenerate.
   The current `generated_benign.jsonl` is not reproducible (unrecorded stickiness),
   so it should be backed up as `generated_benign.pre_calibration.jsonl` before
   being replaced — which also preserves a before/after comparison for the report.
2. **Domain gate** — `transform.py:181` references `ml/unsupervised/train.py`, which
   does not exist yet (`ml/` holds only an empty `supervised/`). Rule: keep a column
   only if it has variance in *both* train and eval. Auto-drops the 6 IP + 3
   temporal + 6 flag columns.
3. **Transductive-gate question, still open.** The eval-variance stage inspects the
   eval set. It reads only column variance, never labels, so it cannot leak class
   information — but it is technically transductive. Recommendation: accept and
   document, because those 9 columns are degenerate for a *structural* reason known
   a priori (one user, one IP, one collection window). The alternative is computing
   eval variance on a held-out real-benign slice.
4. **`duration_sec_feat` removal** — recommended, provisionally taken, reversible.
5. **Bake-off** — ECOD, COPOD, IForest, HBOS, PCA + MAD z-score baseline + rule-layer
   baseline. Fit on generated benign only; score real eval. An 80/20 generated
   holdout serves as the control that distinguishes a domain gap from a genuine
   anomaly. `StandardScaler` fit on train only — this is the precise mechanism by
   which generated data influences real evaluation, and belongs in the report as a
   stated assumption. Metric: precision@k and recall@k at k ∈ {10, 25, 50}, plus
   average precision. Not ROC-AUC.
6. **Feature-subset comparison** — {`avg_command_length`, `unique_command_ratio`} vs
   +`command_count` vs all five, with directional scoring.
7. **The number that decides the thesis:** precision on the **17 attacks carrying no
   keyword flag**. If ML ranks those above benign, the platform justifies itself
   over the rule layer. If not, five features are not enough and command-vocabulary
   rarity (n-gram / TF-IDF novelty against a per-persona profile) is the next
   addition — behavioural, not a keyword lookup.

---

## 9. Facts worth adding to CLAUDE.md

- All 256 real sessions share one collection minute (`start_hour` σ = 0.062), so
  `off_hours_flag` / `is_weekend` / `start_hour` are non-evaluable on real data.
- `persona` is NaN on all real attack sessions — a perfect label proxy.
- `account` is a partial label proxy: `p_admin` 100% attack, `bastionsvc` 100%
  benign; the other three are clean at ~15%.
- The stickiness value used for the existing `generated_benign.jsonl` was never
  recorded; the file is not reproducible from its inputs.
