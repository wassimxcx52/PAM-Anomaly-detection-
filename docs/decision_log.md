# Decision Log

Standing decisions for the PAM-driven insider-threat detection platform. See
`claude.md` for full working context; this file is the durable subset worth
keeping independent of that rolling context doc.

## Data sourcing

- **ML pipeline sources from Wazuh ARCHIVES (`wazuh-archives-*`), not alerts.**
  Alerts only contain rule-triggering events → structural recall ceiling → the
  model would only re-learn what the rules already catch. Archives contain
  every command, required for `command_entropy`/`command_count`/
  `unique_command_ratio`. (2026-07-xx, confirmed working 2026-08-03 — see
  claude.md §3 item 9 for the Filebeat `archives` module gotcha that delayed
  this.)
- **`rule_id`/`rule_level` are EVALUATION metadata, not model input features.**
  Feeding rule output into the model when sourcing from alerts would be
  circular. Keep them for ML-vs-rules comparison only.

## Dataset generation

- **Generated data TRAINS; real injected sessions JUDGE; never mix.**
  Evaluation-integrity rule. A small, 100%-real, isolated `eval_real.jsonl`
  set is never used for training the generator or the model — it exists only
  to score the final result.
- **Benign:attack ratio locked at 85:15** (2026-08-03, tightened from the
  original 70-80%:20-30% range). More representative of real SOC conditions;
  consistent with the ML methodology's SMOTE-for-imbalance and
  precision@k-not-accuracy stance (see claude.md §11).
- **Public command datasets (HuggingFace, Atomic Red Team, GTFOBins, etc.) are
  CONTENT sources, never primary training data.** Commands from these sources
  must still be run THROUGH the real WALLIX Bastion in a real session — WALLIX
  stays the source of truth, identity resolution stays the thesis. Training
  directly on an external dataset, bypassing WALLIX, would kill the thesis.
  (Applied 2026-08-03: `curate_linux_commands.py` for benign content,
  `curate_atomic_redteam.py` for attack content — both filtered for
  self-cleaning/non-destructive/no-TTY-hang before being wired into
  `simulate_sessions.py`.)
- **Attack corpus rebuilt from two sources** (2026-08-04, supersedes the earlier
  "ART yielded zero for privesc/cred_access/exfil" note). ART's parent-technique
  files were Linux-thin; the fix was to fetch the relevant Linux SUB-techniques
  (`curate_atomic_redteam.py`, 12→25 YAMLs) and add GTFOBins as a second,
  command-shaped source (`curate_gtfobins.py`, 478 binaries). Two ART safety
  filters were deliberately relaxed with justification: exfil external-host →
  `127.0.0.1` rewrite (matches the existing exfil scenario convention), and
  bash-history writes treated as safe-without-cleanup (session-ephemeral).
  Result: `attack_commands_curated.json` 16 → 256 commands, all 6 tactics
  populated (cred_access 186, exfil 31, persistence 15, privesc 10, log_tamper 8,
  recon 6). Four tactics remain thin — deferred; intended to become the Pool B
  (rule-blind) seed alongside hand-authored evasion variants.
- **GTFOBins cred_access entries read `/etc/passwd` (world-readable), not
  `/etc/shadow`** — the snippets embed that path literally. Safer (no root
  needed) and still matches rule 100510's regex. Some entries reference tools not
  installed on debian-lab (restic/smbclient/rlogin) — fine as vocabulary content,
  will fail-fast if actually executed.

## Feature pipeline & ML data (2026-08-04)

- **One unified feature matrix; each ML track is a filter over it, not a separate
  pipeline.** transform.py computes every feature once, label-agnostic. Metadata
  columns (`label`, `tactics`, `source`, `split`, `persona`) ride alongside.
  Unsupervised (thesis) = `source=generated & label=benign & split=train`, with
  the `flag_*` keyword columns DROPPED (behavioural-only "Config A", avoids the
  circularity of a model that re-learns the rules). Supervised = `split=train`,
  keep all columns, `y=label`/`tactics` ("Config B" additionally keeps `flag_*`).
  Consequence: the benign vocabulary/weights/generator built for the unsupervised
  track ARE the 85% benign majority class of the supervised set — built once.
- **Benign command diversity is calibrated to plausible human behaviour
  (stickiness ≈ 0.35 → unique_command_ratio ≈ 0.6), NOT to the real templates.**
  The 34 real benign template sessions have `unique_command_ratio ≈ 1.00` (every
  command distinct) — an artifact of simulate_sessions.py's fixed-list-of-distinct-
  commands design (§6), not real usage. Calibrating the generator to match 1.00
  would teach the unsupervised model that "benign = all commands unique", so a real
  user (or attacker) repeating a command would score anomalous for the wrong
  reason. `build_persona_weights.py` (family-level `--tail-mass`, real-anchored
  head) + `generate_benign.py` (`--stickiness`) instead target realistic
  repetition. FOLLOW-UP: benign templates should be re-collected with varied,
  repetitive sequences before diversity can be calibrated empirically rather than
  by this documented judgement call.

## Security / RAG

- **Sessions run under `p_admin` (root) or containing real privileged
  operations must NEVER be fed raw into the RAG vector DB.** This is exactly
  what the sanitised-summary guardrail (`load.py`, not yet built) is for —
  dual-write a sanitised natural-language summary per session, never raw
  commands, gated by a `rag_indexable` schema flag.

## Honest lab constraints (documented, not engineered around)

- Two target hosts only → no real lateral movement; don't synthesise fake
  lateral movement.
- Effectively one real source IP → source-IP diversity
  (`distinct_source_ips_24h`, `new_source_ip_for_user`, etc.) must come from
  the synthetic metadata layer (Phase 2), not from real captured sessions.
- Only 5 real vaulted accounts stand in for personas → per-user baselines are
  really per-persona baselines. Genuine external-validity limitation for the
  report, not something more data collection fixes.

## Metadata layer / diversity strategy (2026-08-05)

Artifact: `dataset_generation/metadata/build_identity_pool.py` →
`identity_pool.json` (seeded, versioned, reviewable).

- **Governing rule: every synthetic attribute is anchored to an identity's own
  history; an anomaly is a deviation from THAT identity's baseline, never a
  globally-unseen value.** If any single metadata axis (IP, target, hour,
  account) separates the classes on its own, the model memorises metadata and
  never learns behaviour.
- **Synthetic population: 16 users over 4 personas, uneven (dev×6, dba×3,
  admin×3, auditor×4).** With one real login user (`test-ssh`), every per-user
  feature in the plan (`duration_zscore`, `session_hour_zscore`,
  `new_source_ip_for_user`) is degenerate and peer-group baselines have no
  peers. Uneven headcount mirrors real orgs and stresses cold-start.
- **IP scheme: proposed RFC1918 layout, not the real pool** (per-team
  `10.20.X.0/24`, VPN `10.99.0.0/16`, jump `10.30.0.0/24`). Swappable for a real
  pool later without touching generator logic.
- **~70% of ATTACK sessions originate from the actor's OWN home IP; ~10% of
  BENIGN sessions roam (VPN/jump).** Real insiders work from their own laptop.
  Without this symmetry `client_ip` alone solves the task and the command
  features are never learned. Same reasoning as the existing "both targets must
  see both benign and attack" constraint.
- **Strongest IP anomaly is the WRONG-TEAM SUBNET**, i.e. a known-good
  workstation address attached to the wrong identity — not an unseen address.
  Requires team-scoped subnets, which is why IPs are not randomly assigned.
- **Target inventory: ~20 synthetic hosts with group + criticality tier +
  protocol.** Protocol is a property of the HOST (Linux→SSH, Windows→RDP), so
  protocol diversity falls out of target affinity instead of being drawn
  independently. `criticality` is EVALUATION metadata for the risk = anomaly ×
  impact argument, NOT a model input feature.
- **Admins carry an on-call rotation:** a 03:00 admin session is normal for the
  admin on call that week, anomalous for anyone else. This is what makes
  `session_hour_zscore` earn its place over a flat `off_hours_flag`.
- **Generator must emit per-user TIMELINES, not independent sessions.**
  `generate_benign.py` currently draws each timestamp independently, which makes
  every 24h-window feature (`sessions_count_24h`, `distinct_targets_24h`,
  `distinct_source_ips_24h`, `concurrent_sessions`) meaningless. Attacks are
  INSERTED INTO an existing user timeline, not sampled separately. Biggest
  remaining change to the generator; lands before the attack generator.
- **Leakage audit is a required validation step:** after generation, train a
  classifier on metadata-only features (no command features). If it separates
  the classes well, the metadata is a giveaway and must be rebalanced. Report
  metadata-only vs metadata+behaviour performance — pre-empts the obvious
  thesis-defence objection that semi-synthetic labels are self-fulfilling.

---

## 2026-08-07 — Unsupervised track v1: first end-to-end result

### Two collection artifacts were found by MEASUREMENT, not inspection

Running the first bake-off surfaced two defects in how `simulate_sessions.py`
composed sessions. Both were properties of the driver, not of the lab:

1. **`unique_command_ratio` == 1.00 in every real session.** A session was a fixed
   list of distinct commands run once; real users repeat themselves. The domain
   gate rejected `unique_command_ratio` (KS 0.94) and `command_entropy` (KS 0.69):
   a model trained on generated benign would have flagged every real session for
   *being real*.
2. **An attack session was 100% attack commands**, so `avg_command_length` alone
   scored AUC 0.832 — the detector was reading "long command", not behaviour.
   `recon` (avg 14.3 chars) was indistinguishable from benign and went undetected.

**Decision: fix the COLLECTOR, never calibrate the generator to match a scripting
artifact.** `simulate_sessions.py` now composes sessions: benign gets variable
length + repetition (`--stickiness`); attacks get one of `full` / `diluted`
(scenario intact, benign filler interleaved, so create-then-delete pairs still
clean up) / `minimal` (1-2 read-only attack commands buried in benign activity,
`--bury-rate`).

Effect on real telemetry: the benign/attack gap in `avg_command_length` fell from
25.5 chars to 1.9, `unique_command_ratio` from 1.00 to ~0.77, and **all 5 candidate
features now pass the domain gate** (previously 3 of 5).

### The domain gate is a required step, and it has a blind spot

Every candidate feature is gated by a two-sample KS between GENERATED benign and
REAL benign. A feature whose benign distribution differs across domains is a
domain marker: the detector would flag sessions for being real, and precision@k
would measure the seam between datasets. Measured, never hand-picked.

**Blind spot, documented deliberately:** the gate compares benign to benign only,
so it cannot see contamination of the ATTACK class. This bit once — after fixing
the benign side, 45 of 58 eval attacks were still pre-fix and the reported numbers
were computed on a 78%-artifact attack class. Hence `build_eval_set.py
--composed-only`, which keeps only post-fix sessions.

**Leakage caveat for the report:** the gate reads the eval set's benign labels.
Accepted because the alternative (shipping known domain markers) is worse and the
gate is blind to the attack class it scores on. With more real benign, hold out a
calibration slice instead.

### Result on a clean eval set (256 real sessions, 49 attacks, base rate 19.1%)

| model | ROC-AUC | P@25 | P@50 | R@50 |
|---|---|---|---|---|
| PCA | 0.778 | **0.72** | **0.60** | 0.61 |
| MAD (baseline) | **0.798** | 0.68 | 0.48 | 0.49 |
| IForest | 0.775 | 0.60 | 0.52 | 0.53 |
| ECOD | 0.755 | 0.56 | 0.54 | 0.55 |
| HBOS | 0.749 | 0.44 | 0.48 | 0.49 |
| COPOD | 0.719 | 0.36 | 0.42 | 0.43 |

Random ranker = 0.191 at every k, so PCA@25 is a 3.8x lift.

- **MAD wins ROC-AUC but loses precision@k.** The two metrics disagree, and the
  one the SOC actually feels is precision@k. Concrete support for the standing
  decision to report precision@k, not ROC-AUC.
- **Before the collection fix, HBOS led at 0.862.** That advantage was the
  artifact, not learning. Worth stating plainly in the report.

### Recall by attack composition — the honest limit

PCA @k=50: `full` 0.92 · `diluted` 0.67 · `minimal` **0.27**

`minimal` sessions average 19.3 chars vs 19.1 for benign — indistinguishable on
every command-shape feature available. **The detector catches the loud case and
misses the realistic one.** This is the gap that motivates the contextual features
(`session_hour_zscore`, `new_source_ip_for_user`, `distinct_targets_24h`), which
the lab cannot yet supply for REAL sessions: one login user, one client IP, one
target. Report this as a measured limit, not a tuning failure.

### Safety: the benign corpus contained destructive commands

A collected session executed `mv /usr/local/bin/* /opt/bin/` as root on
debian-lab. No damage — only because `/usr/local/bin` was empty. Root cause:
`curate_linux_commands.py` filtered the public corpus against `wallix_rules.xml`
but never against destructiveness, and the `_COMMANDS_DIR` path had been stale
since the restructure (silently loading nothing), so the corpus had never been
exercised until the path was fixed.

**Decision: `dataset_generation/command_safety.py` is the single definition,**
imported by the collector (SAFETY — it executes as root) and by
`build_persona_weights.py` (PARITY — a command the collector cannot emit must not
be in the generated vocabulary, or the gap becomes a domain marker). Blocks state
mutation and non-terminating commands (`free -s 1`, `tail -f`, `ping` without
`-c`), which would otherwise hang a session and silently truncate collection.
1669 of ~3200 commands rejected.

## 2026-08-15 — Command rarity, and two leaks that looked like success

Full working notes: `session_2026-08-15_command_rarity.md`. The durable
decisions:

### The decoder was truncating commands at the first escaped quote

`data="([^"]*)"` stopped at the `\"` WALLIX uses to escape a quote inside a
command. 244 of 7506 KBD_INPUT events cut — 3.3% of events but **21% of the
distinct vocabulary**, because quoted `awk`/`find`/`echo` one-liners are the long
distinctive ones. A persistence attack reached the rules as
`(crontab -l 2>/dev/null; echo \` with its payload gone.

**Decision: identity fields keep the cheap `[^"]*`; free-text fields (`data`,
`command_line`) use escape-aware `((?:[^"\]|\.)*)`.** The decoder stays
lossless (escapes preserved); `extract.py` unescapes.

**Decision: `extract.py` repairs from `full_log` rather than requiring
re-collection.** `full_log` preserved the complete line, so all 244 were
recovered offline — real sessions cannot be re-collected, so any future decoder
fix must come with a repair path, not just a forward fix.

Everything measured before this date used corrupted commands. 129 of the 256
eval sessions were affected; `session_2026-08-09`'s figures are superseded.

### Rarity features: the profile is global, and fitted out-of-fold

- **Global, not per-persona.** `persona` is NaN on all 49 real attack sessions,
  so a per-persona profile cannot be selected at scoring time for exactly the
  sessions being hunted. Per-user degenerates identically (one real login user).
  Revisit when AD lands.
- **Cross-fitted.** Fitting the profile on the rows it scores makes
  `cmd_oov_rate` identically 0 for training benign — a perfect label that drove
  CV PR-AUC to 1.0000 and tied 64 eval sessions at score 1.0. Any statistic
  derived from the target population is cross-fitted.

### A feature that does not vary within the reference class is not a feature

`ml/feature_gate.py:reference_class_gate`. The whole-column domain gate cannot
catch this: such a column varies across the training set (attacks differ) and
varies in eval — only the within-benign view exposes that the separator was
handed to the model rather than learned. Needs a float tolerance (`1e-9`); the
novelty columns are `1.55e-16`, not `0.0`.

### The generated benign vocabulary must be OPEN

A closed vocabulary (850 types × 42 000 draws) makes novelty structurally
impossible for benign and so makes it a perfect attack marker. Cross-fitting
does **not** fix this — holding out sessions still leaves every command type.

**Decision: novelty is generated as varied ARGUMENTS, not novel programs**
(`generate_benign.vary_arguments`) — which is how real novelty arises, and keeps
`command_safety`'s guarantees intact since no new head or redirection is
introduced. Fitted as a third knob (`arg_variation`) against the real benign OOV
rate, alongside `stickiness` and `length_tilt`.

**Trap recorded: the OOV target is sample-size dependent** — the same knob gives
4.9% OOV at 150 sessions/persona and 0% at 1250. `--oov-samples` must match
`--per-persona`. Likewise, real-vs-real OOV (22.5%) is not the target;
real-vs-deployed-profile (1.4%) is, because both classes must be scored against
the same profile.

### Result: the thesis question is answered affirmatively

The 16 real attacks carrying no keyword flag — structurally invisible to
`wallix_rules.xml` — went from ROC-AUC 0.502 (random) to **0.963**, all ranked
inside the top 64 of 256. Real PR-AUC 0.417 → **0.921**, precision@10 **1.00**,
domain gap 0.288 → **0.079**. Rarity features hold the top five permutation
importances; every shape feature is ≤ 0.008.

**Known limitation, not engineered away:** training is still perfectly separable
because the attack corpus is disjoint from the benign corpus, so 0 of 882
generated attacks have `cmd_oov_rate == 0`. The generator cannot yet produce a
living-off-the-land attack built entirely from ordinary commands — the hardest
real insider case. Next realism gap.
