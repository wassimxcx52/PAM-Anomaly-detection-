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
