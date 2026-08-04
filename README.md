# PAM-Driven Insider-Threat Detection Platform

Behavioural-anomaly detection for privileged sessions, built on top of a WALLIX
Bastion (PAM) → Wazuh (SIEM/XDR) pipeline. Session telemetry is decoded into
structured events, sessionized, turned into ML-ready features, and scored for
anomalous/insider-threat behaviour — with the explicit goal of showing that the
configured detection **rules are not enough**, and that ML detects behaviour the
rules cannot see.

> *"Détection d'anomalies comportementales sur les sessions à privilèges par
> apprentissage automatique."* — 2-month internship project.

**New here?** Read [`docs/GUIDE_PROJET_FR.md`](docs/GUIDE_PROJET_FR.md) (full
French walkthrough of the structure, personas, and both ML approaches) and
[`docs/GUIDE_VISUEL_FR.pdf`](docs/GUIDE_VISUEL_FR.pdf) (visual guide).

## Core idea: generated trains, real judges

Two data worlds are kept strictly separate — the project's evaluation-integrity
rule:

- **`feature_extraction/`** — the **real** side. `simulate_sessions.py` drives
  genuine labelled sessions through WALLIX; these are collected, sessionized, and
  used to **judge** the models (never to train them).
- **`dataset_generation/`** — the **generated** side. A semi-synthetic dataset
  built from real command content, used to **train** the models.

And two detection questions, answered by two models over one shared feature matrix:

| Track | Question | Trains on | Output |
|---|---|---|---|
| **Unsupervised** (primary) | *is this abnormal?* | benign only | anomaly score → ranked queue |
| **Supervised** (secondary) | *known attack? which type?* | generated 85:15 | attack? + tactic vector |

## Pipeline

```
WALLIX Bastion (PAM)
      │  session events (SSH), forwarded via syslog (rfc5424)
      ▼
Wazuh Manager (custom decoder + rules 100500-100599)
      │  decoded events → archives → indexer (OpenSearch)
      ▼
feature_extraction/extract.py      pull + normalise + sessionize → sessions.jsonl
      ▼
feature_extraction/transform.py    per-session features → features.csv
      ▼
ml/   unsupervised (PyOD) + supervised (RF/LogReg) bake-off, evaluated on real sessions

  ── in parallel ──
dataset_generation/   curate → calibrate → weight → generate synthetic training data
```

## Repo layout

```
.
├── infra/wazuh/
│   ├── wallix_decoder.xml       # source of truth; live deployment bind-mounts its own copy
│   └── wallix_rules.xml         # detection rules, 6 tactics, MITRE-mapped
│
├── feature_extraction/          # REAL side: collection + feature pipeline
│   ├── simulate_sessions.py     #   drives real labelled SSH sessions through WALLIX
│   ├── extract.py               #   Stage 1: pull + normalise + sessionize Wazuh events
│   ├── extract_raw.py           #   raw indexer dump (diagnostic)
│   ├── transform.py             #   Stage 2: per-session feature engineering
│   ├── README_simulate_sessions.md
│   └── out/                     #   real telemetry (events/sessions/features/ground_truth)
│
├── dataset_generation/          # GENERATED side: synthetic dataset building
│   ├── curate_atomic_redteam.py #   attack content <- Atomic Red Team sub-techniques
│   ├── curate_gtfobins.py       #   attack content <- GTFOBins (478 binaries)
│   ├── curate_linux_commands.py #   benign content per persona
│   ├── build_calibration.py     #   real per-persona command frequencies (calibration)
│   ├── build_persona_weights.py #   weighted sampling vocabulary
│   ├── generate_benign.py       #   synthetic benign sessions (same schema as extract.py)
│   ├── commands_dataset/        #   curated pools + weighted vocab (+ gitignored raw caches)
│   └── out/generated_benign.jsonl
│
├── docs/
│   ├── decision_log.md          # durable decisions (data sourcing, ratios, security)
│   ├── GUIDE_PROJET_FR.md        # full French project guide
│   └── GUIDE_VISUEL_FR.pdf       # visual guide
└── requirements.txt
```

## Status

- **WALLIX → Wazuh telemetry pipeline**: working end-to-end for SSH, including
  full-command capture (`wazuh-archives-*` enabled and verified). RDP decoder not
  yet verified against a real line; FTP not set up.
- **`simulate_sessions.py`**: drives real, labelled, self-cleaning sessions — 6
  attack scenarios (recon/cred_access/privesc/persistence/log_tamper/exfil) across
  real vaulted accounts (`p_admin` root + `p_dev`/`p_dba`/`p_audit` non-sudo, with
  denials captured as real `fail_ratio` signal) and 4 benign personas. Logs
  `ground_truth.jsonl`.
- **`extract.py` / `transform.py`**: built and tested. Extract pulls + normalises +
  sessionizes (append+dedup, `indexer`/`fixture` sources). Transform builds
  per-session features (command entropy/count, unique-command ratio, average
  length, risk-keyword flags). Contextual features (off-hours, per-user z-scores,
  IP behaviour) are the next transform extension.
- **Attack corpus**: rebuilt 16 → 256 commands across all 6 tactics, sourced
  independently from Atomic Red Team + GTFOBins (see `docs/decision_log.md`). This
  independent sourcing is what makes the "rules vs ML" comparison credible.
- **Benign generation**: `build_calibration.py` → `build_persona_weights.py` →
  `generate_benign.py` produce synthetic benign sessions calibrated to real
  per-persona command behaviour (family-level weights + a repetition/diversity
  knob). Output shares the real `sessions.jsonl` schema, so `transform.py`
  consumes real and generated sessions identically.
- **Known limitation**: WALLIX forwards only `KBD_INPUT`, not session open/close
  lifecycle events, so `session_start`/`session_end`/`duration_sec` are best-effort
  estimates from per-session min/max timestamps (flagged via `*_is_estimated`).
- **Not yet built**: synthetic metadata layer (users/IP pool/timestamps), attack
  session generator, `templates.jsonl`/`eval_real.jsonl` split, `rule_baseline.py`
  (Pool A/B split), ML bake-off, RAG SOC copilot, FastAPI service.

## Setup

```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

Indexer credentials are read from environment variables (see
`feature_extraction/extract.py` for names/defaults).

## Usage

```bash
# --- REAL side (feature_extraction/) ---
cd feature_extraction
python simulate_sessions.py --attacks all --repeat 2 --benign 10   # collect real sessions
python extract.py --source indexer --since 1h --index archives      # pull full-command telemetry
python transform.py                                                 # per-session features -> features.csv

# --- GENERATED side (dataset_generation/) ---
cd ../dataset_generation
python curate_atomic_redteam.py && python curate_gtfobins.py        # rebuild attack corpus
python build_calibration.py                                         # real stats for calibration
python build_persona_weights.py                                     # weighted vocabulary
python generate_benign.py --per-persona 250 --stickiness 0.35       # synthetic benign sessions
```

## Security notes

- `feature_extraction/out/` contains real session telemetry. Some attack scenarios
  (e.g. privilege-escalation) can echo credentials into keystroke data — never feed
  raw session data unsanitised into a RAG/vector store.
- The Wazuh indexer connection disables TLS verification for the lab's self-signed
  certificate; do not carry that setting into production.
- This is a lab environment on a private network; the repo currently contains lab
  demo credentials in context/config files. Rotate them before any real deployment.
