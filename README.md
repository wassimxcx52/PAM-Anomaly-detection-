# PAM-Driven Insider-Threat Detection Platform

Behavioural-anomaly detection for privileged sessions, built on top of a WALLIX
Bastion (PAM) → Wazuh (SIEM/XDR) pipeline. Session telemetry is decoded into
structured events, sessionized, turned into ML-ready features, scored for
anomalous/insider-threat behaviour, and served over HTTP — with the explicit goal
of showing that the configured detection **rules are not enough**, and that ML
detects behaviour the rules cannot see.

> *"Détection d'anomalies comportementales sur les sessions à privilèges par
> apprentissage automatique."* — 2-month internship project.

**New here?** Read [`docs/GUIDE_PROJET_FR.md`](docs/GUIDE_PROJET_FR.md) (full
French walkthrough of the structure, personas, and both ML approaches) and
[`docs/GUIDE_VISUEL_FR.pdf`](docs/GUIDE_VISUEL_FR.pdf) (visual guide).
[`docs/decision_log.md`](docs/decision_log.md) records *why* the non-obvious
choices were made.

## Core idea: generated trains, real judges

Two data worlds are kept strictly separate — the project's evaluation-integrity
rule:

- **`feature_extraction/`** — the **real** side. `simulate_sessions.py` drives
  genuine labelled sessions through WALLIX; these are collected, sessionized, and
  used to **judge** the models (never to train them). 256 isolated eval sessions.
- **`dataset_generation/`** — the **generated** side. A semi-synthetic dataset
  built from real command content, used to **train** the models. 5 882 sessions
  at the locked 85:15 benign:attack ratio.

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
ml/  unsupervised (IsolationForest/KMeans) + supervised (LightGBM/RF) bake-off,
     evaluated on the isolated real sessions → ml/bundles/*.joblib
      ▼
api/main.py                        POST /score → ranked alert queue

  ── real-time serving loop (deploy/) ──
api/collector.py    every 30s: extract closed sessions → POST /grafana/ingest
      ▼             (model scores once per session, result cached)
api/store.py        SQLite cache (scores + features + per-command audit)
      ▼
api/grafana_api.py  GET /grafana/*  → Grafana dashboard (10s auto-refresh)

  ── in parallel ──
dataset_generation/   curate → calibrate → weight → generate synthetic training data
```

The **real-time loop** (`deploy/`) keeps Grafana's auto-refresh off the model:
inference runs once per session at ingest and is cached in SQLite, so panels poll
cheap SQL. One command brings up the scoring API + collector + Grafana:
`docker compose -f deploy/docker-compose.yml up -d --build`. See
[`deploy/TEAM_GUIDE.md`](deploy/TEAM_GUIDE.md).

## Results

Measured on the 256 isolated **real** sessions, which no model ever trained on.
The deployed Wazuh rules are the bar:

| Track | Model | PR-AUC | Precision | Recall | Rule-misses in top 50 |
|---|---|---|---|---|---|
| supervised | **LightGBM** | 0.973 | 0.74 | 1.00 | 14 / 17 |
| unsupervised | **IsolationForest** | 0.964 | 0.93 | 0.80 | **14 / 17** |
| supervised | RandomForest | 0.921 | 0.74 | 1.00 | 11 / 17 |
| unsupervised | KMeans | 0.893 | 0.85 | 0.80 | 13 / 17 |
| *baseline* | *Wazuh rules (deployed)* | — | *0.94* | *0.65* | — |

**The rules miss 17 of 49 attacks** (recall 0.65 at precision 0.94), measured
from the `rule_id`s that actually fired — not from a reimplementation. Per-tactic
recall is where it bites: privesc **0.25**, exfil / log_tamper / persistence 0.62.

The last column is the one the report defends: of those 17 attacks the rule layer
never saw, how many does each model surface inside a 50-session alert budget.
IsolationForest ranks them highest (median rank 30) despite losing the headline
PR-AUC — and it is the preferred model, because it never trains on an attack and
so cannot be learning that the synthetic attack corpus is merely a different
corpus.

Headline P@10 is 1.00 for all four models and therefore separates none of them;
obvious attacks are easy.

`ml/results_all.csv` holds the full metric set. Figures in
[`visualisation/`](visualisation/).

## Repo layout

```
.
├── infra/
│   ├── wazuh/
│   │   ├── wallix_decoder.xml       # source of truth; live deployment bind-mounts its own copy
│   │   ├── wallix_rules.xml         # detection rules, 6 tactics, MITRE-mapped
│   │   └── docker-compose.wazuh.yml # reference compose for the Wazuh single-node SIEM tier
│   └── wallix/
│       └── 99-wazuh-forward.conf    # WALLIX syslog-ng drop-in (OS-log forward to Wazuh)
│
├── feature_extraction/          # REAL side: collection + feature pipeline
│   ├── simulate_sessions.py     #   drives real labelled SSH sessions through WALLIX
│   ├── extract.py               #   Stage 1: pull + normalise + sessionize Wazuh events
│   ├── extract_raw.py           #   raw indexer dump (diagnostic)
│   ├── transform.py             #   Stage 2: per-session feature engineering
│   ├── command_profile.py       #   corpus-wide command rarity (TF-IDF / frequency)
│   └── out/                     #   real telemetry; *.jsonl tracked, feature CSVs are build output
│
├── dataset_generation/          # GENERATED side: synthetic dataset building
│   ├── curate_atomic_redteam.py #   attack content <- Atomic Red Team sub-techniques
│   ├── curate_gtfobins.py       #   attack content <- GTFOBins (478 binaries)
│   ├── curate_linux_commands.py #   benign content per persona
│   ├── command_safety.py        #   blocks destructive commands from reaching a live host
│   ├── build_calibration.py     #   real per-persona command frequencies (calibration)
│   ├── build_persona_weights.py #   weighted sampling vocabulary
│   ├── fit_generator.py         #   fits generator params to real behaviour
│   ├── generate_benign.py       #   synthetic benign sessions (same schema as extract.py)
│   ├── generate_attacks.py      #   attack sessions, incl. buried-in-benign composition
│   ├── build_training_set.py    #   merges both at the locked 85:15 ratio
│   └── metadata/                #   identity pool, calibration slice, generator params
│
├── ml/
│   ├── evaluation.py            #   SHARED metric code -- both tracks score identically
│   ├── feature_gate.py          #   drops leaky/constant columns before training
│   ├── persistence.py           #   bundle save/load (model + scaler + order + profile)
│   ├── unsupervised/build_eval_set.py  # ground truth x sessions -> eval_real.jsonl
│   ├── unsupervised/train.py    #   IsolationForest, KMeans
│   ├── supervised/train.py      #   LightGBM, RandomForest
│   ├── compare.py               #   cross-track comparison -> results_all.csv
│   └── score.py                 #   CLI inference against a saved bundle
│
├── api/                         # serving layer
│   ├── main.py                  #   FastAPI: POST /score, GET /model, GET /health
│   ├── grafana_api.py           #   GET /grafana/* (dashboard feeds) + POST /grafana/ingest
│   ├── store.py                 #   SQLite cache: scores + features + per-command audit
│   ├── collector.py             #   real-time loop: extract closed sessions → ingest
│   ├── seed_demo.py             #   re-time sessions onto "now" for demos
│   └── Dockerfile               #   ships feature code, not just a pickle
│
├── deploy/                      # one-command real-time stack (Scenario A)
│   ├── docker-compose.yml       #   pam-scoring + pam-collector + pam-grafana
│   ├── .env.example             #   only WALLIX_HOST changes per machine
│   ├── setup-env.{ps1,sh}       #   detect host IP, write .env
│   ├── collector-entrypoint.sh  #   extract (--overwrite) + continuous ingest
│   └── TEAM_GUIDE.md            #   step-by-step deployment guide for colleagues
│
├── visualisation/
│   ├── grafana/                 #   Grafana dashboard JSON + Infinity datasource provisioning
│   ├── dashboard/               #   standalone Chart.js dashboard (no Grafana needed)
│   └── *.png / *.pdf            #   report figures + plotting script
├── docs/                        # guides, decision log, session logs
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
  `ground_truth.jsonl`. 413 real sessions collected; 256 held out as `eval_real`.
- **`extract.py` / `transform.py` / `command_profile.py`**: built and tested.
  Transform builds per-session features (command entropy/count, unique-command
  ratio, average length, risk-keyword flags) plus corpus-wide command rarity.
- **Attack corpus**: rebuilt 16 → 256 commands across all 6 tactics, sourced
  independently from Atomic Red Team + GTFOBins (see `docs/decision_log.md`). This
  independent sourcing is what makes the "rules vs ML" comparison credible.
- **Dataset generation**: complete. Calibration → weights → benign + attack
  generation → `build_training_set.py` merges at 85:15. Output shares the real
  `sessions.jsonl` schema, so `transform.py` consumes real and generated sessions
  identically.
- **ML bake-off**: complete, 4 models across both tracks, scored by the shared
  `ml/evaluation.py` so no model is measured by its own code. See Results above.
- **Scoring service**: `api/` serves the saved bundle over HTTP. It imports
  `transform.py` rather than reimplementing features, so serving cannot drift from
  training.
- **Real-time serving loop** (`deploy/`): built and verified end-to-end. A
  collector extracts newly-closed sessions every 30s and POSTs them once to the
  scoring service, which caches scores/features/per-command audit in SQLite; a
  Grafana dashboard (auto-provisioned Infinity datasource) reads that cache on a
  10s refresh. A live session appears automatically within ~1 min of closing. A
  standalone Chart.js dashboard (`visualisation/dashboard/`) offers the same views
  without Grafana.
- **Session lifecycle decoding** (was a known limitation, now fixed): WALLIX does
  forward `SESSION_DISCONNECTION`, but the decoder wasn't parsing it (a sibling
  child-decoder blocked fallthrough) — fixed with per-child `<prematch>`. Combined
  with a graceful session close in `simulate_sessions.py`, `session_end`/`duration`
  are now real (not estimated) for cleanly-closed sessions. RDP not verified; FTP
  not set up.
- **Rules-vs-ML baseline**: complete. The deployed rules are scored from their
  own `rule_id`s and appear as a row in `results_all.csv`; each model reports how
  many of the rules' 17 misses it surfaces inside the alert budget.
- **Known limitation — `fail_ratio`**: `simulate_sessions.py` captures denied
  commands, but real benign sessions have a 0% denial rate (0 of 260), so a
  generated benign column would be constant and `reference_class_gate()` drops it
  as a separator by construction. It stays an evaluation dimension rather than a
  model feature; making it one would require inventing a benign denial rate that
  no data supports.
- **Not yet built**: RAG SOC copilot (Qdrant + `/ask`), `auth.py` (RBAC for the
  API), and the remaining contextual features (per-user z-scores, 24h rolling
  aggregates, `role_command_mismatch`).

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
python generate_attacks.py                                          # attack sessions
python build_training_set.py                                        # merge at 85:15

# --- TRAIN + EVALUATE (ml/) ---
cd ..
python ml/unsupervised/build_eval_set.py --composed-only              # real -> eval_real.jsonl
python ml/unsupervised/train.py                                     # IsolationForest, KMeans
python ml/supervised/train.py                                       # LightGBM, RandomForest
python ml/compare.py                                                # -> ml/results_all.csv

# --- SCORE ---
python ml/score.py --sessions feature_extraction/out/eval_real.jsonl \
                   --bundle ml/bundles/isolationforest.joblib --top 10

# --- SERVE (real-time stack: scoring API + collector + Grafana) ---
cd deploy
cp .env.example .env        # set WALLIX_HOST; helper: ./setup-env.ps1 (or .sh)
docker compose -f docker-compose.yml up -d --build                  # Grafana on :3000
# open http://localhost:3000  (dashboard "PAM Anomaly Scores", set range Last 24h)
```

Model bundles are committed under `ml/bundles/`, so the API image builds without a
local training run. The Wazuh SIEM tier is a separate stack — see
[`infra/wazuh/docker-compose.wazuh.yml`](infra/wazuh/docker-compose.wazuh.yml) and
[`deploy/TEAM_GUIDE.md`](deploy/TEAM_GUIDE.md).

## Security notes

- `feature_extraction/out/` contains real session telemetry. Some attack scenarios
  (e.g. privilege-escalation) can echo credentials into keystroke data — never feed
  raw session data unsanitised into a RAG/vector store.
- **`/score` and `/grafana/*` have no authentication.** `auth.py` is Security-owned
  and unbuilt, and the endpoints return privileged session content. The `deploy/`
  stack keeps `pam-scoring` on an internal network with **no published port** (only
  Grafana is exposed, with its own login); do not publish the scoring API until
  RBAC exists.
- The Wazuh indexer connection disables TLS verification for the lab's self-signed
  certificate; do not carry that setting into production.
- This is a lab environment on a private network; the repo currently contains lab
  demo credentials in context/config files. Rotate them before any real deployment.
