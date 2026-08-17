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

  ── in parallel ──
dataset_generation/   curate → calibrate → weight → generate synthetic training data
```

## Results

Measured on the 256 isolated **real** sessions, which no model ever trained on:

| Track | Model | PR-AUC | P@10 | P@25 | Buried-attack P@25 |
|---|---|---|---|---|---|
| supervised | **LightGBM** | 0.973 | 1.00 | 1.00 | 0.64 |
| unsupervised | **IsolationForest** | 0.964 | 1.00 | 1.00 | 0.56 |
| supervised | RandomForest | 0.921 | 1.00 | 0.92 | 0.44 |
| unsupervised | KMeans | 0.893 | 1.00 | 0.96 | 0.52 |

The last column is the honest one. Headline P@10 is 1.00 for every model —
obvious attacks are easy, and that number flatters all four equally. The
*buried-attack* column scores only sessions where 1–2 malicious commands hide
inside otherwise-benign activity, with the risk-keyword flags gated off so the
model cannot simply re-read the rules. That is the number the report defends.

`ml/results_all.csv` holds the full metric set. Figures in
[`visualisation/`](visualisation/).

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
│   ├── unsupervised/train.py    #   IsolationForest, KMeans
│   ├── supervised/train.py      #   LightGBM, RandomForest
│   ├── compare.py               #   cross-track comparison -> results_all.csv
│   └── score.py                 #   CLI inference against a saved bundle
│
├── api/                         # serving layer
│   ├── main.py                  #   FastAPI: POST /score, GET /model, GET /health
│   ├── Dockerfile               #   ships feature code, not just a pickle
│   └── docker-compose.yml       #   joins the Wazuh stack's network
│
├── visualisation/               # report figures (PNG + PDF) + plotting script
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
- **Known limitation**: WALLIX forwards only `KBD_INPUT`, not session open/close
  lifecycle events, so `session_start`/`session_end`/`duration_sec` are best-effort
  estimates from per-session min/max timestamps (flagged via `*_is_estimated`).
- **Not yet built**: `rule_baseline.py` (the rules-vs-ML precision/recall
  comparison), RAG SOC copilot (Qdrant + `/ask`), `auth.py` (RBAC for the API),
  dashboard.

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
python ml/unsupervised/train.py                                     # IsolationForest, KMeans
python ml/supervised/train.py                                       # LightGBM, RandomForest
python ml/compare.py                                                # -> ml/results_all.csv

# --- SCORE ---
python ml/score.py --sessions feature_extraction/out/eval_real.jsonl \
                   --bundle ml/bundles/isolationforest.joblib --top 10

# --- SERVE ---
docker compose -f api/docker-compose.yml up -d --build              # 127.0.0.1:8000
```

Note that `ml/bundles/` is gitignored — model weights are build output, so the
API image can only be built after a local training run.

## Security notes

- `feature_extraction/out/` contains real session telemetry. Some attack scenarios
  (e.g. privilege-escalation) can echo credentials into keystroke data — never feed
  raw session data unsanitised into a RAG/vector store.
- **`/score` has no authentication.** `auth.py` is Security-owned and unbuilt, and
  the endpoint returns privileged session content. Compose publishes to
  `127.0.0.1` only; do not expose it publicly until RBAC exists.
- The Wazuh indexer connection disables TLS verification for the lab's self-signed
  certificate; do not carry that setting into production.
- This is a lab environment on a private network; the repo currently contains lab
  demo credentials in context/config files. Rotate them before any real deployment.
