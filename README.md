# PAM-Driven Insider-Threat Detection Platform

Behavioural-anomaly detection for privileged sessions, built on top of a WALLIX
Bastion (PAM) → Wazuh (SIEM/XDR) pipeline. Session telemetry is decoded into
structured events, sessionized, turned into ML-ready features, and (in later
phases) scored for anomalous/insider-threat behaviour with results surfaced
through a RAG-backed SOC copilot.

> *"Détection d'anomalies comportementales sur les sessions à privilèges par
> apprentissage automatique."* — 2-month internship project.

## Pipeline

```
WALLIX Bastion (PAM)
      │  session events (SSH/RDP), forwarded via syslog (rfc5424)
      ▼
Wazuh Manager (custom decoder + rules)
      │  decoded events → indexer (OpenSearch)
      ▼
feature_extraction/extract.py
      │  pulls from the Wazuh indexer, normalises to schema fields,
      │  sessionizes by session_id → events.jsonl / sessions.jsonl
      ▼
feature_extraction/transform.py
      │  per-session features: command_entropy, command_count,
      │  risk-keyword flags, timing, etc. → features.csv
      ▼
ml/            anomaly scoring (bake-off: PyOD unsupervised + baselines)
visualisation/  dashboard / reporting
```

## Repo layout

```
.
├── feature_extraction/
│   ├── extract.py            # Stage 1: pull + normalise + sessionize Wazuh events
│   ├── transform.py           # Stage 2: per-session feature engineering
│   ├── commands_dataset/      # public command reference lists (cmd/linux/macos/vbscript)
│   ├── out/                   # generated pipeline output (events/sessions/features)
│   └── transform.ipynb        # exploratory notebook
├── ml/                        # anomaly scoring models (in progress)
├── visualisation/              # dashboard / reporting (in progress)
├── requirements.txt
└── claude.md                  # full project context/history for AI-assisted development
```

## Status

- **WALLIX → Wazuh telemetry pipeline**: working end-to-end for SSH; custom
  decoder + rules installed and verified against real alerts (MITRE-mapped).
  RDP telemetry arrives but its decoder is not yet verified against a real
  line.
- **`extract.py`**: built and tested. Pulls WALLIX events from the Wazuh
  indexer, normalises them to the schema-contract fields, and sessionizes by
  `session_id`. Supports `indexer` / `fixture` / `generated` sources so the
  rest of the pipeline can be developed offline. Append+dedup by default.
- **`transform.py`**: builds per-session features (command entropy, command
  count, unique-command ratio, average command length, risk-keyword flags
  for credential access / privesc / persistence / log tampering / recon /
  exfiltration) from `sessions.jsonl`.
- **Known limitation**: WALLIX currently forwards only `KBD_INPUT` events, not
  session open/close lifecycle events, so `session_start` / `session_end` /
  `duration_sec` are derived as a best-effort estimate from the min/max event
  timestamp per session (flagged via `*_is_estimated`) until the WALLIX SIEM
  Integration filter is updated to forward the lifecycle events too.
- **Not yet built**: dataset generation (semi-synthetic training set from real
  templates), ML bake-off / scoring, RAG SOC copilot, FastAPI service.

## Setup

```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

Indexer credentials are read from environment variables (see
`feature_extraction/extract.py` for the exact names and defaults); do not
hardcode credentials into scripts or commit them.

## Usage

```bash
cd feature_extraction

# pull the last hour of WALLIX events from the Wazuh indexer
python extract.py --source indexer --since 1h --index alerts

# explicit time window (prevents future leakage when building baselines)
python extract.py --source indexer --from 2026-07-24T00:00:00Z --to 2026-07-25T00:00:00Z

# offline development against a saved fixture, no live system access needed
python extract.py --source fixture --fixture-file sample_events.jsonl

# build per-session features from the sessionized output
python transform.py
```

`extract.py` writes `out/events.jsonl` (raw normalised events) and
`out/sessions.jsonl` (grouped by session). `transform.py` reads
`out/sessions.jsonl` and writes `out/features.csv`.

## Security notes

- `out/` contains real session telemetry pulled from the lab environment.
  Some generated attack scenarios (e.g. privilege-escalation) can echo
  credentials into keystroke data — review before pushing, and never commit
  raw session data to a public repository or feed it unsanitised into a
  RAG/vector store.
- The Wazuh indexer connection disables TLS verification for the lab's
  self-signed certificate; do not carry that setting into a production
  deployment.
