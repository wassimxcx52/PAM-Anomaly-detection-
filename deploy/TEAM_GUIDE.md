# PAM Anomaly Detection — Team Deployment Guide

Get the whole stack running on your machine: **WALLIX Bastion VM** + **Wazuh** +
**Scoring API** + **Collector** + **Grafana dashboard**.

---

## What runs where

| Component | Runs as | Port (host) |
|---|---|---|
| WALLIX Bastion | VMware/VirtualBox VM (from Google Drive) | — |
| Wazuh (manager/indexer/dashboard) | Docker (separate compose) | 9200, 1514, 443 |
| Scoring API (FastAPI) | Docker `pam-scoring` | internal only |
| Collector (extract → score) | Docker `pam-collector` | — |
| Grafana dashboard | Docker `pam-grafana` | 3000 |

> No Logstash. The pipeline is `extract.py` (collector) → Wazuh Filebeat → SQLite → Grafana.

---

## Prerequisites

- **RAM:** 12 GB+ (Wazuh indexer wants ~4 GB; WALLIX VM ~4 GB).
- **VMware Workstation/Player** or **VirtualBox** (for the WALLIX VM).
- **Docker Desktop** (Win/Mac) or **Docker Engine + compose plugin** (Linux).
- **git**, and the two repos: this one (`hps`) + the Wazuh one (`wazuh-docker`).

---

## The IP strategy (read once)

Only **two** addresses ever change per machine. Everything else uses
`host.docker.internal` — no IP chasing.

| # | What | Where you set it |
|---|---|---|
| 1 | **WALLIX VM IP** | `deploy/.env` → `WALLIX_HOST` (helper script does this) |
| 2 | **Your host LAN IP** | inside the **WALLIX GUI** (SIEM Integration target) — helper script prints it |

App→indexer and Grafana→API resolve automatically. You never edit container IPs.

---

## Step 1 — WALLIX VM

1. Download the VM export from the Google Drive folder.
2. **Import** into VMware/VirtualBox (File → Open/Import).
3. **Network adapter → Bridged** (not NAT) — it must get a LAN IP on your network.
   - *VMware:* set Bridged to your real Ethernet/Wi-Fi adapter (not "Automatic").
4. Boot it, log in at the console, find its IP:
   ```
   ip a        # note the 192.168.x.x address
   ```
5. Confirm your host can reach it:
   ```
   ping <wallix-vm-ip>
   ```

---

## Step 2 — Environment config

```bash
cd hps/deploy
# Windows:
./setup-env.ps1
# Linux/macOS:
./setup-env.sh
```
The script:
- prints **your host LAN IP** → paste it into the WALLIX GUI (SIEM Integration destination + syslog server),
- asks for the **WALLIX VM IP** → writes it to `.env`.

Then edit `deploy/.env` if you want to change `GF_ADMIN_PASSWORD` / `GF_PORT`.

> The model bundle ships in the repo (`ml/bundles/isolationforest.joblib`) — nothing to download.

---

## Step 3 — Bring it up

**a) Wazuh stack** (once):
```bash
cd wazuh-docker/single-node
docker compose up -d
# first boot only, if the indexer needs certs:
# docker compose -f generate-indexer-certs.yml run --rm generator
```

**b) PAM stack:**
```bash
cd hps/deploy
docker compose -f docker-compose.yml up -d --build
```

**c) Watch it work:**
```bash
docker compose -f docker-compose.yml logs -f pam-collector   # "ingested N new session(s)"
```

---

## Step 4 — Verify & access

| Service | URL | Login |
|---|---|---|
| **Grafana** | http://localhost:3000 (or your `GF_PORT`) | admin / your `GF_ADMIN_PASSWORD` |
| **Wazuh dashboard** | https://localhost:443 | admin / (Wazuh compose creds) |
| **Scoring API** (internal) | via container only | — |

**Health checks:**
```bash
# all three PAM containers healthy/up
docker compose -f docker-compose.yml ps

# scoring API alive + model loaded (from inside the network)
docker compose -f docker-compose.yml exec pam-scoring \
  python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read())"

# Wazuh indexer reachable
curl -k https://localhost:9200 -u admin:SecretPassword
```

**In Grafana:** open dashboard **PAM Anomaly Scores** → set time range **Last 24 hours** → panels populate.

---

## Generate live sessions (smoke test)

```bash
cd hps/feature_extraction
WALLIX_HOST=<wallix-vm-ip> python simulate_sessions.py --attacks recon --benign 3
```
Within ~1 min the new sessions appear in Grafana (Last 1h). Count rises on its own.

---

## Troubleshooting (fast)

| Symptom | Fix |
|---|---|
| Grafana port clash | set `GF_PORT=3001` in `.env`, `up -d` again |
| Panels empty | time range too short → set **Last 24h** (data is time-filtered, not lost) |
| Collector: "indexer unreachable" | Wazuh stack not up, or `WAZUH_INDEXER_PASS` wrong in `.env` |
| WALLIX session fails / "No route to host" | VM adapter not **Bridged** to the real NIC (avoid VMware "Automatic") |
| Infinity plugin 404 in Grafana | using old Grafana image → this compose pins `grafana:12.0.0` |
| Env change not taking effect | env is frozen at container create → `docker compose up -d --force-recreate <svc>` |

---

## Linux host note
`host.docker.internal` is wired via `extra_hosts` in the compose file, so it works
on Docker Engine too — no change needed.
