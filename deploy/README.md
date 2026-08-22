# deploy/ — Scenario A: app-only Linux VM → existing Wazuh

Runs the scoring API + collector + Grafana as containers on one Ubuntu VM. Wazuh
and WALLIX stay where they are; this VM only reaches the Wazuh **indexer:9200**.

```
pam-collector ──extract──▶ Wazuh indexer:9200        (external, existing)
      │  sessions.jsonl
      └──POST /grafana/ingest──▶ pam-scoring ──SQLite──▶ /grafana/* reads
                                      ▲                        │
                                      └──── pam-grafana ◀──────┘  (:3000, published)
```

## Prerequisites (on the VM)
- A Docker host — **Ubuntu Server 22.04** or **Alpine** (lightweight, see below),
  **2 vCPU / 4 GB / 20 GB**.
- Docker Engine + compose plugin; user in the `docker` group.
- Network route to `https://<wazuh-host>:9200` — verify: `curl -k https://<wazuh-host>:9200`.
- **The model bundle present locally before build:** `ml/bundles/isolationforest.joblib`
  (gitignored — it's baked into the image, see below).

## Alpine host (lightweight option)

Alpine makes an excellent minimal Docker host (~150 MB, tiny RAM overhead → more
of your 4 GB goes to the containers). **Nothing in `deploy/` changes** — the
compose file, entrypoint, and images run identically.

> **Use Alpine only as the HOST OS — not as the image base.** Alpine uses musl
> libc, and the scientific-Python stack (numpy/scipy/scikit-learn/pandas/lightgbm)
> ships glibc-only manylinux wheels; on a musl base pip compiles them all from
> source (slow, fragile). `api/Dockerfile` is `python:3.12-slim` (Debian/glibc) on
> purpose — **keep it**. A glibc container runs fine on a musl host; Docker
> isolates userspace. musl host + glibc containers is fully supported.

Alpine uses **OpenRC**, not systemd:
```sh
apk add docker docker-cli-compose git
rc-update add docker default      # start Docker on boot
service docker start
addgroup <user> docker            # docker without sudo (re-login to apply)
```
Then follow **First run** below unchanged. Docker's `restart: unless-stopped`
still works — the daemon manages restarts regardless of the host init system.

> Confirm Compose **v2**: `docker compose version`. `deploy/docker-compose.yml`
> uses v2 features (`depends_on: condition: service_healthy`, top-level `name:`).
> If `apk`'s `docker-cli-compose` is too old, install the compose plugin binary
> manually.

## First run (4 commands)
```bash
git clone <repo> && cd hps/deploy
cp .env.example .env            # set WAZUH_INDEXER_* and GF_ADMIN_PASSWORD
# make sure ../ml/bundles/isolationforest.joblib exists (or load a prebuilt image)
docker compose up -d --build
docker compose logs -f pam-collector
```
Open **http://<vm-ip>:3000** — the Infinity plugin, datasource, and dashboard are
all auto-provisioned; panels populate within one `PAM_INTERVAL`.

## The model bundle (the one non-code artifact)
`ml/bundles/*.joblib` is gitignored and **baked into the image** by `api/Dockerfile`.
Two ways to get it onto the VM:
- **Build there:** copy the `.joblib` into `ml/bundles/` before `up --build`.
- **Prebuilt image:** build where the bundle exists, then move the image —
  `docker save pam-scoring:1.0 | gzip > pam.tgz`, copy over, `docker load < pam.tgz`,
  and `docker compose up -d` (no `--build`).
The VM never trains. Retraining = rebuild the image elsewhere, redeploy.

## Verify
```bash
docker compose ps                                             # 3 services healthy
docker compose exec pam-scoring curl -s localhost:8000/health # model_loaded: true
docker compose logs pam-collector | grep ingested             # "ingested N new session(s)"
```
In Grafana: datasource **Infinity** present, dashboard **PAM Anomaly Scores**
populated. Set the time range to match your live data.

## Config (`.env`)
| Var | Meaning |
|---|---|
| `WAZUH_INDEXER_URL/USER/PASS` | where the collector pulls sessions |
| `WAZUH_VERIFY_TLS` | `false` for lab self-signed certs |
| `PAM_INTERVAL` | extract + ingest cadence (s) |
| `EXTRACT_SINCE` | look-back window per cycle (keep > interval) |
| `GF_ADMIN_PASSWORD` | Grafana admin login |
| `GF_PORT` | published Grafana port on the VM |

## Ops
- All services `restart: unless-stopped` → survive reboot.
- **Back up volumes** `pam_scores` (score history) and `pam_grafana` (dashboard edits).
- Empty-window demo fix: `docker compose exec pam-scoring python -m api.seed_demo --api http://localhost:8000 --span 24h`.
- Logs: `docker compose logs -f <service>`.

## Security / caveats
- **Only Grafana is published.** `pam-scoring` is unauthenticated (returns
  privileged session content) and stays on the internal `pam-net`. Do not publish
  it until `auth.py` exists.
- **Wazuh reachability** is the real dependency — same-LAN trivial, cross-network
  is a firewall/route task.
- **Per-command audit timestamps are interpolated** until the collector is wired
  to `events.jsonl` (real per-`KBD_INPUT` times).
- **WALLIX is untouched** — still its own appliance VM forwarding to Wazuh.
