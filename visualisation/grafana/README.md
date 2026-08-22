# Grafana PAM Anomaly Dashboard

Migration of the custom FastAPI + Chart.js dashboard to **Grafana**, with
real-time auto-refresh, user/session template variables, click-to-drill-down,
and a raw command audit trail.

## The one architectural rule

**Grafana's auto-refresh never touches the ML model.** Inference runs exactly
once per session, at *ingest*, and the result lands in a SQLite store. Every
Grafana panel polls cheap read-only SQL. That is what lets you set a 5s refresh
across nine panels without melting the scoring service.

```
 extract.py ──▶ sessions.jsonl
                     │
             collector.py  (every N s: new CLOSED sessions only)
                     │  POST /grafana/ingest        ◀── model runs HERE, once each
                     ▼
              FastAPI + SQLite store (api/store.py)
                     │  GET /grafana/{summary,ranked,ratio,distribution,
                     │      features,commands,vars/*}   ◀── Grafana polls THESE
                     ▼
          Grafana  (Infinity datasource, 10s auto-refresh)
```

## Endpoints (all added in `api/`)

| Method | Path | Feeds | Touches model? |
|---|---|---|---|
| POST | `/grafana/ingest` | collector | **yes, once per session** |
| GET | `/grafana/summary` | 4 stat panels | no |
| GET | `/grafana/ratio` | attack-ratio donut | no |
| GET | `/grafana/ranked` | ranked bar chart | no |
| GET | `/grafana/distribution` | score histogram | no |
| GET | `/grafana/features` | feature-profile panel | no |
| GET | `/grafana/commands` | command audit table | no |
| GET | `/grafana/vars/identities` | `$identity` variable | no |
| GET | `/grafana/vars/sessions` | `$session` variable | no |

Every windowed GET accepts `?from=&to=` (epoch ms) — Grafana passes the picker
range as `${__from}/${__to}`, so **Last 15m / 1h / 24h is enforced in SQL**, not
in the browser. `ranked`/`distribution`/`vars/sessions` also accept `identity`.

---

## Setup

### 1. Start the scoring API (with the new Grafana surface)

```powershell
cd api
uvicorn main:app --port 8000          # or: docker compose -f api/docker-compose.yml up -d --build
```
On startup it loads the bundle once and initialises the store
(`api/scores.db`, override with `SCORES_DB_PATH`).

### 2. Feed it — run the collector

```powershell
# continuous (real-time): re-ingests newly closed sessions every 30s
python -m api.collector --api http://127.0.0.1:8000 --interval 30

# or a single pass (for Task Scheduler / cron)
python -m api.collector --api http://127.0.0.1:8000 --once
```
Point `--sessions` at whatever your scheduled `extract.py` refreshes. The
collector only ingests sessions whose `session_end` is set and **not** estimated
(open sessions have wrong features — CLAUDE.md §7), and de-dupes by `session_id`.

> Backfill for a demo: one `--once` pass ingests every closed session already in
> `feature_extraction/out/sessions.jsonl` (~390 real sessions).

### 3. Add the datasource in Grafana

Install the **Infinity** datasource plugin
(`yesoreyeram-infinity-datasource`), then create a datasource whose **base URL**
is your API:

| Grafana location | Base URL |
|---|---|
| same Docker network as the API | `http://pam-scoring:8000` |
| Grafana in Docker, API on host | `http://host.docker.internal:8000` |
| both native on one host | `http://127.0.0.1:8000` |

The dashboard panels use **relative** paths, so the base URL is the only
per-machine setting.

### 4. Import the dashboard

**Manual import (into your existing Grafana on :3000):**
Dashboards → New → Import → upload `pam_dashboard.json` → when prompted for
*Infinity (PAM scoring API)*, pick the datasource from step 3.

**Fully automated (fresh Grafana with everything provisioned):**
```powershell
$env:PAM_API_URL="http://host.docker.internal:8000"
docker compose -f visualisation/grafana/docker-compose.grafana.yml up -d
```
This stands up Grafana on **:3001** with the Infinity plugin, the datasource
(`provisioning/datasources/infinity.yml`), and the dashboard
(`provisioning/dashboards/pam_dashboard.provisioned.json`, datasource uid
already baked in) all loaded. Login `admin` / `admin`.

---

## Using the dashboard

- **Auto-refresh** is preset to **10s**; the picker offers 5s–1h. Time range
  defaults to Last 24h.
- **Top row** — Active model, Sessions scored, Real-time alerts (green→orange→red
  by count), Anomaly threshold.
- **Attack ratio** donut — Attack (≥ threshold) vs Benign, live counts + %.
- **Ranked anomaly scores** — horizontal bars, `identity | session_id` labels,
  **red ≥ threshold / blue below**. The color break *is* the threshold line
  (Grafana bar charts color each bar by its value against the threshold step).
- **Score distribution** — histogram, 0.03 buckets.
- **Drill-down** (scoped to `$session`): **Feature profile** bars +
  **Session command audit log** — every command as typed, interpolated
  execution time, per-command risk flag (colored by MITRE category), and
  per-command surprisal.

### Click-to-drill-down

The `$identity` and `$session` template variables (top of the dashboard) scope
the ranked chart and both drill-down panels. Two ways to drive them:

1. **Dropdowns** — pick a user, then a session.
2. **Click a bar** in *Ranked anomaly scores* — a data link sets
   `var-session` to that bar's `session_id` and the Feature profile + Audit log
   repaint for it instantly.

---

## Wiring live queries without overloading the ML service

- Reads never load the model (design rule above), so **panel count × refresh
  rate is free** — it's SQLite lookups.
- The **collector interval** is the only knob that gates inference. 30s is a good
  default; drop it only if session latency matters. The collector ingests just
  the *delta* (new closed sessions), so cost scales with new sessions, not with
  dashboard viewers.
- SQLite runs in **WAL mode** — Grafana reads never block the collector's writes.
- If throughput ever outgrows SQLite, repoint the ~10 queries in `api/store.py`
  at Postgres/OpenSearch; Grafana is unaffected.

## Honest limitations (document, don't hide)

- **Per-command timestamps are interpolated** evenly across the session window —
  `sessions.jsonl` carries only session start/end. When the collector is wired to
  `events.jsonl` (a real timestamp per `KBD_INPUT`), swap
  `grafana_api._command_rows` for the real times.
- **The bar-chart threshold is a hardcoded field threshold (`0.664`)** matching
  the deployed IsolationForest bundle. If you retrain and the bundle threshold
  changes, update panel 6's threshold step (the live value is always shown in the
  *Anomaly threshold* stat panel).
- **True WebSocket streaming** (Grafana Live) is possible but unnecessary here —
  sessions close on the order of seconds-to-minutes, so 5–10s polling is
  indistinguishable from streaming and far simpler. Noted as future work.
