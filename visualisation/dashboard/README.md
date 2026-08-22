# visualisation/dashboard/ — PAM anomaly-score front end

A single-page Chart.js dashboard over the FastAPI scoring service (`api/main.py`).
It POSTs a batch of sessions (in `sessions.jsonl` shape) to **`/score`**, then
ranks and visualises the anomaly scores the way a SOC would triage them.

Static, dependency-free (Chart.js from a CDN, no build step). Distinct from the
sibling `plot_unsupervised.py` figures: those are the **print figures for the
report** (matplotlib → PNG/PDF, light-only); this is a **live, themeable web app**
that talks to the running model.

## What it shows

| Panel | Form | Why |
|---|---|---|
| Stat tiles | hero numbers | Model loaded, sessions scored, alert count, threshold — the four questions a SOC asks first. |
| **Ranked anomaly scores** | horizontal bars, sorted desc, with a dashed threshold line | The central view. Bars past the threshold are flagged (status red); the rest are below (sequential blue). Click a bar to inspect its features. |
| Score distribution | histogram | Shows the benign cluster vs. the anomalous tail — the separation is what a good detector produces. |
| Feature profile | horizontal bars | The 10 model features for the selected session (`command_entropy`, `cmd_max_surprisal`, …), largest first. |
| All sessions | table view | The same ranking for screen readers, audit, and copy-paste. |

Colour follows the dataviz skill's validated palette: **status red = alert**
(reserved status colour, always paired with a label + legend + table, never
colour-alone), **sequential blue = below threshold**. Light/dark/auto theme
toggle top-right; the charts recolour from live CSS tokens.

## Run it

The page fetches `sample_sessions.json` and calls the API, so it must be served
over **HTTP** (a `file://` page can't fetch, and its `Origin: null` can't be
allow-listed). Two terminals:

```powershell
# 1) the scoring API  (loads ml/bundles/isolationforest.joblib by default)
cd api
uvicorn main:app --port 8000

# 2) a static server from the REPO ROOT
python -m http.server 5500
```

Then open **http://127.0.0.1:5500/visualisation/dashboard/** and click
**Score sessions**. The connection dot turns green once `/model` responds; the
model metadata line at the bottom names the loaded bundle and its build metrics.

CORS on the API is open by default for this lab convenience (see the note in
`api/main.py`). It does **not** make `/score` safe to expose — the endpoint is
still unauthenticated and must stay bound inside the compose network. Pin the
allow-list with `DASHBOARD_ORIGINS=http://127.0.0.1:5500` if you serve the page
from a fixed origin.

## `sample_sessions.json`

16 **real captured lab sessions** (from `feature_extraction/out/sessions.jsonl`),
stratified across the score range so the demo shows a genuine spread — roughly a
third land above the threshold. To score your own batch, replace this file with
any `{"sessions": [ … ]}` payload in `sessions.jsonl` shape (only `session_id`
and `commands` are strictly required per session).

> Note: sessions carrying no command telemetry (e.g. RDP) are rejected by
> `/score` with a 422 — the model scores commands, and an imputed zero would read
> as "perfectly ordinary". The dashboard surfaces that error rather than hiding it.
