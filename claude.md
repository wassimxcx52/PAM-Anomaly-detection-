# Project Context — PAM-Driven Insider-Threat Detection Platform

Paste this whole file into a new chat to continue with full context.

---

## Role

Expert Cybersecurity Engineer + MLOps specialist helping build an insider-threat /
behavioural-anomaly detection platform for a 2-month internship. Be concise and
direct; step-by-step for hands-on WALLIX/Wazuh tasks. User works across English,
French, and Arabic (Darija) — match whichever they use.

## Project in one line

**WALLIX Bastion (PAM) → Wazuh (SIEM/XDR) → feature pipeline → ML anomaly scoring
→ RAG SOC copilot → FastAPI (`/score`, `/ask`) → dashboard.**

Report title: *"Détection d'anomalies comportementales sur les sessions à privilèges
par apprentissage automatique."*

Team: this person (technical lead) + 1 security engineer (2 months) + 1 data/AI
engineer (2 weeks only — owns feature engineering + ML bake-off, then hands off).

---

## 1. Environment (Lab A — the only one in use)

| Component | Address | Notes |
|---|---|---|
| Windows physical host | `192.168.1.32` | Docker Desktop, runs Wazuh stack |
| WALLIX Bastion | `192.168.1.50` | VMware VM, **bridged**, hostname `wab-12-0-5`, v12.0.86 |
| debian-lab (SSH target) | `192.168.1.74` | vaulted account `svc-debian`, is root |
| win10-lab (RDP target) | `192.168.1.75` | |

Wazuh 4.14.5 single-node Docker stack (`wazuh.manager`, `wazuh.indexer`,
`wazuh.dashboard`). Project dir: `C:\Users\niro\Desktop\...\wazuh-docker\single-node`.
Feature pipeline dir: `C:\Users\niro\Desktop\hps\feature_extraction`.

Bastion login user: `test-ssh` (password `P@ssw@rd123`), group `testssh-group`.
Target root password: `lab`. RDP login: `test-rdp`. WSL2 (Ubuntu) available on the
host but on a NAT network (`172.24.x`), not the LAN.

---

## 2. STATUS — the whole SSH + RDP pipeline WORKS end to end

Real session telemetry flows: WALLIX → Wazuh → custom decoder → rules → alerts →
indexer. Confirmed by real alerts (e.g. `whoami` → rule 100518, `useradd vc` →
rule 100512 level 12 with MITRE mapping). RDP logs now also arriving (decoder not
yet verified against a real RDP line — RDP format may differ from SSH; may be
session/app-launch events rather than KBD_INPUT).

Real captured SSH line shape:
```
Jul 24 13:49:30 wab-12-0-5 sshproxy[10143]: [SSH Session] \
  session_id="19f94e38158d9f6b000c291af8a6" client_ip="192.168.1.32" \
  target_ip="192.168.1.74" user="test-ssh" device="debian-lab" service="SSH" \
  account="svc-debian" type="KBD_INPUT" data="cat /etc/shadow"
```

---

## 3. Infrastructure problems solved (do NOT re-litigate)

The pipeline took a long debugging chain. Root causes, in order found:

1. **No syslog `<remote>` block** in ossec.conf — only the agent block (1514/tcp).
   Added `connection=syslog`, port 514, udp.
2. **`docker compose restart` does not reload bind-mounted config.** The manager
   copies `/wazuh-config-mount/etc/ossec.conf` → `/var/ossec/etc/ossec.conf` only at
   entrypoint. Must use `docker compose up -d --force-recreate wazuh.manager`.
3. **`allowed-ips` needs CIDR.** `0.0.0.0` matches nothing; `0.0.0.0/0` works.
4. **Docker NAT rewrites source IP.** Wazuh sees `172.20.0.1`/`172.21.0.1` (Docker
   gateway), never WALLIX's real `192.168.1.50`. The gateway shifts across recreates,
   so keep `allowed-ips` wide (`0.0.0.0/0`) or use `172.16.0.0/12`. **Document this.**
5. **THE MAIN BLOCKER: `syslog-ng` was dead on WALLIX.** A hand-added file
   `/etc/syslog-ng/conf.d/99-wazuh-forward.conf` had `log (` instead of `log {`. One
   char → daemon refused to start → nothing forwarded, including native SIEM. Found
   via `sudo /usr/sbin/syslog-ng --syntax-only`.
6. **Windows Firewall** needed an inbound UDP 514 allow rule.
7. **Docker Desktop DID forward UDP correctly** — earlier failures were a wrong IP
   (`.31` vs `.32`) plus the dead syslog-ng. VMware-migration and WSL2 detours were
   considered and rejected.
8. **`test-ssh` account lockout** after repeated failed auth. Symptom:
   `Permission denied (publickey,gssapi-with-mic,keyboard-interactive)`. Unlock in
   GUI. Raise the lockout threshold before dataset runs (sequential sessions can
   lock it mid-run and silently truncate the dataset).

### Debugging techniques that worked
- Container has no `netstat`/`ss`/`tcpdump`/`grep` on the PowerShell side — use
  `Select-String` or wrap in `sh -c "..."`.
- Listening UDP ports via `/proc/net/udp`; port 514 = hex `0202`.
- Isolate network vs. app with a throwaway capture container:
  `docker run --rm -p 192.168.1.32:514:514/udp alpine sh -c "apk add --no-cache socat && socat -u UDP-RECV:514 STDOUT"`.

---

## 4. WALLIX configuration (all confirmed correct)

- **System → SIEM Integration:** Routing Enabled, IP `192.168.1.32`, udp, 514,
  rfc5424. `KBD_INPUT` checked under SSH session filters. Apply pressed.
- **Connection policy `SSH1`:** `[trace] Log all kbd` = enabled. No pattern-detection
  section in this version → detection happens in Wazuh.
- **`Log group membership`** exists in the connection policy (default False) — this
  is how AD group membership would flow if AD is added later.

### Two forwarding paths currently active (cleanup needed)
1. Native SIEM integration (structured session events — what we want).
2. Manual `99-wazuh-forward.conf` forwarding `source(s_src)` — the appliance OS log,
   which floods Wazuh with sudo/sshd/cron noise and GUI-audit polling
   (`[wabaudit] action="list" type="Approval"` every 60s). **Trim this before dataset
   generation** — it pollutes ML features. Session events arrive regardless of it.

---

## 5. Wazuh decoder + rules — BUILT, INSTALLED, VERIFIED WORKING

Files bind-mounted from `config/wallix/` (version-controllable, in repo under `infra/`):
```yaml
- ./config/wallix/wallix_decoder.xml:/var/ossec/etc/decoders/wallix_decoder.xml
- ./config/wallix/wallix_rules.xml:/var/ossec/etc/rules/wallix_rules.xml
```

### Decoder design (learned the hard way)
- Parent anchors on `program_name` `^sshproxy|^rdpproxy|^wabengine|^wabaudit`.
- **Wazuh applies only the FIRST matching sibling child decoder** — it does NOT
  accumulate fields across several. So each event shape needs ONE comprehensive regex
  capturing every field, most-specific first. (First version had one-field-per-decoder
  and silently extracted only session_id — rewritten.)
- **All regexes use `type="pcre2"`.** The default OS_Regex engine does NOT support
  `\b` word boundaries or `(a|b)` alternation groups — including them makes
  wazuh-analysisd fail to start (this crashed analysisd; the "logtest error when
  connecting to wazuh-analysisd" symptom).
- Maps to standard Wazuh field names: `srcuser` (login user), `dstuser` (vaulted
  account), `dsthost`, `dstip`, `srcip`, `protocol`, plus custom `session_id`,
  `wallix_event`, `command`, `duration`.

### Rule IDs (reserved 100500–100550), all pcre2 fields
| ID | Level | Purpose | MITRE |
|---|---|---|---|
| 100500 | 2 | base rule (`if_sid` anchor) | — |
| 100502 | 3 | session opened | — |
| 100503 | 3 | session closed (w/ duration) | — |
| 100504 | 8 | auth/connection failure | — |
| 100505 | 5 | file transfer (SFTP/SCP) | — |
| 100510 | 12 | credential access (`/etc/shadow`, keys, mimikatz) | T1003, T1552 |
| 100512 | 12 | privilege escalation (useradd, sudoers, setuid) | T1548, T1136 |
| 100514 | 10 | persistence (cron, systemd, authorized_keys) | T1053, T1098 |
| 100516 | 12 | log tampering (`history -c`, log deletion) | T1070, T1562 |
| 100518 | 6 | recon (whoami, netstat, nmap) | T1082, T1087 |
| 100520 | 10 | exfiltration (scp, rsync, curl upload, nc) | T1048, T1041 |
| 100530 | 12 | native KILL_COMMAND_DETECTED | — |
| 100532 | 10 | native WARNING_/NOTIFY_COMMAND_DETECTED | — |
| 100534 | 10 | native _PATTERN_DETECTED | — |
| 100540 | 0 | suppress GUI approval-poll noise | — |

Install/test: `docker compose exec -it wazuh.manager /var/ossec/bin/wazuh-logtest`,
paste a real line, confirm rule fires. Custom decoders live in
`/var/ossec/etc/decoders/`, rules in `/var/ossec/etc/rules/` (the `wazuh_etc` is a
NAMED volume — one `docker compose down -v` destroys it, hence the bind mount).

---

## 6. Attack generators — BUILT

`ssh_attack.sh` and `rdp_attack.sh` + `README_attacks.md`. Drive labelled,
self-cleaning attack sessions through the Bastion, log one `ground_truth.jsonl` line
per session with a unique `session_tag` (echoed as first command so it appears in
telemetry), mapped to expected rule IDs.

### Key facts learned
- **SSH flow is TWO-PASSWORD and interactive:** `test-ssh's password:`
  (`P@ssw@rd123`) → `Account successfully checked out` → `root's password:` (`lab`)
  → shell `root@debian:~#`. `sshpass` answers only ONE prompt, so the script was
  **rewritten around `expect`**, which waits for each prompt in order. `sshpass`
  caused exit-code-5 hangs.
- Shell-prompt regex widened to `[#\$>][ ]?$` (was `[\$#] $` and missed prompts).
- Six scenarios each: recon, cred_access, privesc, persistence, log_tamper, exfil.
- All read-only or create-then-delete; exfil/scp/nc point at `127.0.0.1` so nothing
  leaves; log_tamper uses `ls`/`cat` not real deletion.
- RDP uses `xfreerdp /app` to launch `cmd.exe /c "..."`. RDP keystroke capture
  depends on RDP connection-policy OCR/metadata settings, not just `Log all kbd`.

### Security note
The privesc scenario types the sudo password into the session (`echo 'lab' | sudo -S`),
so `lab` appears in KBD_INPUT telemetry. Fine for a throwaway lab, but these sessions
must NEVER be fed raw into the RAG vector DB — this is exactly what the sanitised-
summary guardrail is for. Note in decision_log.md.

---

## 7. extract.py — BUILT, TESTED, WORKING

First stage of the feature pipeline. `feature_pipeline/extract.py`.

- Pulls WALLIX events from the Wazuh **indexer** (OpenSearch, port 9200), normalises
  to schema-contract fields, emits `events.jsonl` (raw normalised) and `sessions.jsonl`
  (grouped by session_id with `commands[]`, lifecycle timestamps, computed
  `duration_sec`).
- **`--source {indexer,fixture,generated}`** — fixture mode lets the AI teammate build
  transform.py with zero live-system access (dependency isolation).
- **`--index {archives,alerts}`.** Archives is the target (see §8) but Wazuh does NOT
  ship archives to the indexer by default — needs the archives Filebeat module + a
  `wazuh-archives-*` index. Script checks and falls back to alerts with a message.
  Currently running `--index alerts` (16 events → 1 session confirmed).
- **`search_after` pagination** (10k-hit cap).
- **`--from`/`--to`** as_of bounds to prevent future leakage in baseline builds.
- Filters to WALLIX events (`decoder.name:wallix` or `sshproxy`/`rdpproxy`) so OS
  noise stays out even if it's in the archives index.
- **APPEND + DEDUP by default** (added on request): re-running accumulates data across
  runs without overwriting or duplicating. Dedup by `session_id` (sessions) and a
  composite key (events). `--overwrite` flag forces replace. Keeps first-seen copy, so
  extract AFTER a session closes (SESSION_DISCONNECTION), not while open.

FIELD_MAP: session_id←data.session_id, user←data.srcuser, account←data.dstuser,
client_ip←data.srcip, target_ip←data.dstip, target_hostname←data.dsthost,
protocol←data.protocol, event_type←data.wallix_event, command←data.command,
duration←data.duration.

Run examples:
```powershell
python extract.py --source indexer --since 1h --index alerts
python extract.py --source indexer --from 2026-07-24T00:00:00Z --to 2026-07-25T00:00:00Z --index alerts
python extract.py --source fixture --fixture-file sample_events.jsonl
python extract.py --source indexer --since 1h --index alerts --overwrite
```
Deps: `pip install requests urllib3`. Creds via env: `WAZUH_INDEXER_URL/USER/PASS`
(defaults `https://192.168.1.32:9200`, `admin`, `SecretPassword`).

---

## 8. Data-source decision (locked)

**ML pipeline sources from ARCHIVES (`wazuh-archives-*`), not alerts.** Alerts contain
only rule-triggering events → structural recall ceiling → the model would only learn
what the rules already catch. Archives contain every command, needed for
command_entropy / command_count / unique_command_ratio. Enable via
`<logall_json>yes</logall_json>` + archives Filebeat module + index pattern. Until
enabled, `--index alerts` works but is the fallback, not the target.

**Corollary — rule_id/rule_level as features:** keep them as EVALUATION metadata
(ML-vs-rules comparison), NOT as model input features. Feeding rule_level into the
model when sourcing from alerts is circular ("the model re-learned the rules"). If
used as features at all, only from archives where most events have no rule.

Two Wazuh APIs, don't conflate: Manager API (55000, JWT, management only) vs Indexer
API (9200, basic auth, where alerts/archives live). extract.py uses the indexer.

---

## 9. Feature engineering plan (transform.py — NOT yet built)

The user will largely OWN the feature calculations (AI-team deliverable). Consumes
`sessions.jsonl`.

**Extracted (raw, from extract.py):** timestamp, source_ip, target_ip, user, account,
target_name, protocol, command, rule_id, rule_level.

**Calculated (transform.py):** command_entropy (Shannon), command_count,
unique_command_ratio, avg_command_length, risk-keyword flags (privesc/cred_access/
persistence/log_tamper/recon/exfil), off_hours_flag, session_hour_zscore,
duration_zscore (per-user Welford baseline), distinct_targets_24h, sessions_count_24h,
new_source_ip_for_user, distinct_source_ips_24h, source_ip_entropy,
role_command_mismatch, fail_ratio, consecutive_failures, concurrent_sessions.

### Design principles
- 3-file split (extract/transform/load) so the same transform works in batch (now)
  and streaming (future) — only extract's trigger changes. Batch only for now.
- Per-user baselines stored separately (incremental Welford), not recomputed inline.
- Baseline store exposes `as_of` to prevent future leakage.
- Sequence modelling (Markov/LSTM) deferred.

### Keystroke-token gotcha
WALLIX emits raw keystrokes incl. special keys as literal tokens, e.g.
`data="nano debconf.<TAB>"` and `whoami<NL>id`. Strip/normalise `<TAB>`, `<NL>`,
`<BACKSPACE>` on a COPY before computing command_entropy (else skewed); keep raw
command for audit. Normalisation belongs in transform.py, not extract (extract stays
lossless).

---

## 10. Dataset generation — PLAN AGREED (Option 4, hybrid), NOT yet built

**Principle: generated data TRAINS; real injected sessions JUDGE; never mix.**
(Evaluation-integrity rule — record in decision_log.md.)

Large semi-synthetic training set built from real templates + a small 100%-real
isolated evaluation set.

### Phases
1. **Collect real templates** — run each of the 6 attack types 1–2× (SSH + RDP) +
   ~10 benign, extract → split into `templates.jsonl` (for generation) and
   `eval_real.jsonl` (isolated, never trained on). BLOCKER: must do this first;
   everything depends on the real captured shape (esp. RDP, which may differ).
2. **Metadata layer** — personas (admin/dba/dev/auditor, each with a distinct command
   distribution), an IP pool (user will provide) split into per-persona home IPs +
   roaming + anomalous, time windows + Poisson timing. Assignment is COHERENT: benign
   = persona home IP + business-hours; attack = deliberate deviation. Keep
   `real_ts`/`real_ip` beside `synthetic_ts`/`synthetic_ip` (auditable).
3. **Generator** (`generate_from_template.py`, to build) — takes templates, produces N
   sessions varied on 5 axes: composition (~70% of attacks = 1–2 malicious commands
   buried in benign), persona, timing, pacing (some low-and-slow across sessions),
   intensity (obvious→subtle). Ratios: benign:attack = 70–80% : 20–30%, ≥30–50
   benign/persona before attacks. Writes unified ground_truth.jsonl.
4. **transform.py** — features on both train + eval.
5. **Train/eval** — train on generated, evaluate on isolated real. Bake-off + metric
   below.

### Diversity — the 5 axes
composition (buried attacks, the most important), personas, temporal spread,
attack pacing (fast vs low-and-slow), intensity gradient.

### Synthetic metadata — decided approach
Real sessions (through WALLIX), metadata rewritten DOWNSTREAM (transform input stage),
baseline-anchored, deviations deliberate and logged. NOT by injecting fake syslog into
Wazuh (that would bypass WALLIX and break the thesis). Timestamps: safe. IPs:
persona-anchored (home IP per persona, anomaly = known IP for the WRONG identity — the
strong insider signal — not just an unseen IP). User will PROVIDE an IP pool. Random
scatter = no (spurious learning); persona-anchored = yes. It's a semi-synthetic
dataset — MUST be documented as such in the report.

### Public command datasets — how to use them safely
User raised retrieving data from "commands datasets". Correct use: commands from a
public dataset (e.g. Schonlau/SEA for benign, Atomic Red Team / GTFOBins for attacks)
= CONTENT to fill sessions that still run THROUGH the Bastion. WALLIX stays the source,
identity resolution stays the thesis. WRONG use: training directly on a public dataset
bypassing WALLIX — kills the thesis. (Consistent with the standing decision: public
datasets rejected as PRIMARY data; Schonlau kept only as a command_entropy validator;
LANL optional for baseline-machinery stress test.)

### Honest lab constraints (document, don't fake away)
- Two hosts → no real lateral movement. Don't synthesise fake lateral movement.
- Single real source IP → source-IP features come from the synthetic pool; don't let
  target host become a label proxy (both targets must see both benign and attack).

---

## 11. ML methodology

Reference: Chamkar et al., "Improving Threat Detection in Wazuh Using ML Techniques"
(J. Cybersecur. Priv. 2025) — hybrid RF + DBSCAN, structure adopted as template.

Bake-off: unsupervised via PyOD (ECOD, COPOD, Isolation Forest, HBOS, PCA
reconstruction) as primary; MAD z-score as mandatory baseline; RF + LogReg once labels
exist; SMOTE for imbalance. **DBSCAN excluded from deployment** (no predict method).
Peer-group/cohort baselines for cold-start.

Points to defend in the report:
- **Metric: precision@k** (k = SOC alert budget), NOT ROC-AUC.
- Isolation Forest's underperformance in Chamkar et al. is dataset-specific — keep it.
- Comparable papers' ML mostly re-ranks rule output; this feature set (command_entropy,
  distinct_targets_24h, z-scores) is meaningfully different.
- **Risk ≠ anomaly.** Risk = anomaly score × impact weight; impact needs a
  Security-owned asset-criticality CSV WALLIX can't supply.
- **Train/serve skew:** truncate historical sessions at multiple horizons (t+60/300/900/
  final) during snapshot generation.
- **Rules vs ML scope:** rules = binary policy violations; ML = behavioural patterns.
  Don't duplicate (off-hours belongs in ML features, not Wazuh `<time>` rules).

---

## 12. RAG + API (later phases)

- **Qdrant**, two collections: `soc_policies` (ISO 27001/SOC2/MITRE/runbooks,
  Security-curated, static) and `session_history` (load.py dual-writes a SANITISED
  natural-language summary per session — never raw commands, to avoid embedding
  secrets; gated by a `rag_indexable` schema flag). LangChain RetrievalQA, cited answers.
- **FastAPI:** `/score` (session → ML risk), `/ask` (question → grounded answer +
  sources). `auth.py` (RBAC) Security-owned. Audit-log every `/ask`.

---

## 13. Repo & governance

```
soc-insider-threat/
├── infra/          # SECURITY: docker-compose, wazuh decoders/rules, lists/, samples/
├── schema/         # SHARED: schema_contract.yaml (dual sign-off to edit)
├── feature_pipeline/  # AI: extract.py, transform.py, load.py, sessionize.py
├── ml/             # AI: train.py, evaluate.py, inference/score.py
├── rag/            # AI (content Security-curated): ingestion/, retrieval/, prompts/
├── policies/       # SECURITY: raw RAG source docs
├── api/            # SHARED: main.py, auth.py (Security), schemas.py
├── monitoring/     # SHARED: drift/ (AI), logging/ (Security)
├── data/generator/ # Security owns scenarios.py, AI owns profiles.yaml
├── .github/        # CODEOWNERS
└── docs/           # architecture.md, runbooks, decision_log.md
```

Schema contract — 12 min fields: session_id (join key), user, account (borrowed
privileged identity, distinct from user), target_ip, target_hostname, protocol,
client_ip, session_start, duration (H:MM:SS on SESSION_DISCONNECTION), event_type,
command/command_line, file_transfer_bytes. Plus `rag_indexable`. Naming note:
extract.py currently emits client_ip/target_hostname/event_type; the user's feature
list says source_ip/target_name — LOCK names in schema_contract.yaml to avoid drift.

Open governance decisions: (1) labelling authority (confirm Security owns ground
truth); (2) threshold governance (can AI tune thresholds autonomously?);
(3) session_history retention (auto-purge vs indefinite).

**AD integration — DEFERRED.** Would give real per-user baselines, authentic personas,
real role_command_mismatch. Skipped now for resource reasons (a Domain Controller VM =
+4GB RAM; host resources tight). Does NOT require a VM per user — users are identities,
not machines. When added: enable `Log group membership` in the WALLIX connection policy
so AD group flows through the same syslog path; add a `group` field to decoder + schema
+ extract.py FIELD_MAP. Real AD names become personal data → strengthens the RAG
sanitisation + retention requirements.

---

## 14. Deliverables produced so far

- `wallix_decoder.xml`, `wallix_rules.xml`, `test_lines.txt` (installed, verified).
- `ssh_attack.sh` (expect-driven, two-password), `rdp_attack.sh`, `README_attacks.md`.
- `extract.py` (append+dedup), `sample_events.jsonl`, `README_extract.md`.
- Earlier: `WALLIX_Insider_Threat_Guide.pdf`, Team Implementation Guide (PDF),
  Workflow Architecture Diagram (PDF/Graphviz), `HPS_implementation_report.tex` (FR),
  `session_generator.py`, `rdp_session_churn.sh`, `rdp_attack_actions.ps1`,
  `wallix_session_features.xlsx`. Screenshots in Drive ("HPS-project", "claude-screens").
- French "état d'avancement" email drafted (steps: integration / decoders+rules /
  extract.py done; dataset generation / transform.py / ML upcoming).

### Environment packaging (for the teammate)
Image tarballs are NOT what to share — they're vanilla Wazuh. Ship compose +
`config/` (holds ossec.conf, certs, bind-mounted decoder/rules):
```powershell
Compress-Archive -Path .\docker-compose.yml, .\config -DestinationPath wazuh-setup.zip -Force
```
Recipient runs `docker compose up -d`; images pull from Docker Hub. Stock demo creds
still in use (`SecretPassword`, `MyS3cr37P450r.*-`, `kibanaserver`) — flag for
production-hardening checklist.

---

## 15. Immediate next steps (in order)

1. **Verify RDP decoding** — grab a real `rdpproxy` line from archives/alerts, confirm
   the decoder extracts fields (RDP may be session/app-launch events, not KBD_INPUT).
2. **Trim `99-wazuh-forward.conf`** — stop forwarding appliance OS noise before dataset
   generation pollutes ML features.
3. **Enable archives index** (logall_json + Filebeat archives module) so extract.py can
   use `--index archives`.
4. **Collect real templates** (dataset Phase 1) — run 6 attack types + benign, extract,
   split into templates vs isolated eval set.
5. **Build the generator** (`generate_from_template.py`) — needs the user's IP pool and
   confirmed persona command distributions.
6. **transform.py** — feature calculation (AI-team deliverable; user wants to own it).
7. ML bake-off + scoring script (rule-layer precision/recall baseline).
8. RAG + FastAPI + dashboard.

---

## What I want next

*[State what to work on — e.g. "build generate_from_template.py", "scaffold
transform.py", "help verify the RDP decoder against this line: ...", or paste the IP
pool to build the metadata layer.]*