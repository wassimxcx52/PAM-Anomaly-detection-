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

Bastion login user: `test-ssh` (password `P@ssw@rd123`, may include a trailing `.`
— confirm before use), group `testssh-group`. RDP login: `test-rdp`. WSL2 (Ubuntu)
available on the host but on a NAT network (`172.24.x`), not the LAN.

**Real vaulted accounts on debian-lab** (WALLIX account-selection menu, confirmed
2026-08-03): `p_admin` (root, requires a manual second password `lab`),
`p_dev`/`p_dba`/`p_audit` (plain sudoers, NOT NOPASSWD — `sudo` prompts for a
password we don't have; treated as a real "denied privesc attempt" signal, see
§6), `bastionsvc` (plain non-sudo test account). All four non-admin accounts
auto-connect (no second password). Personas map to these: `dev`→`p_dev`,
`dba`→`p_dba`, `auditor`→`p_audit`, `admin`→`bastionsvc`.

---

## 2. STATUS — SSH pipeline WORKS end to end, archives capture now fixed

Real session telemetry flows: WALLIX → Wazuh → custom decoder → rules → alerts →
indexer. Confirmed by real alerts (e.g. `whoami` → rule 100518, `useradd vc` →
rule 100512 level 12 with MITRE mapping). RDP logs arrive but the decoder is NOT
yet verified against a real RDP line (RDP format may differ from SSH; may be
session/app-launch events rather than KBD_INPUT) — still pending. FTP is NOT set
up at any layer yet (no WALLIX connection policy, no decoder support, no target
FTP server) — added to the dataset-generation scope (§10) but needs infra work
first.

**Dataset-collection driver (`feature_extraction/simulate_sessions.py`) is BUILT
and verified live** — see §6. As of 2026-08-03: ~64 real SSH sessions collected
(6 attack scenarios + 4 benign personas), archives index enabled and confirmed
capturing full command sequences (was previously silently dropping anything that
didn't match a custom rule — see §8).

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
9. **Archives were never shipped to the indexer even though `logall_json` was
   already `yes`.** Root cause: Filebeat's `wazuh` module has a separate
   `archives: enabled` toggle (in `config/filebeat.yml`) that defaulted to
   `false` — `logall_json` writes archives.json to disk, but nothing shipped it
   to OpenSearch. Concrete proof it mattered: under `--index alerts`, the
   `echo TAG:<tag>` marker every simulated session sends (see §6) had ZERO
   matches anywhere in extracted output, and a 5-command benign session only
   yielded 2 commands — anything not matching a custom rule was silently
   dropped. Fixed by flipping `archives: enabled: true`.
10. **Docker Desktop bind-mount stale-cache bug (unresolved root cause, has a
    workaround).** Editing `config/filebeat.yml` on the host and then running
    `docker compose up -d --force-recreate` reverted the file back to its
    exact original content AND original mtime, every time — reproduced with
    both a scripted edit and a manual one, a full Docker Desktop + `wsl
    --shutdown` restart did NOT fix it, and it happens specifically at the
    `--force-recreate` step (confirmed: file holds fine while idle, breaks the
    instant that command runs). Ruled out: OneDrive/cloud sync (none in use),
    `docker-compose.yml` override files (none), wrong compose project (bind
    source verified via `docker inspect` to be the exact right host path).
    **Workaround that worked:** edit the file directly inside the *already
    running* container's filesystem (`docker compose exec ... sh -c "cat >
    /etc/filebeat/filebeat.yml << 'EOF' ... EOF"` — use a heredoc for full
    control, NOT `sed -i`, which fails with `Device or resource busy` trying
    to rename over a bind-mounted file), then restart just the Filebeat
    process, not the whole container. This is NOT a permanent fix — the next
    `--force-recreate` will likely revert it again. Root cause still unknown;
    revisit before relying on this long-term.
11. **Claude Code's Bash tool (Git Bash/MSYS) and its Read/Write/Edit/PowerShell
    tools can resolve the identical absolute path to two DIFFERENT physical
    files** under `C:\Users\niro\Desktop\...` — observed directly (a file
    edited via one showed stale content via the other, confirmed via
    checksums). Docker Desktop's bind mounts follow the PowerShell/Read/Write
    view, not Bash's. If a host-file edit doesn't seem to be taking effect,
    verify with PowerShell (`Get-Content`/`Get-Item ... LastWriteTime`)
    before concluding the edit failed or something else reverted it.

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

Files bind-mounted from `config/wallix/` in the separate wazuh-docker deployment
project (`C:\Users\niro\Desktop\wazuh\wazuh-docker\single-node\config\wallix\`):
```yaml
- ./config/wallix/wallix_decoder.xml:/var/ossec/etc/decoders/wallix_decoder.xml
- ./config/wallix/wallix_rules.xml:/var/ossec/etc/rules/wallix_rules.xml
```
The version-controlled source-of-truth copy lives in THIS repo at
`infra/wazuh/wallix_decoder.xml` / `infra/wazuh/wallix_rules.xml` (moved there
2026-08-03 during repo restructuring) — the two are independent copies on
disk; sync changes manually between this repo's `infra/wazuh/` and the live
deployment's `config/wallix/`.

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

## 6. Session simulator — BUILT, VERIFIED LIVE

`feature_extraction/simulate_sessions.py` (Python + paramiko, NOT bash/expect —
neither `expect` nor `sshpass` are available in this environment's Git Bash).
Drives real, labelled, self-cleaning sessions through the Bastion over SSH, logs
one `ground_truth.jsonl` line per session with a unique `session_tag` (echoed as
`echo TAG:<tag>`, the session's first command, so it lands in real `KBD_INPUT`
telemetry and can be joined back to the extracted `sessions.jsonl` by searching
for that string — WALLIX assigns its own opaque `session_id` with no inherent
link to which scenario was run). Full details in
`feature_extraction/README_simulate_sessions.md`.

### Login flow (why paramiko + invoke_shell(), not a one-shot exec)
Paramiko authenticates to the Bastion at the SSH protocol level (`test-ssh` +
login password — real SSH auth). Post-auth, WALLIX shows an interactive
account-selection MENU (table of `ID | Site | Authorization` — NOT a second
password prompt as originally assumed): the script regex-parses this menu
(`MENU_ROW_RE`) and sends the row ID matching the target account. Only
`p_admin` then prompts a genuine second password (`p_admin's password:` → `lab`);
the other accounts (`p_dev`/`p_dba`/`p_audit`/`bastionsvc`) auto-connect straight
to a shell.

### Attacks through non-admin accounts (`--attack-accounts`)
Attack scenarios default to `p_admin` but can rotate across
`p_admin,p_dev,p_dba,p_audit`. Root-only steps (`useradd`, `/etc/sudoers.d/`
edits, `/etc/shadow`, `auth.log`) use a `{sudo}` template placeholder, empty for
`p_admin`. Since `p_dev`/`p_dba`/`p_audit` turned out NOT to be NOPASSWD sudoers
(verified live — deliberately did not guess a password, to avoid another
lockout), a mid-command `[sudo] password for X:` prompt is treated as a DENIAL,
not a script failure: the driver sends Ctrl+C, logs the denied command, and
keeps going. Ground truth records `commands_denied`/`fail_ratio` per session —
real telemetry for the `fail_ratio`/`consecutive_failures` features already
planned (§9), and arguably a MORE realistic insider signal than a scripted
success (a normal-role account attempting something it has no rights to do).

### Six attack scenarios (all self-cleaning / read-only)
recon (100518), cred_access (100510, `find` scoped to `/root /home /etc` + bin
dirs — unscoped `find /` timed out in testing), privesc (100512,
create-then-delete temp user + sudoers entry), persistence (100514,
create-then-delete cron entry), log_tamper (100516, read-only — `ls`/`cat`/
`history -c`, no real deletion), exfil (100520, targets `127.0.0.1` only, `scp`
uses `BatchMode=yes` so a missing key fails fast instead of hanging on a
password prompt).

### Benign personas (each its own real account, see §1)
`admin`→`bastionsvc`, `dba`→`p_dba`, `dev`→`p_dev`, `auditor`→`p_audit`. Command
lists are currently short/fixed (4-6 commands, same order every rep) — fine as
template shape for the generator, but the isolated `eval_real` set should vary
this, and the vocabulary itself should eventually draw from public command
datasets (Schonlau/GTFOBins-style, see §10) rather than the hand-picked list.

### What's randomized per run vs. not
Randomized: session order, session tag, inter-command pacing
(`random.uniform(0.4, 1.3)`s). NOT randomized: the command list per
scenario/persona is fixed content in a fixed order every rep.

### RDP / FTP status
RDP: not built into the simulator yet (§2 — decoder unverified). FTP: not
started at any layer (no WALLIX connection policy, no `ftpproxy` decoder
support, no target FTP server) — added to dataset scope (§10), infra work
needed first.

### Security note
The privesc scenario writes a temp sudoers entry (not a live sudo password
prompt), so no real secret should appear in this scenario's telemetry. Sessions
run through `p_admin` still involve real root access — these sessions must
NEVER be fed raw into the RAG vector DB regardless; this is exactly what the
sanitised-summary guardrail is for. Note in decision_log.md.

---

## 7. extract.py — BUILT, TESTED, WORKING

First stage of the feature pipeline. `feature_pipeline/extract.py`.

- Pulls WALLIX events from the Wazuh **indexer** (OpenSearch, port 9200), normalises
  to schema-contract fields, emits `events.jsonl` (raw normalised) and `sessions.jsonl`
  (grouped by session_id with `commands[]`, lifecycle timestamps, computed
  `duration_sec`).
- **`--source {indexer,fixture,generated}`** — fixture mode lets the AI teammate build
  transform.py with zero live-system access (dependency isolation).
- **`--index {archives,alerts}`.** Archives is the target (see §8) and, as of
  2026-08-03, IS enabled and verified working — `wazuh-archives-*` exists with
  real data (11,665 docs same-day). **Use `--index archives` going forward**,
  not the alerts fallback. A fresh pull showed 1,147 events / 71 sessions with
  full command sequences (including the `TAG:` marker, previously dropped
  entirely under alerts-only extraction).
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
command_entropy / command_count / unique_command_ratio.

**STATUS (2026-08-03): archives is enabled and verified.** `<logall_json>yes</logall_json>`
was already set in `ossec.conf`, but Filebeat's `wazuh` module `archives: enabled`
toggle (separate setting, in `config/filebeat.yml`) defaulted to `false` — so
nothing was ever shipped to the indexer despite `logall_json` writing full data to
disk all along. Flipped to `true` and confirmed working (see §3 item 9-10 for the
Docker Desktop bind-mount gotcha hit while fixing this, and the workaround used —
NOT a permanent fix, revisit before relying on this long-term). Any sessions
collected before this fix have permanently incomplete command data (nothing to
recover it from) and should be re-run if they matter for training.

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

### Protocols in scope
SSH (built, ~64 real sessions collected as of 2026-08-03, see §6), RDP (decoder
unverified, not built into simulator), **FTP (added to scope 2026-08-03 — NOT
started at any layer: no WALLIX connection policy, no `ftpproxy` decoder
support in `wallix_decoder.xml`/`wallix_rules.xml` (only `SFTP_EVENT`/
`SCP_EVENT` under the SSH-based sshproxy exist), no target FTP server. Needs
infra work before any simulate_sessions.py-style scripting.**

### Phases
1. **Collect real templates** — run each of the 6 attack types 1–2× (SSH + RDP +
   FTP once built) + ~10 benign per protocol, extract → split into
   `templates.jsonl` (for generation) and `eval_real.jsonl` (isolated, never
   trained on). SSH: in progress (§6). RDP/FTP: blocked on infra above.
2. **Metadata layer** — personas (admin/dba/dev/auditor, each with a distinct command
   distribution), an IP pool (user will provide) split into per-persona home IPs +
   roaming + anomalous, time windows + Poisson timing. Assignment is COHERENT: benign
   = persona home IP + business-hours; attack = deliberate deviation. Keep
   `real_ts`/`real_ip` beside `synthetic_ts`/`synthetic_ip` (auditable).
3. **Generator** (`generate_from_template.py`, to build) — takes templates, produces N
   sessions varied on 5 axes: composition (~70% of attacks = 1–2 malicious commands
   buried in benign), persona, timing, pacing (some low-and-slow across sessions),
   intensity (obvious→subtle). **Ratio LOCKED 2026-08-03: benign:attack = 85% : 15%**
   (tightened from the original 70–80% : 20–30% range — user's explicit call, more
   representative of real SOC conditions; consistent with §11's SMOTE-for-imbalance
   and precision@k-not-accuracy stance), ≥30–50 benign/persona before attacks.
   Writes unified ground_truth.jsonl.
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

**This is the aspirational multi-owner target layout, not the current repo.**
The actual repo (`C:\Users\niro\Desktop\hps`, restructured 2026-08-03) realizes
a subset of it under different names, since only extract.py/transform.py/
simulate_sessions.py and the decoder/rules exist so far:
`infra/wazuh/` (decoder+rules), `feature_extraction/` (not yet renamed
`feature_pipeline/` — no code depends on the name either way), `ml/`,
`visualisation/`, `docs/decision_log.md`. `schema/`, `rag/`, `policies/`,
`api/`, `monitoring/`, `data/generator/`, `.github/` don't exist yet — added
when those phases actually start, not scaffolded empty ahead of time.

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

- `infra/wazuh/wallix_decoder.xml`, `infra/wazuh/wallix_rules.xml` (installed
  in the live deployment, verified).
- `feature_extraction/simulate_sessions.py` (paramiko-driven, menu-based account
  selection, multi-account attack rotation with denial handling) +
  `README_simulate_sessions.md`. Supersedes the earlier planned
  `ssh_attack.sh`/`rdp_attack.sh` (bash/expect), which were never actually built —
  `expect`/`sshpass` aren't available in this environment.
- `extract.py` (append+dedup), `sample_events.jsonl`, `README_extract.md`.
- `feature_extraction/out/ground_truth.jsonl` — ~64 real SSH sessions logged as
  of 2026-08-03 (session_tag, scenario/persona, expected_rule_ids,
  commands_denied, fail_ratio, status).
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

1. **Set up FTP infra** — WALLIX connection policy + target FTP server, then extend
   `wallix_decoder.xml` (new `ftpproxy` parent branch, built from a real captured
   line same as SSH/RDP were) + `wallix_rules.xml` before any FTP scripting.
2. **Verify RDP decoding** — grab a real `rdpproxy` line from archives/alerts, confirm
   the decoder extracts fields (RDP may be session/app-launch events, not KBD_INPUT).
3. **Trim `99-wazuh-forward.conf`** — stop forwarding appliance OS noise before dataset
   generation pollutes ML features.
4. **Re-run/expand SSH template collection** now that archives capture is fixed —
   consider adding `--attack-accounts` rotation (p_dev/p_dba/p_audit denial
   scenarios) to future runs, not just `p_admin`.
5. **Confirm the Docker Desktop bind-mount fix is durable**, or find the real root
   cause (§3 item 10) — the current fix lives only inside the running container.
6. **Split templates vs. eval_real** — join `ground_truth.jsonl` to `sessions.jsonl`
   by `session_tag`, isolate an `eval_real.jsonl` never trained on.
7. **Build the generator** (`generate_from_template.py`) — needs the user's IP pool,
   confirmed persona command distributions, and uses the locked 85:15 ratio (§10).
8. **transform.py** — feature calculation (AI-team deliverable; user wants to own it).
   Remember to strip `echo TAG:...` and trailing `exit` from the raw commands list
   before computing command_entropy/command_count (see §9's keystroke-token gotcha —
   same pattern applies).
9. ML bake-off + scoring script (rule-layer precision/recall baseline).
10. RAG + FastAPI + dashboard.

---

## What I want next

*[State what to work on — e.g. "build generate_from_template.py", "scaffold
transform.py", "help verify the RDP decoder against this line: ...", or paste the IP
pool to build the metadata layer.]*