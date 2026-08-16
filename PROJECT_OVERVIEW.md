# PAM-Driven Insider-Threat Detection — Full Project Extract

*Consolidated reference, generated 2026-08-16 from the repository at
`C:\Users\niro\Desktop\hps` (branch `command-rarity-features`, HEAD `e1a12db`).*

Report title: **« Détection d'anomalies comportementales sur les sessions à
privilèges par apprentissage automatique »** — 2-month internship project.

---

## 1. Thesis in one line

**WALLIX Bastion (PAM) → Wazuh (SIEM/XDR) → feature pipeline → ML anomaly
scoring → FastAPI `/score` → (planned) RAG SOC copilot + dashboard.**

The claim to be defended: **the configured detection rules are not enough.**
Signature/keyword rules catch known policy violations; a behavioural model
catches privileged-session activity the rules are structurally blind to. The
project's headline evidence is the *flagless* slice — real attack sessions that
trip **no** `wallix_rules.xml` keyword — where the rule layer scores recall 0 and
the ML models rank all of them in the top 64 of 256.

### Two governing rules

| Rule | Meaning |
|---|---|
| **Generated data TRAINS; real sessions JUDGE; never mix** | Evaluation integrity. `dataset_generation/` builds the training substrate; `feature_extraction/out/eval_real.jsonl` (256 real sessions) is never trained on. |
| **WALLIX stays the source of truth** | Public corpora (Atomic Red Team, GTFOBins, Linux command sets) supply *content only*; commands are still executed through the real Bastion. Training directly on an external dataset would kill the thesis. |

### Two detection tracks over one shared feature matrix

| Track | Question | Trains on | Output |
|---|---|---|---|
| **Unsupervised** (primary) | *is this abnormal?* | generated **benign only** (5 000) | anomaly score → ranked queue |
| **Supervised** (secondary) | *known attack? which tactic?* | generated 85:15 (5 882) | attack? + tactic vector |

`transform.py` computes every feature once, label-agnostic; each track is a
*filter* over that one matrix, not a separate pipeline.

---

## 2. Team and ownership

| Role | Duration | Scope |
|---|---|---|
| Technical lead (this user) | 2 months | Whole platform |
| Security engineer | 2 months | Wazuh rules, policies, RAG content, `auth.py`, labelling authority |
| Data/AI engineer | 2 weeks | Feature engineering + ML bake-off, then hand-off |

Open governance questions: labelling authority, whether AI may tune thresholds
autonomously, `session_history` retention policy.

---

## 3. Lab environment

| Component | Address | Notes |
|---|---|---|
| Windows physical host | `192.168.1.32` | Docker Desktop; runs the Wazuh stack |
| WALLIX Bastion | `192.168.1.50` | VMware VM, bridged, `wab-12-0-5`, v12.0.86 |
| debian-lab (SSH target) | `192.168.1.74` | vaulted accounts live here |
| win10-lab (RDP target) | `192.168.1.75` | RDP decoder unverified |

Wazuh 4.14.5 single-node Docker stack (`wazuh.manager`, `wazuh.indexer`,
`wazuh.dashboard`) in a **separate** compose project
(`wazuh-docker/single-node`). Bastion login user `test-ssh`, group
`testssh-group`; RDP login `test-rdp`.

### Vaulted accounts on debian-lab

**This list is WALLIX configuration and it moves.** Observed 2026-08-15:
`p_admin`, `p_audit`, `p_dba`, `p_dev`, `svc-debian`. `bastionsvc` no longer
exists — the admin persona now maps to `svc-debian`, which is **root** where
`bastionsvc` was a plain non-sudo account, so `account` is a weaker role signal
than it was.

| Persona | Account | Privilege |
|---|---|---|
| admin | `svc-debian` (was `bastionsvc`) | root |
| dba | `p_dba` | sudoer, **not** NOPASSWD |
| dev | `p_dev` | sudoer, **not** NOPASSWD |
| auditor | `p_audit` | sudoer, **not** NOPASSWD |
| (attacks) | `p_admin` | root |

The non-NOPASSWD sudoers are a feature, not a defect: a mid-command
`[sudo] password for X:` prompt is treated as a **denial**, logged as
`commands_denied` / `fail_ratio` — a normal-role account attempting something it
has no rights to do is arguably a *more* realistic insider signal than a scripted
success.

---

## 4. Telemetry path (working end-to-end for SSH)

```
WALLIX Bastion
  │ syslog rfc5424, UDP 514, native SIEM integration (KBD_INPUT enabled)
  ▼
Wazuh Manager  ──  infra/wazuh/wallix_decoder.xml + wallix_rules.xml
  │ logall_json → archives.json → Filebeat (archives: enabled) → OpenSearch
  ▼
wazuh-archives-*  (indexer, port 9200, basic auth)
```

Real captured line shape:

```
Jul 24 13:49:30 wab-12-0-5 sshproxy[10143]: [SSH Session] \
  session_id="19f94e38..." client_ip="192.168.1.32" target_ip="192.168.1.74" \
  user="test-ssh" device="debian-lab" service="SSH" account="svc-debian" \
  type="KBD_INPUT" data="cat /etc/shadow"
```

### Decoder design constraints (learned the hard way)

- Parent anchors on `program_name` `^sshproxy|^rdpproxy|^wabengine|^wabaudit`.
- **Wazuh applies only the FIRST matching sibling child decoder** — it does not
  accumulate fields across several. Each event shape needs ONE comprehensive
  regex, most-specific first.
- **All regexes must be `type="pcre2"`.** The default OS_Regex engine supports
  neither `\b` nor `(a|b)` alternation; including them makes `wazuh-analysisd`
  fail to start.
- Maps to standard Wazuh names — `srcuser`, `dstuser`, `dsthost`, `dstip`,
  `srcip`, `protocol` — plus custom `session_id`, `wallix_event`, `command`,
  `duration`.

### Rule IDs (reserved 100500–100550)

| ID | Level | Purpose | MITRE |
|---|---|---|---|
| 100500 | 2 | base rule (`if_sid` anchor) | — |
| 100502 | 3 | session opened | — |
| 100503 | 3 | session closed (with duration) | — |
| 100504 | 8 | auth / connection failure | — |
| 100505 | 5 | file transfer (SFTP/SCP) | — |
| 100510 | 12 | credential access (`/etc/shadow`, keys, mimikatz) | T1003, T1552 |
| 100512 | 12 | privilege escalation (useradd, sudoers, setuid) | T1548, T1136 |
| 100514 | 10 | persistence (cron, systemd, authorized_keys) | T1053, T1098 |
| 100516 | 12 | log tampering (`history -c`, log deletion) | T1070, T1562 |
| 100518 | 6 | recon (whoami, netstat, nmap) | T1082, T1087 |
| 100520 | 10 | exfiltration (scp, rsync, curl upload, nc) | T1048, T1041 |
| 100530 | 12 | native `KILL_COMMAND_DETECTED` | — |
| 100532 | 10 | native `WARNING_/NOTIFY_COMMAND_DETECTED` | — |
| 100534 | 10 | native `_PATTERN_DETECTED` | — |
| 100540 | 0 | suppress GUI approval-poll noise | — |

Source of truth lives in this repo at `infra/wazuh/`; the live deployment
bind-mounts its **own copy** under `config/wallix/` — the two are independent
files on disk and must be synced manually.

Install/test: `docker compose exec -it wazuh.manager /var/ossec/bin/wazuh-logtest`.

---

## 5. Infrastructure problems already solved — do not re-litigate

1. **No syslog `<remote>` block** in `ossec.conf` (only the agent block on
   1514/tcp). Added `connection=syslog`, port 514, udp.
2. **`docker compose restart` does not reload bind-mounted config.** The manager
   copies `/wazuh-config-mount/etc/ossec.conf` at entrypoint only. Use
   `docker compose up -d --force-recreate wazuh.manager`.
3. **`allowed-ips` needs CIDR.** `0.0.0.0` matches nothing; `0.0.0.0/0` works.
4. **Docker NAT rewrites the source IP.** Wazuh sees the Docker gateway
   (`172.20.0.1`/`172.21.0.1`), never WALLIX's real `192.168.1.50`, and the
   gateway shifts across recreates — keep `allowed-ips` wide.
5. **The main blocker: `syslog-ng` was dead on WALLIX.** A hand-added
   `/etc/syslog-ng/conf.d/99-wazuh-forward.conf` had `log (` instead of `log {`.
   One character → daemon refused to start → nothing forwarded at all, including
   the native SIEM integration. Found via `syslog-ng --syntax-only`.
6. **Windows Firewall** needed an inbound UDP 514 allow rule.
7. Docker Desktop *did* forward UDP correctly — earlier failures were a wrong IP
   (`.31` vs `.32`) plus the dead syslog-ng.
8. **`test-ssh` lockout** after repeated failed auth (`Permission denied
   (publickey,gssapi-with-mic,keyboard-interactive)`). Raise the lockout
   threshold before dataset runs — sequential sessions can lock mid-run and
   silently truncate the dataset.
9. **Archives were never shipped to the indexer** even though `logall_json` was
   already `yes`. Filebeat's `wazuh` module has a separate `archives: enabled`
   toggle (in `config/filebeat.yml`) defaulting to `false`. Proof it mattered:
   under `--index alerts`, the `echo TAG:<tag>` marker had **zero** matches
   anywhere, and a 5-command benign session yielded 2 commands. Fixed.
10. **Docker Desktop bind-mount stale-cache bug (root cause unresolved).**
    Editing `config/filebeat.yml` on the host then running
    `--force-recreate` reverted the file to its exact original content *and*
    mtime, every time. Ruled out: cloud sync, override files, wrong project.
    **Workaround:** edit inside the already-running container with a heredoc
    (`sed -i` fails with `Device or resource busy` on a bind-mounted file), then
    restart only the Filebeat process. Not permanent — the next
    `--force-recreate` will likely revert it.
11. **Claude Code's Bash (MSYS) and its Read/Write/PowerShell tools can resolve
    the same absolute path to two different physical files** under
    `C:\Users\niro\Desktop\...`. Docker bind mounts follow the PowerShell view.
    Verify with `Get-Content` / `Get-Item ... LastWriteTime` before concluding an
    edit failed.
12. **The decoder silently truncated every command containing a quote** — see §9.

### Debugging techniques that worked

- The container has no `netstat`/`ss`/`tcpdump`/`grep` on the PowerShell side —
  use `Select-String` or wrap in `sh -c "..."`.
- Listening UDP ports via `/proc/net/udp`; port 514 = hex `0202`.
- Isolate network vs. app with a throwaway capture container:
  `docker run --rm -p 192.168.1.32:514:514/udp alpine sh -c "apk add --no-cache socat && socat -u UDP-RECV:514 STDOUT"`.

### Still open at the infra layer

- **Two forwarding paths are active.** (1) The native SIEM integration —
  structured session events, what we want. (2) The manual
  `99-wazuh-forward.conf` forwarding `source(s_src)` — appliance OS log, which
  floods Wazuh with sudo/sshd/cron noise and 60-second GUI-audit polling. **Trim
  path 2** before further dataset generation; session events arrive regardless.
- **RDP decoder unverified** against a real `rdpproxy` line. RDP is GUI: WALLIX
  emits session lifecycle only (`SESSION_ESTABLISHED`/`SESSION_DISCONNECTION`),
  no per-command events, unless OCR/window-title capture is enabled.
- **FTP not set up at any layer** — no WALLIX connection policy, no `ftpproxy`
  decoder branch, no target FTP server.

---

## 6. Repository layout (actual)

```
hps/
├── infra/wazuh/
│   ├── wallix_decoder.xml            # source of truth (live deployment holds a copy)
│   └── wallix_rules.xml              # 6 tactics, MITRE-mapped, IDs 100500-100540
│
├── feature_extraction/               # REAL side — collection + feature pipeline
│   ├── simulate_sessions.py   (670)  # drives real labelled SSH sessions via paramiko
│   ├── extract.py             (602)  # Stage 1: pull + normalise + sessionize
│   ├── extract_raw.py         (227)  # raw indexer dump (diagnostic)
│   ├── transform.py           (478)  # Stage 2: per-session features
│   ├── command_profile.py     (199)  # vocabulary-rarity model (fit/save/score)
│   ├── README_simulate_sessions.md
│   └── out/                          # real telemetry + feature CSVs
│
├── dataset_generation/               # GENERATED side — synthetic training data
│   ├── curate_atomic_redteam.py (259)
│   ├── curate_gtfobins.py       (211)
│   ├── curate_linux_commands.py (183)
│   ├── command_safety.py        (127)  # shared destructive/hanging-command filter
│   ├── build_calibration.py      (89)
│   ├── build_persona_weights.py (172)
│   ├── fit_generator.py         (338)  # fits stickiness / length_tilt / arg_variation
│   ├── generate_benign.py       (440)
│   ├── generate_attacks.py      (477)
│   ├── build_training_set.py    (133)  # merges at the locked 85:15
│   ├── commands_dataset/               # curated pools (+ gitignored raw caches)
│   ├── metadata/
│   │   ├── build_identity_pool.py (232) → identity_pool.json
│   │   ├── build_calibration_slice.py (179) → calibration_slice.json
│   │   └── generator_params.json
│   └── out/
│
├── ml/
│   ├── feature_gate.py     (234)  # the single definition of an allowed column
│   ├── evaluation.py       (208)  # one scoring report for all four models
│   ├── persistence.py       (97)  # save/load a (model+scaler+features+profile) bundle
│   ├── compare.py           (71)  # assembles results_all.csv
│   ├── score.py            (133)  # CLI inference against a saved bundle
│   ├── supervised/train.py (225)  # RandomForest + LightGBM
│   ├── unsupervised/train.py (202) # KMeans + IsolationForest
│   ├── bundles/*.joblib           # 4 saved bundles (gitignored)
│   └── results_{unsupervised,supervised,all}.csv
│
├── api/                            # NEW, uncommitted
│   ├── main.py             (208)  # FastAPI: POST /score, GET /model, GET /health
│   ├── Dockerfile                 # ships the FEATURE CODE, not just a pickle
│   ├── docker-compose.yml         # joins the Wazuh stack's external network
│   └── requirements.txt
│
├── visualisation/
│   ├── plot_unsupervised.py (366) # re-reads training artifacts, recomputes nothing
│   └── fig1..fig5 (.png 300dpi + .pdf vector)
│
├── docs/
│   ├── decision_log.md            # durable decisions
│   ├── GUIDE_PROJET_FR.md   (704) # full French walkthrough
│   ├── GUIDE_VISUEL_FR.pdf
│   ├── RAPPORT_ETAPES.pdf + build_rapport_etapes.py (454)
│   ├── session_2026-08-09_unsupervised_precision.md (397)
│   └── session_2026-08-15_command_rarity.md (214)
│
├── CLAUDE.md                       # rolling working context (local-only; holds lab creds)
├── README.md
└── requirements.txt
```

**Aspirational target layout** (`soc-insider-threat/` with `schema/`, `rag/`,
`policies/`, `monitoring/`, `data/generator/`, `.github/CODEOWNERS`) is *not* the
current repo. Those directories get created when their phase actually starts, not
scaffolded empty. `feature_extraction/` has not been renamed `feature_pipeline/`;
nothing depends on the name.

---

## 7. Data artifacts on disk

### Real side — `feature_extraction/out/`

| File | Records | What it is |
|---|---|---|
| `ground_truth.jsonl` | 404 | one line per driven session: `session_tag`, `kind`, `scenario`, `expected_rule_ids`, `mitre`, `account`, `started_at`, `status` |
| `events.jsonl` | 7 506 | normalised WALLIX events (KBD_INPUT etc.) |
| `sessions.jsonl` | 413 | grouped by `session_id` with `commands[]` |
| `eval_real.jsonl` | **256** | the isolated evaluation set — **never trained on** |
| `*.pre_repair.jsonl` | — | pre-decoder-fix snapshots, kept for audit |
| `features_train.csv` | 5 882 rows × 61 cols | generated training matrix |
| `features_eval_real.csv` | 256 rows | real evaluation matrix |
| `command_profile.json` | — | fitted benign vocabulary (1 273 distinct commands) |
| `out/live/` | 0 | empty live-extraction target (uncommitted) |

`sessions.jsonl` schema: `session_id, user, account, client_ip, target_ip,
target_hostname, protocol, session_start, session_end, duration_sec,
session_start_is_estimated, session_end_is_estimated, duration_sec_is_estimated,
commands, event_types, raw_event_count, file_transfer_bytes`.

### Generated side — `dataset_generation/out/`

| File | Records |
|---|---|
| `generated_benign.jsonl` | 5 000 (1 250 × 4 personas) |
| `generated_attacks.jsonl` | 882 (= 15 %) |
| `generated_train.jsonl` | **5 882**, shuffled at the locked 85:15 |
| `generated_benign.pre_calibration.jsonl` | 1 000 (audit trail) |

Generated sessions use **the same schema as `extract.py`'s `sessions.jsonl`**, so
`transform.py` consumes real and synthetic sessions through one code path.

---

## 8. The pipeline, stage by stage

### 8.1 `simulate_sessions.py` — real session collection

Python + paramiko (not bash/expect — neither `expect` nor `sshpass` exists in
this environment). Drives real, labelled, self-cleaning sessions through the
Bastion and writes one `ground_truth.jsonl` line per session.

**Login flow.** Paramiko authenticates to the Bastion at the SSH protocol level
(`test-ssh` + password). Post-auth WALLIX presents an interactive
account-selection **menu** (`ID | Site | Authorization`), not a second password
prompt as originally assumed; the script regex-parses it (`MENU_ROW_RE`) and
sends the matching row ID. Whether a second password follows is **WALLIX
configuration, not a property of the script** — `p_admin` required it when this
was written and stopped requiring it by 2026-08-15, which hung every attack
session until `STEP_TIMEOUT`. The current code **detects** the prompt
(`_read_until_any([PASSWORD_RE, PROMPT_RE])`) instead of predicting it.

**Join key.** WALLIX assigns its own opaque `session_id` with no inherent link to
the scenario. So every session's first command is `echo TAG:<tag>` — it lands in
real KBD_INPUT telemetry and joins `ground_truth.jsonl` back to
`sessions.jsonl`.

**Six attack scenarios**, all self-cleaning or read-only:

| Scenario | Rule | Notes |
|---|---|---|
| recon | 100518 | |
| cred_access | 100510 | `find` scoped to `/root /home /etc` + bin dirs — unscoped `find /` timed out |
| privesc | 100512 | create-then-delete temp user + sudoers entry |
| persistence | 100514 | create-then-delete cron entry |
| log_tamper | 100516 | read-only: `ls`/`cat`/`history -c`, no real deletion |
| exfil | 100520 | targets `127.0.0.1` only; `scp` uses `BatchMode=yes` so a missing key fails fast |

**Session composition** (added after the 2026-08-07 measurement, see §9):
benign sessions get variable length + repetition (`--stickiness`); attacks get
one of `full` / `diluted` (scenario intact, benign filler interleaved so
create-then-delete pairs still clean up) / `minimal` (1–2 read-only attack
commands buried in benign activity, `--bury-rate`).

### 8.2 `extract.py` — pull, normalise, sessionize

- Pulls from the Wazuh **indexer** (OpenSearch 9200, basic auth), not the
  Manager API (55000, JWT — management only). Do not conflate them.
- `--source {indexer,fixture,generated}` — fixture mode let the AI teammate build
  `transform.py` with zero live-system access.
- `--index {archives,alerts}` — **use `archives`**; see §10.
- `search_after` pagination (10 k hit cap); `--from`/`--to` as-of bounds to
  prevent future leakage.
- Filters to WALLIX events (`decoder.name:wallix` or `sshproxy`/`rdpproxy`) so OS
  noise stays out.
- **Append + dedup by default** — re-running accumulates across runs. Dedup by
  `session_id` (sessions) and a composite key (events); keeps the first-seen
  copy, so extract *after* a session closes. `--overwrite` forces replace.
- `repair_command()` recovers decoder-truncated commands from `full_log`.

`FIELD_MAP`: `session_id←data.session_id`, `user←data.srcuser`,
`account←data.dstuser`, `client_ip←data.srcip`, `target_ip←data.dstip`,
`target_hostname←data.dsthost`, `protocol←data.protocol`,
`event_type←data.wallix_event`, `command←data.command`, `duration←data.duration`.

Credentials via env: `WAZUH_INDEXER_URL` / `USER` / `PASS` (defaults
`https://192.168.1.32:9200`, `admin`, `SecretPassword`). TLS verification is
disabled for the lab's self-signed cert — do not carry that into production.

### 8.3 `transform.py` — the one feature matrix

61 columns in `features_train.csv`. Grouped:

**Passthrough / identity (13):** `session_id, user, account, client_ip,
target_ip, target_hostname, session_start, session_end, duration_sec, commands,
event_types, raw_event_count, file_transfer_bytes`

**Ride-along metadata — never model input (19):** `label, tactics, source, split,
persona, ip_source, target_group, target_criticality, identity_is_synthetic,
ip_is_synthetic, ts_is_synthetic, real_user, real_client_ip, real_target_ip,
real_target_hostname, mitre, composition, attack_command_count, campaign_id`

**Candidate features:**

| Group | Columns |
|---|---|
| Protocol/temporal | `protocol, has_command_telemetry, start_time, end_time, duration_sec_feat, start_hour, off_hours_flag, is_weekend` |
| Command **shape** | `command_count, unique_command_ratio, avg_command_length, command_entropy` |
| Keyword flags (Config B only) | `flag_cred_access, flag_privesc, flag_persistence, flag_log_tamper, flag_recon, flag_exfil` |
| IP behaviour | `new_source_ip_for_user, new_source_ip_globally, ip_foreign_to_user, distinct_source_ips_prior, distinct_source_ips_24h, source_ip_entropy` |
| Command **rarity** (the decisive group) | `cmd_oov_rate, cmd_mean_surprisal, cmd_max_surprisal, cmd_mean_novelty, cmd_max_novelty` |

`RISK_KEYWORDS` deliberately mirrors the `wallix_rules.xml` taxonomy
(100510–100520) so ML features and rule detections stay comparable rather than
becoming a competing taxonomy.

**Keystroke-token gotcha.** WALLIX emits raw keystrokes including special keys as
literal tokens (`nano debconf.<TAB>`, `whoami<NL>id`). These are stripped on a
*copy* before computing entropy; the raw command is kept for audit.
Normalisation belongs in transform, not extract — extract stays lossless. Also
strip `echo TAG:...` and the trailing `exit`.

**RDP is NaN, not zero.** For protocols carrying no command telemetry the command
features are *absent*, emitted as NaN, so no model reads "entropy 0" as a real,
unusually-repetitive session. `COMMAND_PROTOCOLS = {SSH, SFTP, SCP, TELNET}`.

**Serving entry point (uncommitted).** `build_features` was split so
`build_features_from_sessions(frame, ...)` accepts an in-memory frame — this is
what `api/main.py` calls, so the serving path uses *this* code rather than a
re-implementation that would drift on the first one-sided bug fix.

### 8.4 `command_profile.py` — vocabulary rarity

Every pre-existing command feature measures **shape** (how many, how long, how
varied). None looks at **which** commands were typed — a session of ten identical
commands scores the same whether they are `ls` or `cat /etc/shadow`. That gap is
why the forest could not see the attacks the keyword rules miss.

Five columns, two mechanisms:

| Column | Mechanism |
|---|---|
| `cmd_oov_rate` | share of commands never seen in the profile |
| `cmd_mean_surprisal` / `cmd_max_surprisal` | −log₂ p(command) under the benign distribution |
| `cmd_mean_novelty` / `cmd_max_novelty` | `1 − cosine` to the nearest profile command over character n-grams, so a near-miss of routine behaviour is not treated like a genuinely novel command |

Two design decisions, both forced by measurement:

- **Global, not per-persona.** Per-persona would be better security (`tcpdump` is
  routine for infra, odd for a DBA) but `persona` is NaN on all 49 real attack
  sessions, so the profile could not be selected at scoring time for exactly the
  sessions being hunted. Per-user degenerates identically (one real login user).
  Revisit when AD lands.
- **Cross-fitted** (`add_rarity_features_crossfit`, K-fold). Any statistic derived
  from the target population is cross-fitted. See §9 leak #1.

Coverage measured *before* building, as a precondition — if the generated and real
benign vocabularies differed systematically, `oov_rate` would measure "this data
is real":

| | coverage by the generated profile |
|---|---|
| real **benign** vocabulary | **98.7 %** |
| real **attack** vocabulary | **61.5 %** |

### 8.5 `dataset_generation/` — the generated substrate

Pipeline order:

```
1. curate_atomic_redteam.py ─┐
   curate_gtfobins.py        ├→ attack_commands_curated.json   (256 commands, 6 tactics)
   curate_linux_commands.py ─┘→ persona_commands_curated.json  (benign, per persona)
2. build_calibration.py       → real_benign_calibration.json   (joins real GT↔sessions by TAG)
3. build_persona_weights.py   → persona_weighted.json          (real-anchored head + curated tail)
4. fit_generator.py           → metadata/generator_params.json (fits the three knobs)
5. generate_benign.py         → out/generated_benign.jsonl
   generate_attacks.py        → out/generated_attacks.jsonl
6. build_training_set.py      → out/generated_train.jsonl      (85:15, shuffled)
7. transform.py --in generated_train.jsonl --out features_train.csv
```

**The three generator knobs**, all fitted by bisection against real benign:

| Knob | Controls | Fitted value |
|---|---|---|
| `stickiness` | P(re-use a command already issued this session) → `unique_command_ratio` | **0.2912** |
| `length_tilt` | exponential tilting `w_i → w_i·exp(β·z(len_i))` → `avg_command_length`. The max-entropy way to move a distribution's mean under a constraint — of all reweightings hitting the target, it distorts the original shape least | **+0.2091** |
| `arg_variation` | resamples paths/filenames/small integers on a fresh draw, leaving program and flags exactly as curated → **opens the vocabulary** | **0.0256** |

Fit residuals (`generator_params.json`, seed 42, 500 samples/persona):

| Statistic | real target | fitted | gap (target sd) |
|---|---|---|---|
| `avg_command_length` | 21.123 | 20.955 | −0.024 |
| `unique_command_ratio` | 0.7353 | 0.7358 | +0.003 |
| `command_count` | 8.90 | 8.51 | −0.133 |
| `cmd_oov_rate` | 0.0140 | 0.0141 | — |

Per-persona family KL ≤ 0.028 bits (dev 0.0277, auditor 0.0229, dba 0.0154,
admin 0.0116) — the family mix is preserved by the reweighting.

**`command_safety.py` is the single definition** of an executable command,
imported by the collector (SAFETY — it executes as root) *and* by
`build_persona_weights.py` (PARITY — a command the collector cannot emit must not
be in the generated vocabulary, or the gap itself becomes a domain marker). It
blocks state mutation and non-terminating commands (`free -s 1`, `tail -f`,
`ping` without `-c`), which would otherwise hang a session and silently truncate
collection. **1 669 of ~3 200 commands rejected.**

**Synthetic metadata layer** (`identity_pool.json`): 16 users over 4 personas
(dev×6, auditor×4, dba×3, admin×3 — uneven, mirroring real orgs and stressing
cold-start), 20 targets with group + criticality + protocol, target affinity,
roaming modes, privileged accounts, 3 anomaly-IP modes.

Governing rule: **every synthetic attribute is anchored to an identity's own
history; an anomaly is a deviation from THAT identity's baseline, never a
globally-unseen value.** Consequences:

- IP scheme is a proposed RFC1918 layout (per-team `10.20.X.0/24`, VPN
  `10.99.0.0/16`, jump `10.30.0.0/24`), swappable for a real pool without
  touching generator logic.
- **~70 % of attack sessions originate from the actor's own home IP; ~10 % of
  benign sessions roam.** Real insiders work from their own laptop; without this
  symmetry `client_ip` alone solves the task.
- The strongest IP anomaly is the **wrong-team subnet** — a known-good
  workstation address attached to the wrong identity — which is why IPs are not
  randomly assigned.
- Protocol is a property of the *host* (Linux→SSH, Windows→RDP), so protocol
  diversity falls out of target affinity.
- Admins carry an **on-call rotation**: 03:00 is normal for the admin on call
  that week, anomalous for anyone else. This is what makes `session_hour_zscore`
  earn its place over a flat `off_hours_flag`.

**What `generate_attacks.py` deliberately does NOT do** — every incidental
difference is a shortcut the model takes instead of learning behaviour:

- Attack commands are **not** filtered to those matching `RISK_KEYWORDS`. That
  would make `flag_*` a near-perfect label and the model would re-learn the
  rules. Measured: 59 % of generated attack sessions trip ≥1 flag vs 65 % of real
  collected attacks.
- Attacks are **not** always off-hours (46 %), always foreign-IP (30 %), or always
  privileged-account (4 %, same as benign).
- Benign filler inside attack sessions is drawn from the **same**
  `persona_weighted.json` with the **same** knobs — different knobs would make the
  filler itself separate the classes.
- Single-feature AUC on the training set stays **≤ 0.73** for every model input.
- Five diversity axes, all recorded per row for sliced evaluation: composition
  (83 % buried / 17 % burst), persona, temporal spread, low-and-slow campaigns
  (~20 %), intensity (1–6 attack commands).

### 8.6 `ml/` — the four-model bake-off

**`feature_gate.py` — two filters, in order.**

1. **Leak gate** (static). Columns that would hand the model its own label, each
   one measured, not judged: `persona` (NaN on all 49 real attacks, populated on
   all 207 benign), `account` (`p_admin` 100 % attack, `bastionsvc` 100 % benign
   on real eval — a collection artifact), `ip_source` (one-sided by
   construction), `target_group`/`target_criticality` (criticality is the
   *impact* weight in `risk = anomaly × impact`, applied after scoring),
   `composition`/`attack_command_count`/`campaign_id`/`mitre`/`tactics`
   (evaluation slices), `real_*`/`*_is_synthetic`/`source`/`split`/`label`.
2. **Domain gate** (dynamic). Keep a column only if it varies in **both** the
   training and evaluation set, via a two-sample KS between generated benign and
   real benign. A feature whose benign distribution differs across domains is a
   domain marker — the detector would flag sessions for *being real*. On real
   eval, 5 of 14 candidate features are literally constant and 4 more take two
   distinct values across 256 sessions.
3. **`reference_class_gate`** (added 2026-08-15). Drops any column constant
   **within the training benign class**, with float tolerance `FLAT_ABS_TOL =
   1e-9` — the novelty columns are `1.55e-16`, not `0.0`, so an exact `nunique`
   test passes them. **Standing rule, now enforced in code: a feature that does
   not vary within the reference class is not a feature.**

**`evaluation.py` — one scoring report, three slices, always together.** Every
model is scored by this module so a difference in the numbers can never be a
difference in how they were measured.

| Slice | n | attacks | Why |
|---|---|---|---|
| headline | 256 | 49 | everything |
| clean (minus `p_admin`) | 234 | 27 | `p_admin` is 100 % attack — a collection artifact; any model scoring `p_admin` high gets 22 attacks free |
| **flagless** | 223 | 16 | attacks tripping **no** keyword flag — invisible to `wallix_rules.xml` by construction. **The population that justifies ML over the rule layer.** A model that wins the headline and loses here has not earned deployment |

At a 19.1 % base rate, calling everything benign scores 80.9 % accuracy — hence
**precision@k, not accuracy, not ROC-AUC.** Every model emits a score in a
different, incomparable unit (centroid distance, isolation depth, class
probability), so only the **ranking** is comparable; the 0.5-threshold confusion
matrix is context only.

**`persistence.py` — the bundle is the artifact, not the model.** Scoring needs
four things that must agree: `model`, `scaler` (fitted on training only),
`features` (the exact ordered column list — a different order silently scores the
wrong columns), and `command_profile` (the vocabulary the `cmd_*` features are
measured against). A model paired with the wrong profile is not broken, it is
*silently wrong* — so the profile is stored **inside** the bundle and
fingerprint-checked on load. The threshold rides along too, since re-deriving it
at serving time would let the alert rate drift with arriving traffic.

---

## 9. Measured findings — the discoveries that changed the design

### 9.1 (2026-08-07) Two collection artifacts found by measurement, not inspection

1. **`unique_command_ratio == 1.00` in every real session.** A session was a fixed
   list of distinct commands run once; real users repeat themselves. The domain
   gate rejected `unique_command_ratio` (KS 0.94) and `command_entropy` (KS 0.69)
   — a model trained on generated benign would have flagged every real session
   *for being real*.
2. **An attack session was 100 % attack commands**, so `avg_command_length` alone
   scored AUC 0.832 — the detector was reading "long command", not behaviour.
   `recon` (avg 14.3 chars) was indistinguishable from benign and went undetected.

**Decision: fix the COLLECTOR, never calibrate the generator to match a scripting
artifact.** Effect: the benign/attack gap in `avg_command_length` fell from 25.5
chars to 1.9, `unique_command_ratio` from 1.00 to ~0.77, and all 5 candidate
features passed the domain gate (previously 3 of 5).

**The domain gate's blind spot, documented deliberately:** it compares benign to
benign only, so it cannot see contamination of the ATTACK class. This bit once —
after fixing the benign side, 45 of 58 eval attacks were still pre-fix and the
reported numbers were computed on a 78 %-artifact attack class. Hence
`build_eval_set.py --composed-only`.

**Leakage caveat for the report:** the gate reads the eval set's benign labels.
Accepted because the alternative (shipping known domain markers) is worse, and
the gate is blind to the attack class it scores on. With more real benign, hold
out a calibration slice instead.

### 9.2 (2026-08-07) The safety incident

A collected session executed `mv /usr/local/bin/* /opt/bin/` **as root** on
debian-lab. No damage — only because `/usr/local/bin` was empty. Root cause:
`curate_linux_commands.py` filtered the public corpus against `wallix_rules.xml`
but never against *destructiveness*, and the `_COMMANDS_DIR` path had been stale
since the restructure (silently loading nothing), so the corpus had never been
exercised until the path was fixed. → `command_safety.py`.

### 9.3 (2026-08-15) The decoder was truncating commands at the first escaped quote

Found while checking whether a rarity feature was viable: 21 % of the real
distinct vocabulary consisted of fragments ending in a backslash.

```
captured: (crontab -l 2>/dev/null; echo \
actual:   (crontab -l 2>/dev/null; echo \"*/5 * * * * /tmp/x.sh\") | crontab -
```

A persistence attack whose entire payload was discarded before it reached the
rules *or* the features. **244 of 7 506 KBD_INPUT events (3.3 % of events but
21 % of the distinct vocabulary** — quoted `awk`/`find`/`echo` one-liners are
exactly the long distinctive commands) and **129 of the 256 eval sessions**.

- **Decoder fix:** identity fields keep the cheap `[^"]*`; free-text fields
  (`data=`, `command_line=`) use escape-aware `((?:[^"\\]|\\.)*)`. Validated
  against all 3 835 real KBD_INPUT lines: identical match count, exactly the 244
  corrected. Deployed and confirmed via `wazuh-logtest`.
- **Repair path:** `full_log` preserved the complete line, so
  `extract.py:repair_command()` recovered all 244 offline — **no sessions had to
  be re-collected**, which matters because real sessions *cannot* be re-collected.
  It substitutes only when the recovered value *extends* the decoder's, so a
  correct decode is never overwritten. **Any future decoder fix needs a repair
  path, not just a forward fix.**
- **Calibration consequence:** `avg_command_length` had been fitted to 19.76 from
  truncated commands; the repaired value is **21.12** — the generator was
  calibrated 5 % short on the strongest single feature. Everything regenerated.
- **All measurements taken before 2026-08-15 used corrupted commands.** The
  2026-08-09 log's *reasoning* holds; its *numbers* are superseded.

### 9.4 (2026-08-15) Leak #1 — the profile was fitted on the rows it scored

Every training benign command is in the profile by construction, so
`cmd_oov_rate` was **exactly 0.0000 for all 5 000 rows** — a perfect label.
Symptoms: 5-fold CV PR-AUC **1.0000 ± 0.0000**; real eval collapsed to **8
distinct scores** with **64 sessions tied at 1.0**, including all 49 attacks. The
"precision@10 = 0.90" this produced was a coin flip inside the tie.

K-fold cross-fitting was applied — and **did not fix it**, which was the useful
finding: the generator drew from a **closed** vocabulary of 850 command types
sampled 42 000 times, so holding out 20 % of *sessions* still leaves every command
*type* in the profile. Cross-fitting is correct and retained; it is just not
sufficient alone.

### 9.5 (2026-08-15) Leak #2 — a feature can be constant within one class only

→ `reference_class_gate` (§8.6). The whole-column domain gate cannot see this: the
column varies across the training set (attacks differ) and varies in eval. Only
the within-benign view exposes that the separator was *handed* to the model
rather than learned.

### 9.6 (2026-08-15) The generated benign vocabulary must be OPEN

Dropping the degenerate columns left `cmd_max_surprisal`, which still separated
training perfectly (unseen ⇒ exactly 16.379; generated benign never exceeded
10.5). The model was learning "an unseen command is present", not a threshold.

**Novelty is generated as varied ARGUMENTS, not novel programs** — which is how
real novelty actually arises (real benign runs `grep` constantly and
`grep cron /etc/rsyslog.d/50-default.conf` once). `vary_arguments` resamples
paths, filenames and small integers from large pools while leaving the program
and its flags exactly as curated, so `command_safety`'s guarantees are untouched
(no new head, no redirection). Result: generated benign OOV **0.0132** vs real
benign **0.0140**.

**Two traps recorded:**

- **The OOV target is sample-size dependent.** The same `arg_variation` gives
  4.9 % OOV at 150 sessions/persona and **0 %** at 1 250, because a thin profile
  shows novelty a thick one absorbs. `--oov-samples` must match `--per-persona`.
- **22.5 % ≠ 1.4 %.** Real benign scored out-of-fold against *other real benign*
  (165 sessions) gives 22.5 %; against the *deployed generated profile* (5 000
  sessions) gives 1.4 %. Only the second is the right target — both classes must
  be scored against the same profile.

### 9.7 The ablation that carries the report

Random Forest, fitted on generated (5 882 rows, 85:15), judged on the 256 real
sessions. Same repaired data throughout; only the feature set differs.

| | shape features only | + rarity, closed vocab | **+ rarity, open vocab** |
|---|---|---|---|
| Real PR-AUC | 0.417 | 0.782 | **0.921** |
| Real ROC-AUC | 0.656 | 0.956 | **0.982** |
| precision@10 | 0.70 | 0.80 | **1.00** |
| precision@25 | 0.68 | 0.72 | **0.92** |
| clean (minus `p_admin`) PR-AUC | 0.364 | 0.749 | **0.892** |
| Domain gap (generated → real) | 0.288 | 0.218 | **0.079** |
| **Flagless-16 ROC-AUC** | **0.502** | 0.944 | **0.963** |
| Flagless ranks in the 256 queue | scattered to 245 | top 66 | **top 64** |

**The thesis question is answered affirmatively.** The 16 real attacks carrying no
keyword flag — invisible to `wallix_rules.xml` by construction — went from
indistinguishable from random (0.502) to 0.963, all inside the top 64 of 256. The
rule layer scores precision 0.97 / recall 0.67 on the attacks it *can* see and
**0** on these.

Permutation importance on real data: `cmd_max_surprisal` 0.395, `cmd_max_novelty`
0.121, `cmd_mean_novelty` 0.106, `cmd_oov_rate` 0.062, `cmd_mean_surprisal`
0.054. **Every shape feature is ≤ 0.008**, and `command_entropy` (−0.003) and
`command_count` (−0.011) are still mildly harmful.

---

## 10. Current results — the four-model bake-off

`ml/results_all.csv`, evaluated on 256 real sessions, 49 attacks, base rate
19.1 %. Random ranker = 0.191 at every k.

| track | model | headline PR-AUC | P@10 | P@25 | clean PR-AUC | flagless ROC-AUC | flagless P@25 | flagless worst rank | domain gap |
|---|---|---|---|---|---|---|---|---|---|
| supervised | **LightGBM** | **0.973** | 1.00 | 1.00 | **0.940** | **0.987** | **0.64** | **56** | 0.027 |
| unsupervised | **IsolationForest** | 0.964 | 1.00 | 1.00 | 0.921 | 0.986 | 0.56 | 64 | — |
| supervised | RandomForest | 0.921 | 1.00 | 0.92 | 0.892 | 0.963 | 0.44 | 64 | 0.079 |
| unsupervised | KMeans | 0.893 | 1.00 | 0.96 | 0.812 | 0.909 | 0.52 | 146 | — |

**The two tracks are NOT interchangeable at equal score.** The supervised pair
trains on synthetic attacks, and 0 of 882 of those contain no unseen command, so
part of what they learn is that *the attack corpus is a different corpus*. The
unsupervised pair never sees an attack. **Prefer the unsupervised model on a tie,
and say why in the report.**

Supervised control PR-AUC on the generated holdout is **1.0000** for both models
— the domain gap (holdout minus real) is the number that matters, and it has
already caught two real defects (generator miscalibration from truncated data,
and the closed benign vocabulary), neither visible in the headline alone.

`class_weight` / `is_unbalance` rather than SMOTE: at 85:15 the imbalance is
mild, and re-weighting the loss does the same job without synthesising
feature-space points that correspond to no session that could exist.

**Directionality — a known, deliberate imprecision.** Both unsupervised detectors
measure distance from normal in *every* direction, but only the upper tail is
suspicious here. A session that is *more* routine than routine — short,
repetitive, entirely familiar — is a scripted maintenance job, and both models
will spend part of the alert budget on it. ECOD/COPOD allow one-sided scoring and
would fix this; out of scope for this comparison. Recorded, not worked around.

### The earlier (superseded) PyOD bake-off — 2026-08-07

Retained because two of its lessons stand independent of the numbers:

| model | ROC-AUC | P@25 | P@50 | R@50 |
|---|---|---|---|---|
| PCA | 0.778 | **0.72** | **0.60** | 0.61 |
| MAD (baseline) | **0.798** | 0.68 | 0.48 | 0.49 |
| IForest | 0.775 | 0.60 | 0.52 | 0.53 |
| ECOD | 0.755 | 0.56 | 0.54 | 0.55 |
| HBOS | 0.749 | 0.44 | 0.48 | 0.49 |
| COPOD | 0.719 | 0.36 | 0.42 | 0.43 |

- **MAD wins ROC-AUC but loses precision@k.** The two metrics disagree and the
  one the SOC actually feels is precision@k — concrete support for the standing
  decision.
- **Before the collection fix, HBOS led at 0.862.** That advantage was the
  artifact, not learning. Worth stating plainly.
- **Recall by attack composition (PCA @k=50): `full` 0.92 · `diluted` 0.67 ·
  `minimal` 0.27.** `minimal` sessions average 19.3 chars vs 19.1 for benign —
  indistinguishable on every shape feature available. **The detector catches the
  loud case and misses the realistic one.** Report as a measured limit, not a
  tuning failure. (The rarity features are what later closed most of this gap.)

### Figures — `visualisation/`

Regenerated by `python visualisation/plot_unsupervised.py`, which **re-reads the
artifacts `ml/unsupervised/train.py` wrote and recomputes nothing**, so figures
cannot diverge from the reported numbers. Each emits PNG (300 dpi, slides) + PDF
(vector, `\includegraphics`). Light mode only — print figures, not a themeable
web page. Palette validated: blue `#2a78d6` / orange `#eb6834`, ΔE CVD 24.7,
normal 33.6, contrast ≥ 3:1.

| Figure | Shows | Form |
|---|---|---|
| `fig1_precision_at_k` | 6 detectors across the alert budget + random line | Emphasis: PCA and MAD in colour, the other 4 grey |
| `fig2_recall_by_composition` | **The central figure.** Recall by attack stealth, Wilson 95 % CI | Bars, one hue ramping dark→light as the attack gets stealthier |
| `fig3_domain_gate` | Per-feature KS before/after the collection fix | Dumbbell |
| `fig4_score_distribution` | Every session's PCA score by class + top-50 threshold | Strip plot — n=256 is small enough to show *every* session, and the overlap is precisely the result |
| `fig5_recall_by_tactic` | Recall by MITRE tactic | Bars, sequential hue |

Reading notes: in fig. 1 the two curves **cross** (MAD better at small *k*, PCA at
medium *k*) — that crossing *is* the empirical argument for precision@k over
ROC-AUC; do not smooth it. In fig. 3 `command_count` **rises** (0.041 → 0.131),
which is honest and expected: the fix changed the real benign distribution, so the
initially-perfect agreement degraded slightly while staying far below threshold.

---

## 11. The API service (`api/`, uncommitted)

```
POST /score    sessions (sessions.jsonl shape) -> ranked anomaly scores
GET  /model    which bundle is loaded, and what it scored when it was built
GET  /health   liveness
```

- **Features are computed by `transform.py`, not re-implemented.** A serving-side
  copy is the classic source of train/serve skew — identical at birth, divergent
  on the first one-sided bug fix. Consequence: the image ships
  `feature_extraction/` and `ml/`, not just a pickle. That is the correct trade —
  the model is not the artifact, the *(model + scaler + feature order + command
  profile)* bundle is, and the code producing those features is part of the
  contract.
- **Stateless by design.** Cross-session features are computed within the
  request's own batch, so they are only meaningful when a caller sends a user's
  sessions together. Those columns are gated out of the deployed feature set
  anyway (constant on real lab telemetry). When they matter they need a state
  store, and that belongs outside this service.
- **NaN is a refusal, not an imputation.** A protocol carrying no command
  telemetry (RDP) returns HTTP 422 — an imputed 0 would score as "perfectly
  ordinary".
- **No authentication.** `auth.py` (RBAC) is Security-owned and unbuilt. The
  compose file publishes **no** ports by default beyond a `127.0.0.1:8000`
  local-demo binding; `/score` returns privileged session content and must not be
  exposed. It joins the Wazuh stack's network as `external` (`single-node_default`)
  rather than redefining it.
- Default bundle: `ml/bundles/isolationforest.joblib`, overridable via
  `BUNDLE_PATH`. The bundle is **baked into the image** — image and model as one
  immutable, traceable artifact. `libgomp1` is installed explicitly (LightGBM's
  OpenMP runtime; absent from `python:3.12-slim`, and its absence fails at
  *import* time, not build time). Runs as uid 10001, non-root, with a HEALTHCHECK.

---

## 12. ML methodology — points to defend in the report

Reference: Chamkar et al., *"Improving Threat Detection in Wazuh Using ML
Techniques"* (J. Cybersecur. Priv. 2025) — hybrid RF + DBSCAN, structure adopted
as a template.

- **Metric: precision@k** (k = the SOC alert budget), **not** ROC-AUC, and never
  accuracy at a 19.1 % base rate.
- **DBSCAN excluded from deployment** — no `predict` method.
- Isolation Forest's underperformance in Chamkar et al. is dataset-specific —
  kept, and it is the strongest unsupervised model here.
- Comparable papers' ML mostly **re-ranks rule output**; this feature set
  (command rarity, entropy, z-scores) is meaningfully different, which is exactly
  the objection the rarity features were built to answer.
- **Risk ≠ anomaly.** `risk = anomaly score × impact weight`; impact needs a
  Security-owned asset-criticality CSV that WALLIX cannot supply.
  `target_criticality` is therefore evaluation metadata, applied after scoring,
  never a model input.
- **Train/serve skew:** truncate historical sessions at multiple horizons
  (t+60/300/900/final) during snapshot generation.
- **Rules vs ML scope:** rules = binary policy violations; ML = behavioural
  patterns. Don't duplicate — off-hours belongs in ML features, not a Wazuh
  `<time>` rule.
- **`rule_id`/`rule_level` are EVALUATION metadata, never model input.** Feeding
  rule output into a model sourced from alerts is circular.
- Peer-group / cohort baselines for cold-start.
- **What NOT to do:** add more PyOD models (the best barely beats a z-score — the
  leverage is in features, not algorithms); tune thresholds to improve the
  numbers ("tuned ML beat untuned rules" is the easiest attack in a defence);
  start the RAG before the rule comparison exists.

---

## 13. Honest lab constraints — documented, not engineered away

- **Two target hosts** → no real lateral movement. Don't synthesise fake lateral
  movement.
- **Effectively one real source IP, one login user, one collection window** →
  `session_hour_zscore`, `new_source_ip_for_user`, `distinct_targets_24h` can
  **never** pass the domain gate on this lab; their real distribution is
  degenerate. And these are exactly the features that would address the
  `minimal`-composition miss, since two buried commands do not change a session's
  shape — only its context.
  - **Option A** — implement them and evaluate on a held-out *generated* set,
    clearly labelled as a separate experiment, never the main evidence.
  - **Option B** — implement them and document them as unevaluable in this lab;
    "future work".
  - Either way the headline result stays Pool A/B + the rule comparison, measured
    on **real** data.
- **5 real accounts stand in for personas** → per-user baselines are really
  per-persona baselines. A genuine external-validity limit, not something more
  collection fixes.
- **Semi-synthetic dataset** → must be documented as such in the report.
- **Training is still perfectly separable** (CV PR-AUC 1.0000). The attack corpus
  (Atomic/GTFOBins) is *disjoint* from the benign corpus, so 0 of 882 generated
  attacks have `cmd_oov_rate == 0`. Real attacks are far more varied (OOV
  quartiles 0.071 / 0.286 / 0.444 / 0.75 / 1.0 vs generated 0.067 / 0.10 / 0.154
  / 0.25 / 0.857). **The generator cannot yet produce a living-off-the-land
  attack** — one built entirely from ordinary commands. That is the next realism
  gap, and it is exactly what the hardest real insider case looks like.
- **Residual error is false positives, not misses.** No real attack scores below
  0.90; the ranking cost comes from benign sessions scoring high.
- **`command_entropy` sign inversion persists** — generated attacks sit *above*
  benign, real attacks *below*. Harmful in permutation importance.
- **Benign templates should be re-collected** with varied, repetitive sequences
  before diversity is calibrated empirically rather than by the current
  documented judgement call.

---

## 14. Security posture

- `feature_extraction/out/` contains **real** session telemetry. Some attack
  scenarios can echo credentials into keystroke data.
- **Sessions run under `p_admin`/`svc-debian` (root) must NEVER be fed raw into
  the RAG vector DB.** That is what the sanitised-summary guardrail (`load.py`,
  unbuilt) is for: dual-write a sanitised natural-language summary per session,
  never raw commands, gated by a `rag_indexable` schema flag.
- The indexer connection **disables TLS verification** for the lab's self-signed
  cert. Do not carry that into production.
- Stock demo credentials are still in use across the stack (`SecretPassword`,
  `MyS3cr37P450r.*-`, `kibanaserver`) — production-hardening checklist item.
- `CLAUDE.md` is local-only and deliberately **not** committed (it holds lab
  credentials); it was removed from the repo in commit `1c26589`.
- The privesc scenario writes a temp sudoers entry rather than answering a live
  sudo prompt, so no real secret should appear in that scenario's telemetry.
- **AD integration is DEFERRED** (a Domain Controller VM = +4 GB RAM; host
  resources are tight). It does *not* need a VM per user — users are identities,
  not machines. When added: enable `Log group membership` in the WALLIX
  connection policy so AD group flows through the same syslog path, and add a
  `group` field to decoder + schema + `FIELD_MAP`. Real AD names become personal
  data → strengthens the RAG sanitisation and retention requirements. It would
  also unlock genuine per-user baselines, authentic personas, real
  `role_command_mismatch`, and a per-persona command profile.

---

## 15. Schema contract

12 minimum fields: `session_id` (join key), `user`, `account` (the borrowed
privileged identity — distinct from `user`), `target_ip`, `target_hostname`,
`protocol`, `client_ip`, `session_start`, `duration` (H:MM:SS on
`SESSION_DISCONNECTION`), `event_type`, `command`/`command_line`,
`file_transfer_bytes`. Plus `rag_indexable`.

**Naming drift, still unresolved:** `extract.py` emits
`client_ip`/`target_hostname`/`event_type`; the original feature list says
`source_ip`/`target_name`. Lock the names in `schema/schema_contract.yaml` (dual
sign-off to edit) — that file does not exist yet.

**Known limitation:** WALLIX forwards only `KBD_INPUT`, not session open/close
lifecycle events, so `session_start`/`session_end`/`duration_sec` are best-effort
estimates from per-session min/max timestamps, flagged via `*_is_estimated`.

---

## 16. Runbook

```powershell
# 0. Dependencies
python -m venv venv; venv\Scripts\activate
pip install -r requirements.txt

# 1. COLLECT — real sessions through the Bastion  (LAB MUST BE RUNNING)
python feature_extraction\simulate_sessions.py --attacks all --repeat 6 --benign 120 `
       --attack-accounts p_admin,p_dev,p_dba,p_audit
python feature_extraction\extract.py --source indexer --since 2h --index archives `
       --out-dir feature_extraction\out

# 2. GENERATED SIDE — RERUN AFTER EVERY NEW COLLECTION (calibration moves)
cd dataset_generation
python build_calibration.py
python build_persona_weights.py
python metadata\build_identity_pool.py
python metadata\build_calibration_slice.py
python fit_generator.py --oov-samples 1250        # MUST match --per-persona below
python generate_benign.py  --per-persona 1250      # 5000 benign
python generate_attacks.py --benign-count 5000     #  882 attacks (15%)
python build_training_set.py                       # 5882 rows
cd ..

# 3. FEATURES — both sides, same code
python feature_extraction\transform.py --in dataset_generation\out\generated_train.jsonl `
       --out feature_extraction\out\features_train.csv
python feature_extraction\transform.py --in feature_extraction\out\eval_real.jsonl `
       --out feature_extraction\out\features_eval_real.csv --no-split

# 4. TRAIN + EVALUATE + COMPARE
python ml\unsupervised\train.py --k 5,10,25,50
python ml\supervised\train.py
python ml\compare.py                               # -> ml\results_all.csv
python visualisation\plot_unsupervised.py          # -> figures

# 5. SCORE / SERVE
python ml\score.py --sessions feature_extraction\out\eval_real.jsonl `
       --bundle ml\bundles\isolationforest.joblib --top 10
docker compose -f api\docker-compose.yml up -d --build
```

**Trap:** after any new collection you *must* redo step 2. Real benign changes, so
the generator's calibration goes stale and the gap reappears as a domain marker.

**Trap:** if you change `--per-persona`, re-fit with a matching `--oov-samples`
(§9.6).

### Packaging the Wazuh environment for a teammate

Image tarballs are the wrong thing to share — they're vanilla Wazuh. Ship compose
+ `config/` (which holds `ossec.conf`, certs, and the bind-mounted
decoder/rules):

```powershell
Compress-Archive -Path .\docker-compose.yml, .\config -DestinationPath wazuh-setup.zip -Force
```

The recipient runs `docker compose up -d`; images pull from Docker Hub.

---

## 17. Uncommitted work in the tree (as of 2026-08-16)

| Path | State |
|---|---|
| `api/` | **untracked** — FastAPI service, Dockerfile, compose |
| `.dockerignore` | untracked |
| `feature_extraction/out/live/` | untracked, empty |
| `pam_anomaly_detection_conversation.md` | untracked working transcript |
| `feature_extraction/simulate_sessions.py` | modified — account map `bastionsvc`→`svc-debian`; second-password prompt now **detected** rather than predicted |
| `feature_extraction/transform.py` | modified — `build_features_from_sessions()` split out for the serving path |
| `feature_extraction/out/ground_truth.jsonl` | +10 sessions |

Branch `command-rarity-features` is ahead of `Main`.

---

## 18. Next steps, in priority order

| # | Work | Unblocks |
|---|---|---|
| **1** | **`rule_baseline.py`** — Pool A/B split, replay the rule layer over the eval set, 2×2 matrix, McNemar test | **The thesis itself.** Without it there is an ML model with no comparison point |
| **2** | **More `minimal` sessions** (`--bury-rate 0.95`, target 50–60) | Tightens the composition-recall CI from ±0.27 to ±0.12 → a publishable number. Machine time, not development time |
| **3** | **Per-user TIMELINES in `generate_benign.py`** — attacks *inserted into* an existing timeline, not sampled independently | Every 24 h-window feature (`sessions_count_24h`, `distinct_targets_24h`, `distinct_source_ips_24h`, `concurrent_sessions`), currently meaningless |
| **4** | **Contextual features in `transform.py`** | The only credible lever on the `minimal` case. ⚠️ unevaluable on real data (§13) → treat as a separately labelled experiment |
| **5** | **Leakage audit** — train a classifier on metadata-only features; report metadata-only vs metadata+behaviour | Pre-empts the obvious defence objection that semi-synthetic labels are self-fulfilling |
| **6** | **Living-off-the-land attack generation** — attack sessions built entirely from ordinary commands | Closes the "training is perfectly separable" gap; the hardest real insider case |
| **7** | **Trim `99-wazuh-forward.conf`** | Stops appliance OS noise polluting features |
| **8** | **Verify the RDP decoder** against a real `rdpproxy` line | RDP protocol coverage |
| **9** | **FTP infra** — WALLIX connection policy + target server, then an `ftpproxy` decoder branch built from a real captured line | FTP protocol coverage |
| **10** | **Confirm the Docker Desktop bind-mount fix is durable** (§5 item 10) | The current fix lives only inside the running container |
| **11** | **`schema/schema_contract.yaml`** — lock `client_ip` vs `source_ip` naming | Stops silent drift between pipeline stages |
| **12** | **RAG + dashboard** — Qdrant, two collections (`soc_policies` static/Security-curated; `session_history` sanitised summaries only), LangChain RetrievalQA with citations, `/ask` endpoint + audit log, `auth.py` RBAC | Final phase — **not before the rule comparison exists** |

---

## 19. Deliverables produced so far

- `infra/wazuh/wallix_decoder.xml`, `wallix_rules.xml` — installed and verified
  live.
- `feature_extraction/`: `simulate_sessions.py`, `extract.py`, `extract_raw.py`,
  `transform.py`, `command_profile.py` + `README_simulate_sessions.md`.
- `dataset_generation/`: full curate → calibrate → fit → generate → merge chain,
  `command_safety.py`, identity pool, calibration slice, generator params.
- `ml/`: `feature_gate.py`, `evaluation.py`, `persistence.py`, `score.py`,
  `compare.py`, both training tracks, 4 saved bundles, 3 results CSVs.
- `api/`: FastAPI scoring service + Dockerfile + compose (uncommitted).
- `visualisation/`: 5 figures in PNG + PDF, regenerable from training artifacts.
- `docs/`: `decision_log.md`, `GUIDE_PROJET_FR.md`, `GUIDE_VISUEL_FR.pdf`,
  `RAPPORT_ETAPES.pdf`, two dated session logs.
- Earlier artifacts: `WALLIX_Insider_Threat_Guide.pdf`, Team Implementation Guide
  (PDF), Workflow Architecture Diagram (PDF/Graphviz),
  `HPS_implementation_report.tex` (FR), `session_generator.py`,
  `rdp_session_churn.sh`, `rdp_attack_actions.ps1`,
  `wallix_session_features.xlsx`. Screenshots in Drive ("HPS-project",
  "claude-screens").
- French *état d'avancement* email drafted.

**Superseded / never built:** `ssh_attack.sh` / `rdp_attack.sh` (bash+expect —
`expect`/`sshpass` are unavailable in this environment; replaced by
`simulate_sessions.py`); `ml/unsupervised/Kmeans.py`, an earlier standalone
KMeans exploration, was removed on 2026-08-16 — `ml/unsupervised/train.py` runs
KMeans and IsolationForest through the shared `ml/evaluation.py`, so the
standalone version measured the same model by different code (recoverable from
git history if ever needed).
