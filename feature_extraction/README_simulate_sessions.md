# simulate_sessions.py

Drives real SSH sessions through the WALLIX Bastion to collect Phase-1 dataset
templates (see `claude.md` §10): 6 attack scenarios + persona-based benign
sessions, tagged and logged to `ground_truth.jsonl`, ready for `extract.py` to
pull into `events.jsonl`/`sessions.jsonl`.

This script does no synthesis — every command actually executes on
`debian-lab` through the Bastion. It only produces **templates**; the later
`generate_from_template.py` (not built yet) is what creates the large
semi-synthetic training set.

## Usage

```powershell
python simulate_sessions.py --list                                # show scenarios/personas
python simulate_sessions.py --dry-run --attacks all --benign 3     # preview, no connection
python simulate_sessions.py --attacks all --benign 10              # one rep each + 10 benign
python simulate_sessions.py --attacks recon,privesc --benign 0     # narrow run
python simulate_sessions.py --attacks all --repeat 2 --benign 40 --verbose
```

| Flag | Meaning |
|---|---|
| `--attacks` | comma-separated scenario names, `all`, or `none` |
| `--benign N` | number of benign sessions (spread round-robin across personas) |
| `--repeat N` | repeat each attack scenario N times |
| `--dry-run` | print resolved commands, don't touch the lab |
| `--verbose` | echo each command as it's sent |
| `--list` | print scenarios/personas and exit |

## What's randomized per run, what isn't

**Randomized:**
- session order (`random.shuffle(plan)`)
- session tag (`uuid.uuid4().hex[:6]`)
- inter-command pacing (`random.uniform(0.4, 1.3)` seconds)

**Fixed / NOT randomized:**
- the command list per scenario/persona — identical commands, identical order,
  every rep. Command-level diversity is intentionally deferred to
  `generate_from_template.py` (composition/intensity axes) for training data,
  and should be added by hand for the isolated `eval_real` set since that one
  *is* scored directly, not resynthesized.

## Accounts (real WALLIX vaulted accounts on debian-lab)

| Account | Role | Second password? |
|---|---|---|
| `p_admin` | root | yes — manual, `lab` |
| `p_dev` | plain sudoer, **not** NOPASSWD | no — auto-connects |
| `p_dba` | plain sudoer, **not** NOPASSWD | no — auto-connects |
| `p_audit` | plain sudoer, **not** NOPASSWD | no — auto-connects |
| `bastionsvc` | plain non-sudo test account | no — auto-connects |

Benign personas each use their own real account: `dev`→`p_dev`, `dba`→`p_dba`,
`auditor`→`p_audit`, `admin`→`bastionsvc`.

### Attacks through non-admin accounts (`--attack-accounts`)

Attack scenarios default to `p_admin`, but `--attack-accounts p_admin,p_dev,p_dba,p_audit`
rotates them round-robin across accounts (each `(scenario, repeat)` pair gets
the next account in the list). Root-only steps (`useradd`, `/etc/sudoers.d/`
edits, `/etc/shadow`, `auth.log`) are templated with a `{sudo}` placeholder
that resolves to `"sudo "` for every account except `p_admin` (already root,
so the prefix would be a harmless no-op there anyway).

`p_dev`/`p_dba`/`p_audit` turned out **not** to be NOPASSWD sudoers (verified
live: `sudo -l` prompted `[sudo] password for p_dev:`, and we don't have that
password — deliberately not guessing it, to avoid another lockout). Rather
than granting them sudo just to make the attack "succeed" (which would be
scripting the outcome, not discovering it), the driver treats the denial
itself as the signal: `SUDO_DENIED_RE` catches the mid-command password
prompt, sends Ctrl+C to cancel it, and keeps going. Each session's ground
truth records exactly which commands were denied and a `fail_ratio` —
this is real telemetry for the `fail_ratio`/`consecutive_failures` features
already planned in `claude.md` §9, and arguably a *more* realistic
insider-threat signal than a scripted success: a normal-role account
attempting something it has no rights to do.

If you do want some of these accounts to have limited real sudo rights later
(e.g. to model a "compromised admin with narrow legitimate privileges"
scenario rather than "unprivileged account probing"), add specific `visudo`
entries per account/command rather than broad NOPASSWD.

## Login flow this script automates

WALLIX's SSH login is two-step and interactive, which is why this uses
`paramiko.invoke_shell()` instead of a one-shot command:

1. Paramiko authenticates to the Bastion at the SSH protocol level
   (`test-ssh` + login password) — real SSH auth, not something typed into
   the channel.
2. Post-auth, WALLIX prints an account-selection menu (table of
   `ID | Site | Authorization`). The script regex-parses the menu
   (`MENU_ROW_RE`) to find the row matching the target account name and
   sends that row's ID.
3. Only `p_admin` then prompts a second, target-side password
   (`p_admin's password:`), answered with `lab`. The other accounts
   auto-connect straight to a shell.
4. Once the real shell prompt appears, the script sends
   `echo TAG:<session_tag>` first (so the tag lands in real `KBD_INPUT`
   telemetry), then each scenario command, then `exit`.

## Attack scenarios (rule IDs per `wallix_rules.xml`)

| Scenario | Rule ID | MITRE | Notes |
|---|---|---|---|
| `recon` | 100518 | T1082, T1087 | read-only |
| `cred_access` | 100510 | T1003, T1552 | read-only; `find` scoped to `/root /home /etc` and common bin dirs (unscoped `find /` timed out in testing) |
| `privesc` | 100512 | T1548, T1136 | create-then-delete temp user + sudoers entry |
| `persistence` | 100514 | T1053, T1098 | create-then-delete cron entry + drop script |
| `log_tamper` | 100516 | T1070, T1562 | read-only (`ls`/`cat`/`history -c`), no real log deletion |
| `exfil` | 100520 | T1048, T1041 | targets `127.0.0.1` only; `scp` uses `BatchMode=yes` so a missing key fails fast instead of hanging on a password prompt |

## Ground truth

Every session appends one line to `out/ground_truth.jsonl`:

```json
{"session_tag": "atk_privesc_b68d72", "kind": "attack", "scenario": "privesc",
 "expected_rule_ids": [100512], "mitre": ["T1548", "T1136"],
 "target_hostname": "debian-lab", "account": "p_dev", "protocol": "SSH",
 "started_at": "2026-08-03T12:43:44Z", "status": "ok", "error": null,
 "commands_denied": ["sudo -l", "sudo useradd -m tempuser_atk_privesc_b68d72", "..."],
 "fail_ratio": 0.833}
```

`status`/`error` record whether the session completed without a driver-side
timeout/exception — this is append-only and never rewritten, so failed
historical runs stay visible as an audit trail rather than being cleaned up.
`commands_denied`/`fail_ratio` record which commands hit a sudo password
prompt on non-admin accounts (see the `--attack-accounts` section above) —
real telemetry for the planned `fail_ratio` feature, distinct from a
driver-level `status: "error"`.

## Known lab constraints (don't try to fake around these — document them)

- Two target hosts only → no real lateral movement.
- Effectively one real source IP (this host) → source-IP diversity
  (`distinct_source_ips_24h`, `new_source_ip_for_user`, etc.) has to come from
  the synthetic metadata layer (Phase 2), not from these raw sessions.
- Only 5 real vaulted accounts stand in for personas → per-user baselines are
  really per-persona baselines; the model will learn these 5 signatures well,
  which is a genuine external-validity limitation worth stating in the report,
  not something more collection here fixes.

## Next steps after running this

```powershell
python extract.py --source indexer --since 1h --index alerts
```

Then join the resulting `sessions.jsonl` back to `ground_truth.jsonl` by
`session_tag`, and split into `templates.jsonl` (feeds
`generate_from_template.py`) vs. an isolated `eval_real.jsonl` (never trained
on — judges the model only).
