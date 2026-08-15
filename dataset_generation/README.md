# dataset_generation

Synthetic dataset building — the **generated-trains** side of the pipeline.
(The **real-judges** side — `simulate_sessions.py`, `extract.py`, `transform.py` —
lives in `../feature_extraction/`.)

## Pipeline order

```
1. curate_atomic_redteam.py   ─┐
   curate_gtfobins.py          ├─→ commands_dataset/attack_commands_curated.json   (attack content, 6 tactics)
                               ─┘
   curate_linux_commands.py    ──→ commands_dataset/persona_commands_curated.json  (benign content, per persona)

2. build_calibration.py        ──→ commands_dataset/real_benign_calibration.json
   (joins REAL ../feature_extraction/out/{ground_truth,sessions}.jsonl by the TAG marker)

3. build_persona_weights.py    ──→ commands_dataset/persona_weighted.json
   (real-anchored core + curated tail; --tail-mass diversity knob)

4. fit_generator.py            ──→ metadata/generator_params.json
   (fits --stickiness, --length-tilt and --arg-variation so synthetic benign
    sits where REAL benign sits; read as defaults by both generators below)

5. generate_benign.py          ──→ out/generated_benign.jsonl
   generate_attacks.py         ──→ out/generated_attacks.jsonl
   (samples the weighted vocab into sessions.jsonl-schema records.
    label/tactics/source/split/persona ride along.)

6. build_training_set.py       ──→ out/generated_train.jsonl
   (merges the two at the locked 85:15 benign:attack, shuffled)

   ../feature_extraction/transform.py --in out/generated_train.jsonl
                                      --out ../feature_extraction/out/features_train.csv
```

## The combined training set

```powershell
python generate_benign.py  --per-persona 1250          # 5000 benign
python generate_attacks.py --benign-count 5000         #  882 attacks (15%)
python build_training_set.py                           # 5882 rows
python ..\feature_extraction\transform.py --in out\generated_train.jsonl `
       --out ..\feature_extraction\out\features_train.csv
```

Scale with `--per-persona`; everything downstream derives its counts from it.
Both generators MUST run with the same `--stickiness`/`--length-tilt`/
`--arg-variation` (they share `generator_params.json` defaults) — if the benign
filler inside attack sessions were drawn with different knobs, the filler itself
would separate the classes.

⚠️ If you change `--per-persona`, **re-fit** with a matching
`--oov-samples`: the out-of-vocabulary rate is sample-size dependent (the same
`arg_variation` gives 4.9% OOV at 150 sessions/persona and 0% at 1250, because a
thin profile shows novelty a thick one absorbs).

### The third knob: `--arg-variation`

`stickiness` and `length_tilt` shape *how much* is typed. `arg_variation` opens
the **vocabulary**: it resamples paths, filenames and small integers on a fresh
draw while leaving the program and flags exactly as curated.

Without it the generated benign vocabulary is closed — 850 command types drawn
42 000 times — so no held-out benign session can contain anything unseen, and
`cmd_oov_rate` becomes a *perfect* attack marker that does not hold on real data.
Cross-fitting does not fix this; only opening the vocabulary does. Fitted to the
real benign OOV rate of 1.4%; achieved 1.32%. See
`../docs/session_2026-08-15_command_rarity.md`.

`generated_train.jsonl` is the shared substrate, not "the supervised dataset":
the unsupervised track fits on `label=="benign"` and scores the rest, the
supervised track trains on all rows with `label` as target. Built once so the
two tracks stay comparable.

## Attack generation — what is deliberately NOT done

- Attack commands are **not** filtered to those matching `transform.py`'s
  `RISK_KEYWORDS`. That would make `flag_*` a near-perfect label and the model
  would just re-learn `wallix_rules.xml`. Measured coverage: 59% of generated
  attack sessions trip at least one flag, against 65% of real collected attacks.
- Attacks are **not** always off-hours (46%), always from a foreign IP (30%), or
  always on a privileged account (4%, same as benign). Each incidental
  difference is a shortcut the model would take instead of learning behaviour.
  Single-feature AUC on the training set stays ≤ 0.73 for every model input.
- `ip_source` (`home`/`vpn`/`jump` vs `wrong_team_subnet`/`unseen_vpn`/`external`)
  IS one-sided by construction — it is **audit metadata, never a model input**.
  The model sees only the derived `new_source_ip_for_user` / `ip_foreign_to_user`
  / `source_ip_entropy` columns, whose AUCs sit at 0.51–0.58.
  Same for `composition`, `attack_command_count`, `campaign_id`, `mitre`,
  `target_criticality`: evaluation slices, not features.

## Shared substrate

`generate_benign.py` output uses the **same schema as extract.py's sessions.jsonl**,
so `../feature_extraction/transform.py` consumes generated and real sessions
identically. These benign sessions are the unsupervised training set AND the 85%
benign majority class of the supervised set — built once (see
`../docs/decision_log.md`).

## Notes

- `commands_dataset/{atomic_raw,gtfobins_raw,*.tar.gz,linuxcommands_raw.json}` are
  gitignored source caches, regenerable by the curate_* scripts.
- Diversity is calibrated to plausible human behaviour (stickiness ≈ 0.35), NOT to
  the real templates (whose unique_command_ratio ≈ 1.0 is a fixed-list artifact).
- Attack diversity axes (CLAUDE.md §10): composition (83% buried / 17% burst),
  persona, temporal spread, low-and-slow campaigns (~20% of attack sessions),
  intensity (1–6 attack commands). All recorded per row for sliced evaluation.
- RDP/FTP attack generation stays blocked on the decoder work — the command
  vocabulary is Linux shell content and RDP carries no per-command telemetry.
