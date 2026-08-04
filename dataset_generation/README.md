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

4. generate_benign.py          ──→ out/generated_benign.jsonl
   (samples the weighted vocab into sessions.jsonl-schema records; --stickiness
    controls repetition. label/tactics/source/split/persona ride along.)
```

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
- Attack-session generation and the full metadata/diversity layer (synthetic users,
  IP pool, timestamps, durations) are the next builds — see the benign diversity plan.
