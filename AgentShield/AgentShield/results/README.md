# `results/`

Experiment outputs produced by `python -m agentshield.run`.

## What is tracked in version control

Everything under `results/` is **git-ignored** except:

- `results/README.md` (this file)
- `results/.gitkeep` (keeps the directory in the tree)
- `results/example_mock_run/` — a small, committed **reference run** using the
  deterministic mock model (`--model mock`, seed 1337) under two conditions:
  `--defenses none` and `--defenses all`, each with 3 trials. It exists so the
  repo is reproducible out-of-the-box and reviewers can inspect a real
  results file without running anything.

Regenerate any run with the commands in the top-level `README.md`. Per-run
outputs are named `mock-<model>__def-<defenses>__tools-<provisioning>__trials-<n>.json`
(with a side-by-side `.csv`).

## IMPORTANT: what the committed numbers do and do not mean

The `example_mock_run/` numbers are produced by `--model mock`. The mock is a
**deterministic susceptibility simulator**, not a language model (see
`docs/mock_model.md`). Its numbers characterise the *harness* (detectors,
classifier, metrics, deterministic defenses) — they are **not** measurements of
any real LLM and must **not** be read as "GPT-x is 34% vulnerable" or similar.
Answering the research questions about real models requires `--model openai`
against real, consenting deployments. See the top-level README for the full
honesty caveats.

## Analysing a run

```bash
python -m agentshield.analyze results/example_mock_run
# -> results/example_mock_run/analysis/{report.md, summary.json, episodes.csv,
#                                       metrics_by_condition.csv, metrics_by_category.csv, figures/}
```
