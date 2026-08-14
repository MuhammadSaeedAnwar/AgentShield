# `notebooks/`

Lightweight, runnable analysis snippets.

- `explore_results.py` — a plain-Python (no Jupyter) exploration script that
  loads one or more results files and prints the headline metrics, per-condition
  ASR, and the counts of RQ3/RQ4 comparisons. Run it with:

  ```bash
  python notebooks/explore_results.py results/example_mock_run
  python notebooks/explore_results.py /tmp/ash3          # several conditions
  ```

  It uses the same functions as the `agentshield.analyze` CLI, so the numbers
  match `results/example_mock_run/analysis/report.md` exactly.

If you prefer a real notebook, `pip install jupyter` and wrap the snippet in a
`.ipynb`; the `agentshield` API calls are identical.
