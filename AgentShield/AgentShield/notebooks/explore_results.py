#!/usr/bin/env python3
"""Programmatic exploration of AgentShield results (no Jupyter required).

This is a lightweight alternative to an `.ipynb`: it loads one or more results
files and prints the headline findings using the same functions the
`agentshield.analyze` CLI uses, so you can copy the snippets into your own
analysis.

Usage
-----
    python notebooks/explore_results.py results/example_mock_run
    python notebooks/explore_results.py /tmp/ash3          # multiple conditions

Every number printed here is computed from the loaded episodes; nothing is
fabricated.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentshield.evaluation.results import flatten_records, iter_result_files, load_results
from agentshield.metrics.core import attack_success_rate, compute_metrics
from agentshield.metrics.report import attach_condition, summarise


def main(argv: list[str]) -> int:
    paths = argv[1:] or [str(ROOT / "results" / "example_mock_run")]
    files = iter_result_files(paths)
    if not files:
        print(f"no results files found in {paths}", file=sys.stderr)
        return 2

    rows: list[dict] = []
    kept = 0
    for file in files:
        try:
            payload = load_results(file)
        except Exception as exc:  # not a results file (e.g. analysis/summary.json)
            print(f"  (skipping {file.name}: {exc})", file=sys.stderr)
            continue
        rows.extend(flatten_records(payload))
        kept += 1
    if kept == 0:
        print("no loadable results files found", file=sys.stderr)
        return 2
    rows = attach_condition(rows)

    n = len(rows)
    print(f"Loaded {kept} results file(s), {n} episode(s).")

    # Overall headline metrics.
    print("\nOverall metrics:")
    for name in ("attack_success_rate", "safe_completion_rate", "unauthorized_tool_call_rate", "sensitive_information_exposure_rate"):
        m = compute_metrics(rows)[name]
        print(f"  {name:38s} {m.format()}")

    # Per-condition ASR (the primary RQ3 view).
    print("\nAttack Success Rate by condition:")
    conditions = sorted({r["condition"] for r in rows})
    for condition in conditions:
        c_rows = [r for r in rows if r["condition"] == condition]
        m = attack_success_rate(c_rows)
        print(f"  {condition}\n    ASR = {m.format()}")

    # Full summary object (also written to JSON by `agentshield.analyze`).
    summary = summarise(rows)
    print(f"\nDefense comparisons (RQ3): {len(summary['defense_comparisons'])}")
    print(f"Provisioning comparisons (RQ4): {len(summary['provisioning_comparisons'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
