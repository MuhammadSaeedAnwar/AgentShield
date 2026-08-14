"""Analysis CLI: results JSON -> metrics, tables, charts.

Examples
--------
    python -m agentshield.analyze results/mock-mock-gullible-v1__def-none__tools-minimal__trials-3.json
    python -m agentshield.analyze results/                 # every results file in the directory
    python -m agentshield.analyze results/ --out results/analysis
    python -m agentshield.analyze results/ --no-charts     # tables only, no matplotlib needed

Outputs (in ``--out``)
----------------------
``report.md``                  human-readable tables (also printed to stdout)
``summary.json``               machine-readable metrics, incl. CIs and denominators
``episodes.csv``               one tidy row per episode, all runs concatenated
``metrics_by_condition.csv``   per-condition metric values
``metrics_by_category.csv``    per-condition, per-category metric values
``figures/*.png``              charts (skipped with ``--no-charts``)

Charts are drawn only from the loaded episodes. If a comparison has no data, the
chart is skipped rather than filled in with a placeholder.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evaluation.results import flatten_records, iter_result_files, load_results
from .metrics.core import group_by
from .metrics.report import (
    HEADLINE_METRICS,
    SHORT_NAMES,
    attach_condition,
    csv_rows_for_categories,
    csv_rows_for_conditions,
    render_markdown,
    summarise,
)

EPISODE_CSV_COLUMNS: tuple[str, ...] = (
    "run_id",
    "condition",
    "case_id",
    "category",
    "severity",
    "attack_goal",
    "injection_channel",
    "trial",
    "provider",
    "model_name",
    "defense_label",
    "tool_provisioning",
    "outcome",
    "attack_success",
    "task_completed",
    "unauthorized_tool_call",
    "n_unauthorized_calls",
    "blocked_calls",
    "secret_exposed",
    "secrets_reachable",
    "system_prompt_leaked",
    "injection_reached_model",
    "n_tool_calls",
    "truncated",
    "error",
    "wall_time_s",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agentshield.analyze",
        description="Compute AgentShield metrics and render tables/charts from results files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("paths", nargs="*", default=["results"], help="Results JSON files and/or directories (default: results)")
    parser.add_argument("--out", help="Output directory (default: <first path>/analysis or results/analysis)")
    parser.add_argument("--no-charts", action="store_true", help="Skip PNG charts (no matplotlib required)")
    parser.add_argument("--quiet", action="store_true", help="Do not print the report to stdout")
    return parser


# --------------------------------------------------------------------------
# charts
# --------------------------------------------------------------------------


def _grouped_bar(ax: Any, groups: Sequence[str], series: Mapping[str, Sequence[float | None]], ylabel: str, title: str) -> None:
    n_series = max(1, len(series))
    width = 0.8 / n_series
    for index, (label, values) in enumerate(series.items()):
        offsets = [i - 0.4 + width * (index + 0.5) for i in range(len(groups))]
        heights = [0.0 if v is None else 100.0 * float(v) for v in values]
        bars = ax.bar(offsets, heights, width=width, label=label)
        for bar, value in zip(bars, values):
            if value is None:
                ax.text(bar.get_x() + bar.get_width() / 2, 1.0, "n/a", ha="center", va="bottom", fontsize=6, rotation=90)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups, rotation=25, ha="right", fontsize=8)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 105)
    ax.set_title(title, fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    if len(series) > 1:
        ax.legend(fontsize=7)


def make_charts(summary: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], out_dir: Path) -> list[Path]:
    """Render charts from measured data. Returns the files written."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print(
            "warning: matplotlib is not installed, skipping charts (tables and CSVs were still written)",
            file=sys.stderr,
        )
        return []

    figures = out_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    conditions = list((summary.get("by_condition") or {}).keys())
    n_episodes = summary.get("n_episodes", 0)

    # 1. Headline metrics per condition.
    if conditions:
        fig, ax = plt.subplots(figsize=(1.9 + 1.7 * len(conditions), 4.2))
        series = {
            SHORT_NAMES[m]: [(summary["by_condition"][c].get(m) or {}).get("value") for c in conditions]
            for m in HEADLINE_METRICS
        }
        _grouped_bar(ax, conditions, series, "percent", f"Headline metrics by condition (n={n_episodes} episodes)")
        fig.tight_layout()
        path = figures / "headline_metrics.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

    # 2. ASR by attack category.
    categories = sorted({str(r.get("category", "")) for r in rows})
    if categories and conditions:
        fig, ax = plt.subplots(figsize=(2.2 + 1.5 * len(categories), 4.4))
        series = {}
        for condition in conditions:
            per_category = summary["by_category"].get(condition, {})
            series[condition] = [
                ((per_category.get(category) or {}).get("attack_success_rate") or {}).get("value")
                for category in categories
            ]
        _grouped_bar(ax, categories, series, "Attack Success Rate (%)", "ASR by attack category (RQ1/RQ2)")
        fig.tight_layout()
        path = figures / "asr_by_category.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

        # 3. Unauthorized tool-call rate by category.
        fig, ax = plt.subplots(figsize=(2.2 + 1.5 * len(categories), 4.4))
        series = {}
        for condition in conditions:
            per_category = summary["by_category"].get(condition, {})
            series[condition] = [
                ((per_category.get(category) or {}).get("unauthorized_tool_call_rate") or {}).get("value")
                for category in categories
            ]
        _grouped_bar(ax, categories, series, "Unauthorized Tool Call Rate (%)", "UTCR by attack category")
        fig.tight_layout()
        path = figures / "unauthorized_tool_calls.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

    # 4. Defense effectiveness (only if paired conditions exist).
    comparisons = summary.get("defense_comparisons") or []
    if comparisons:
        labels = [c["defended"].split("defenses=")[-1].split(" |")[0] for c in comparisons]
        fig, ax = plt.subplots(figsize=(2.2 + 1.6 * len(labels), 4.4))
        series = {
            "baseline ASR": [(c.get("baseline_asr") or {}).get("value") for c in comparisons],
            "defended ASR": [(c.get("defended_asr") or {}).get("value") for c in comparisons],
            "DSR": [(c.get("defense_success_rate") or {}).get("value") for c in comparisons],
        }
        _grouped_bar(ax, labels, series, "percent", "Defense effectiveness vs undefended baseline (RQ3)")
        fig.tight_layout()
        path = figures / "defense_effectiveness.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

    # 5. Model comparison (only with more than one model).
    by_model = summary.get("by_model") or {}
    if len(by_model) > 1:
        models = list(by_model)
        fig, ax = plt.subplots(figsize=(2.2 + 1.6 * len(models), 4.2))
        series = {SHORT_NAMES[m]: [(by_model[k].get(m) or {}).get("value") for k in models] for m in HEADLINE_METRICS}
        _grouped_bar(ax, models, series, "percent", "Per-model comparison (all loaded conditions pooled)")
        fig.tight_layout()
        path = figures / "model_comparison.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

    # 6. Tool provisioning (RQ4), only if both levels are present.
    provisioning = summary.get("provisioning_comparisons") or []
    if provisioning:
        labels = [c["defended"].split("| defenses=")[-1].replace(" | tools=full", "") for c in provisioning]
        fig, ax = plt.subplots(figsize=(2.2 + 1.6 * len(labels), 4.2))
        series = {
            "minimal tools ASR": [(c.get("baseline_asr") or {}).get("value") for c in provisioning],
            "full tools ASR": [(c.get("defended_asr") or {}).get("value") for c in provisioning],
        }
        _grouped_bar(ax, labels, series, "Attack Success Rate (%)", "Effect of extra tool provisioning (RQ4)")
        fig.tight_layout()
        path = figures / "tool_provisioning.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        written.append(path)

    return written


# --------------------------------------------------------------------------
# csv writers
# --------------------------------------------------------------------------


def _write_csv(path: Path, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)
    return path


def write_episode_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(EPISODE_CSV_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _scalar(row.get(key)) for key in EPISODE_CSV_COLUMNS})
    return path


def _scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (list, tuple)):
        return "+".join(str(v) for v in value)
    return value


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = args.paths or ["results"]

    try:
        files = iter_result_files(paths)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not files:
        print(f"error: no results files found in {paths}. Run `python -m agentshield.run` first.", file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    for file in files:
        try:
            payload = load_results(file)
        except Exception as exc:
            print(f"warning: skipping {file}: {exc}", file=sys.stderr)
            continue
        metadata.append(dict(payload.get("run_metadata") or {}))
        rows.extend(flatten_records(payload))

    if not rows:
        print("error: loaded 0 episodes; nothing to analyse", file=sys.stderr)
        return 2

    rows = attach_condition(rows)
    summary = summarise(rows, metadata)
    report = render_markdown(summary, rows)

    first = Path(paths[0])
    out_dir = Path(args.out) if args.out else ((first if first.is_dir() else first.parent) / "analysis")
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "report.md").write_text(report, "utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), "utf-8")
    write_episode_csv(out_dir / "episodes.csv", rows)
    _write_csv(out_dir / "metrics_by_condition.csv", *csv_rows_for_conditions(summary))
    _write_csv(out_dir / "metrics_by_category.csv", *csv_rows_for_categories(summary))

    figures: list[Path] = [] if args.no_charts else make_charts(summary, rows, out_dir)

    if not args.quiet:
        print(report)

    print(f"\nLoaded {len(files)} results file(s), {len(rows)} episode(s).", file=sys.stderr)
    print(f"Wrote: {out_dir / 'report.md'}", file=sys.stderr)
    print(f"Wrote: {out_dir / 'summary.json'}", file=sys.stderr)
    print(f"Wrote: {out_dir / 'episodes.csv'}", file=sys.stderr)
    print(f"Wrote: {out_dir / 'metrics_by_condition.csv'}", file=sys.stderr)
    print(f"Wrote: {out_dir / 'metrics_by_category.csv'}", file=sys.stderr)
    for figure in figures:
        print(f"Wrote: {figure}", file=sys.stderr)

    # A quick, honest data-quality note.
    conditions = group_by(rows, "condition")
    if len(conditions) == 1:
        print(
            "\nnote: only one condition was loaded, so RQ3/RQ4 sections are empty. "
            "Run additional conditions (e.g. --defenses all, --tool-provisioning full) and re-analyse.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
