"""Turn episode rows into a summary object and a Markdown report.

Pure standard library: charts live in :mod:`agentshield.analyze` so that the
metrics layer stays importable in a minimal environment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from ..attacks.taxonomy import category_label, category_letter
from .core import (
    METRIC_DEFINITIONS,
    DefenseComparison,
    Metric,
    applicable_rows,
    attack_success_rate,
    compare_defense,
    compute_metrics,
    group_by,
    metrics_by,
)

Row = Mapping[str, Any]

HEADLINE_METRICS: tuple[str, ...] = (
    "attack_success_rate",
    "safe_completion_rate",
    "unauthorized_tool_call_rate",
    "sensitive_information_exposure_rate",
)
SUPPORT_METRIC_NAMES: tuple[str, ...] = (
    "task_completion_rate",
    "blocked_call_rate",
    "system_prompt_leak_rate",
    "injection_delivery_rate",
    "error_rate",
)
SHORT_NAMES: dict[str, str] = {
    "attack_success_rate": "ASR",
    "safe_completion_rate": "SCR",
    "unauthorized_tool_call_rate": "UTCR",
    "sensitive_information_exposure_rate": "SIER",
    "task_completion_rate": "TCR",
    "blocked_call_rate": "Blocked",
    "system_prompt_leak_rate": "SysLeak",
    "injection_delivery_rate": "Delivered",
    "error_rate": "Errors",
    "defense_success_rate": "DSR",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def condition_key(row: Row) -> str:
    """Identifier of an experimental condition: model | defenses | provisioning."""
    defense = row.get("defense_label") or "none"
    return f"{row.get('model_name', '?')} | defenses={defense} | tools={row.get('tool_provisioning', 'minimal')}"


def fmt(metric: Metric | None, *, with_counts: bool = True) -> str:
    if metric is None:
        return "-"
    if metric.value is None:
        return "n/a"
    if with_counts:
        return f"{metric.percent:.1f}% ({metric.numerator}/{metric.denominator})"
    return f"{metric.percent:.1f}%"


def render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return "_(no data)_"
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    lines = [
        "| " + " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)) + " |",
        "|" + "|".join("-" * (w + 2) for w in widths) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) + " |")
    return "\n".join(lines)


def metrics_to_dict(metrics: Mapping[str, Metric]) -> dict[str, Any]:
    return {name: metric.to_dict() for name, metric in metrics.items()}


# --------------------------------------------------------------------------
# summary construction
# --------------------------------------------------------------------------


def summarise(rows: Sequence[Row], run_metadata: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Build the machine-readable analysis summary."""
    rows = list(rows)
    conditions = group_by(rows, "condition")
    summary: dict[str, Any] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_episodes": len(rows),
        "n_conditions": len(conditions),
        "n_cases": len({r.get("case_id") for r in rows}),
        "models": sorted({str(r.get("model_name", "")) for r in rows}),
        "defense_labels": sorted({str(r.get("defense_label", "none")) for r in rows}),
        "metric_definitions": dict(METRIC_DEFINITIONS),
        "runs": [
            {
                "run_id": m.get("run_id"),
                "timestamp_utc": m.get("timestamp_utc"),
                "model": (m.get("model") or {}).get("model_name"),
                "provider": (m.get("model") or {}).get("provider"),
                "defenses": m.get("defenses"),
                "dataset_source": (m.get("dataset") or {}).get("source"),
                "dataset_sha256": (m.get("dataset") or {}).get("sha256"),
                "trials": (m.get("config") or {}).get("trials"),
                "tool_provisioning": (m.get("config") or {}).get("tool_provisioning"),
                "agentshield_version": m.get("agentshield_version"),
                "command_line": m.get("command_line"),
            }
            for m in (run_metadata or [])
        ],
        "overall": metrics_to_dict(compute_metrics(rows)),
        "by_condition": {},
        "by_category": {},
        "by_severity": {},
        "by_channel": {},
        "by_model": {},
        "per_case": [],
        "defense_comparisons": [],
        "provisioning_comparisons": [],
    }

    for condition, condition_rows in conditions.items():
        summary["by_condition"][condition] = metrics_to_dict(compute_metrics(condition_rows))
        summary["by_category"][condition] = {
            category: metrics_to_dict(metrics)
            for category, metrics in metrics_by(condition_rows, "category").items()
        }
        summary["by_severity"][condition] = {
            severity: metrics_to_dict(metrics)
            for severity, metrics in metrics_by(condition_rows, "severity").items()
        }
        summary["by_channel"][condition] = {
            channel: metrics_to_dict(metrics)
            for channel, metrics in metrics_by(condition_rows, "injection_channel").items()
        }

    for model, model_rows in group_by(rows, "model_name").items():
        summary["by_model"][model] = metrics_to_dict(compute_metrics(model_rows))

    # Per-case ASR within each condition (finds the cases that carry the signal).
    for condition, condition_rows in conditions.items():
        for case_id, case_rows in group_by(condition_rows, "case_id").items():
            metric = attack_success_rate(case_rows)
            summary["per_case"].append(
                {
                    "condition": condition,
                    "case_id": case_id,
                    "category": str(case_rows[0].get("category", "")),
                    "severity": str(case_rows[0].get("severity", "")),
                    "n_episodes": len(case_rows),
                    "asr": metric.value,
                    "successes": metric.numerator,
                    "applicable": metric.denominator,
                }
            )

    summary["defense_comparisons"] = [c.to_dict() for c in build_defense_comparisons(rows)]
    summary["provisioning_comparisons"] = [c.to_dict() for c in build_provisioning_comparisons(rows)]
    return summary


def _strata(rows: Sequence[Row]) -> dict[tuple[str, str], list[Row]]:
    """Group rows by (model, provisioning) so comparisons stay within a stratum."""
    out: dict[tuple[str, str], list[Row]] = {}
    for row in rows:
        key = (str(row.get("model_name", "")), str(row.get("tool_provisioning", "minimal")))
        out.setdefault(key, []).append(row)
    return out


def build_defense_comparisons(rows: Sequence[Row]) -> list[DefenseComparison]:
    """Compare every defended condition against the undefended baseline.

    Comparisons are made **within** a (model, tool-provisioning) stratum, and only
    when an undefended (``defenses=none``) condition exists there.
    """
    comparisons: list[DefenseComparison] = []
    for _, stratum_rows in sorted(_strata(rows).items()):
        by_defense = group_by(stratum_rows, "defense_label")
        baseline = by_defense.get("none")
        if not baseline:
            continue
        for label, defended in by_defense.items():
            if label == "none":
                continue
            comparison = compare_defense(baseline, defended)
            if comparison.n_paired:
                comparisons.append(comparison)
    return comparisons


def build_provisioning_comparisons(rows: Sequence[Row]) -> list[DefenseComparison]:
    """Compare minimal vs full tool provisioning (RQ4), within (model, defenses)."""
    comparisons: list[DefenseComparison] = []
    grouped: dict[tuple[str, str], list[Row]] = {}
    for row in rows:
        key = (str(row.get("model_name", "")), str(row.get("defense_label", "none")))
        grouped.setdefault(key, []).append(row)

    for (model, defense), group_rows in sorted(grouped.items()):
        by_prov = group_by(group_rows, "tool_provisioning")
        minimal, full = by_prov.get("minimal"), by_prov.get("full")
        if not minimal or not full:
            continue
        # Pairing ignores provisioning by construction here: compare the same
        # (case, trial) under the two provisioning levels.
        stripped_minimal = [{**r, "tool_provisioning": "paired"} for r in minimal]
        stripped_full = [{**r, "tool_provisioning": "paired"} for r in full]
        comparison = compare_defense(stripped_minimal, stripped_full)
        comparison.baseline_label = f"{model} | defenses={defense} | tools=minimal"
        comparison.defended_label = f"{model} | defenses={defense} | tools=full"
        if comparison.n_paired:
            comparisons.append(comparison)
    return comparisons


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------


def render_markdown(summary: Mapping[str, Any], rows: Sequence[Row]) -> str:
    parts: list[str] = []
    parts.append("# AgentShield analysis report\n")
    parts.append(
        f"Generated {summary.get('generated_utc')} from {summary.get('n_episodes')} episode(s), "
        f"{summary.get('n_cases')} case(s), {summary.get('n_conditions')} condition(s).\n"
    )
    parts.append(
        "> Every number below is computed from executed episodes in the loaded results files. "
        "Cells reading `n/a` have an empty denominator.\n"
    )

    # --- runs -----------------------------------------------------------
    runs = summary.get("runs") or []
    if runs:
        parts.append("## Runs included\n")
        parts.append(
            render_table(
                ["run_id", "model", "provider", "defenses", "trials", "tools", "dataset sha256", "timestamp"],
                [
                    [
                        r.get("run_id", ""),
                        r.get("model", ""),
                        r.get("provider", ""),
                        "+".join(r.get("defenses") or []) or "none",
                        r.get("trials", ""),
                        r.get("tool_provisioning", ""),
                        str(r.get("dataset_sha256", ""))[:12],
                        r.get("timestamp_utc", ""),
                    ]
                    for r in runs
                ],
            )
        )
        parts.append("")

    # --- headline metrics per condition ---------------------------------
    parts.append("## Headline metrics by condition\n")
    headers = ["condition", *[SHORT_NAMES[m] for m in HEADLINE_METRICS], "episodes"]
    table_rows = []
    for condition, metrics in (summary.get("by_condition") or {}).items():
        counts = len([r for r in rows if condition_key(r) == condition])
        table_rows.append(
            [condition, *[_fmt_dict(metrics.get(m)) for m in HEADLINE_METRICS], counts]
        )
    parts.append(render_table(headers, table_rows))
    parts.append("")
    parts.append(
        "ASR = Attack Success Rate, SCR = Safe Completion Rate, UTCR = Unauthorized Tool Call Rate, "
        "SIER = Sensitive Information Exposure Rate. Definitions and denominators: see README.\n"
    )

    parts.append("## Supporting metrics by condition\n")
    parts.append(
        render_table(
            ["condition", *[SHORT_NAMES[m] for m in SUPPORT_METRIC_NAMES]],
            [
                [condition, *[_fmt_dict(metrics.get(m)) for m in SUPPORT_METRIC_NAMES]]
                for condition, metrics in (summary.get("by_condition") or {}).items()
            ],
        )
    )
    parts.append("")

    # --- ASR by category ------------------------------------------------
    parts.append("## Attack Success Rate by category (RQ1 / RQ2)\n")
    for condition, categories in (summary.get("by_category") or {}).items():
        parts.append(f"**{condition}**\n")
        parts.append(
            render_table(
                ["", "category", "ASR", "UTCR", "SIER", "SCR"],
                [
                    [
                        category_letter(category),
                        category_label(category),
                        _fmt_dict(metrics.get("attack_success_rate")),
                        _fmt_dict(metrics.get("unauthorized_tool_call_rate")),
                        _fmt_dict(metrics.get("sensitive_information_exposure_rate")),
                        _fmt_dict(metrics.get("safe_completion_rate")),
                    ]
                    for category, metrics in sorted(categories.items(), key=lambda kv: category_letter(kv[0]))
                ],
            )
        )
        parts.append("")

    # --- injection channel ---------------------------------------------
    parts.append("## Attack Success Rate by injection channel\n")
    for condition, channels in (summary.get("by_channel") or {}).items():
        parts.append(f"**{condition}**\n")
        parts.append(
            render_table(
                ["channel", "ASR", "delivered to model"],
                [
                    [channel, _fmt_dict(metrics.get("attack_success_rate")), _fmt_dict(metrics.get("injection_delivery_rate"))]
                    for channel, metrics in sorted(channels.items())
                ],
            )
        )
        parts.append("")

    # --- defense effectiveness -----------------------------------------
    comparisons = summary.get("defense_comparisons") or []
    parts.append("## Defense effectiveness (RQ3)\n")
    if not comparisons:
        parts.append(
            "_No paired baseline/defended conditions were found. Run the same dataset with "
            "`--defenses none` and with a defense set to populate this section._\n"
        )
    else:
        parts.append(
            render_table(
                ["defended condition", "paired n", "baseline ASR", "defended ASR", "DSR", "abs. reduction (pp)", "p (uncorr.)"],
                [
                    [
                        c.get("defended", ""),
                        c.get("n_paired_episodes", 0),
                        _fmt_dict(c.get("baseline_asr")),
                        _fmt_dict(c.get("defended_asr")),
                        _fmt_dict(c.get("defense_success_rate")),
                        c.get("absolute_asr_reduction_pp"),
                        c.get("p_value_uncorrected"),
                    ]
                    for c in comparisons
                ],
            )
        )
        parts.append("")
        parts.append(
            "DSR = of the attacks that succeeded in the paired baseline episodes, the fraction the defended "
            "condition prevented. `p` is an uncorrected two-proportion z-test, descriptive only.\n"
        )
        for c in comparisons:
            if c.get("newly_successful_episodes"):
                parts.append(
                    f"- Note: `{c.get('defended')}` introduced {len(c['newly_successful_episodes'])} "
                    f"newly successful attack(s): {', '.join(c['newly_successful_episodes'][:10])}\n"
                )

    # --- tool provisioning ---------------------------------------------
    provisioning = summary.get("provisioning_comparisons") or []
    parts.append("## Effect of tool provisioning (RQ4)\n")
    if not provisioning:
        parts.append(
            "_No paired minimal/full provisioning conditions were found. Run the dataset with "
            "`--tool-provisioning minimal` and `--tool-provisioning full` to populate this section._\n"
        )
    else:
        parts.append(
            render_table(
                ["comparison", "paired n", "minimal ASR", "full ASR", "ASR delta (pp)", "p (uncorr.)"],
                [
                    [
                        c.get("defended", ""),
                        c.get("n_paired_episodes", 0),
                        _fmt_dict(c.get("baseline_asr")),
                        _fmt_dict(c.get("defended_asr")),
                        None
                        if c.get("absolute_asr_reduction_pp") is None
                        else -1 * float(c["absolute_asr_reduction_pp"]),
                        c.get("p_value_uncorrected"),
                    ]
                    for c in provisioning
                ],
            )
        )
        parts.append("")
        parts.append("A positive delta means granting extra tools increased the Attack Success Rate.\n")

    # --- per-case detail ------------------------------------------------
    parts.append("## Per-case detail\n")
    per_case = sorted(
        summary.get("per_case") or [],
        key=lambda r: (str(r.get("condition")), str(r.get("case_id"))),
    )
    parts.append(
        render_table(
            ["condition", "case", "category", "severity", "successes/applicable", "ASR"],
            [
                [
                    r.get("condition", ""),
                    r.get("case_id", ""),
                    category_letter(str(r.get("category", ""))),
                    r.get("severity", ""),
                    f"{r.get('successes', 0)}/{r.get('applicable', 0)}",
                    "n/a" if r.get("asr") is None else f"{100 * float(r['asr']):.0f}%",
                ]
                for r in per_case
            ],
        )
    )
    parts.append("")
    parts.append("---\n")
    parts.append(
        "Reproduce: see `run_metadata.command_line` in each results file, and the dataset SHA-256 above.\n"
    )
    return "\n".join(parts)


def _fmt_dict(metric_dict: Mapping[str, Any] | None) -> str:
    if not metric_dict:
        return "-"
    value = metric_dict.get("value")
    if value is None:
        return "n/a"
    return f"{100 * float(value):.1f}% ({metric_dict.get('numerator')}/{metric_dict.get('denominator')})"


def csv_rows_for_conditions(summary: Mapping[str, Any]) -> tuple[list[str], list[list[Any]]]:
    """Flat CSV of per-condition metrics."""
    metric_names = [*HEADLINE_METRICS, *SUPPORT_METRIC_NAMES]
    headers = ["condition", *[f"{m}" for m in metric_names], *[f"{m}_n" for m in metric_names]]
    rows: list[list[Any]] = []
    for condition, metrics in (summary.get("by_condition") or {}).items():
        values = [(metrics.get(m) or {}).get("value") for m in metric_names]
        denoms = [(metrics.get(m) or {}).get("denominator") for m in metric_names]
        rows.append([condition, *values, *denoms])
    return headers, rows


def csv_rows_for_categories(summary: Mapping[str, Any]) -> tuple[list[str], list[list[Any]]]:
    metric_names = [*HEADLINE_METRICS]
    headers = ["condition", "category", *metric_names, "applicable_episodes"]
    rows: list[list[Any]] = []
    for condition, categories in (summary.get("by_category") or {}).items():
        for category, metrics in sorted(categories.items()):
            asr = metrics.get("attack_success_rate") or {}
            rows.append(
                [
                    condition,
                    category,
                    *[(metrics.get(m) or {}).get("value") for m in metric_names],
                    asr.get("denominator"),
                ]
            )
    return headers, rows


def attach_condition(rows: Iterable[Row]) -> list[dict[str, Any]]:
    """Add the derived ``condition`` column used throughout the report."""
    return [{**row, "condition": condition_key(row)} for row in rows]
