"""Experiment runner CLI.

Examples
--------
Offline, deterministic smoke run::

    python -m agentshield.run --model mock --dataset data/attacks.json

Undefended baseline, 3 trials::

    python -m agentshield.run --model mock --trials 3 --defenses none

All defenses on::

    python -m agentshield.run --model mock --trials 3 --defenses all

Single defense ablation::

    python -m agentshield.run --model mock --defenses authorization

Real provider (requires OPENAI_API_KEY; costs tokens)::

    python -m agentshield.run --model openai --model-name gpt-4o-mini --trials 1

Local OpenAI-compatible server::

    python -m agentshield.run --model openai --base-url http://localhost:11434/v1 \\
        --model-name llama3.1:8b --api-key-env NONE
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

from .attacks.dataset import load_dataset
from .config import RunConfig
from .defenses.pipeline import DEFENSE_NAMES, DefensePipeline
from .evaluation.results import flatten_records
from .evaluation.runner import BenchmarkRunner, RunnerConfig
from .metrics.core import compute_metrics
from .metrics.report import HEADLINE_METRICS, SHORT_NAMES, SUPPORT_METRIC_NAMES
from .models import build_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agentshield.run",
        description="Run the AgentShield security benchmark for tool-using LLM agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Defaults are None so that "was the flag given?" can be distinguished from
    # "the default happens to equal the config file value".
    parser.add_argument("--config", help="JSON/YAML config file with any of the options below")

    data = parser.add_argument_group("dataset")
    data.add_argument("--dataset", help="Dataset JSON file or directory (default: data/attacks.json)")
    data.add_argument("--categories", help="Comma-separated category filter (e.g. rag_injection,tool_output_injection)")
    data.add_argument("--ids", help="Comma-separated case-id filter (e.g. A-01,C-03)")
    data.add_argument("--severities", help="Comma-separated severity filter (low,medium,high,critical)")
    data.add_argument("--limit", type=int, help="Use only the first N cases after filtering")

    model = parser.add_argument_group("model")
    model.add_argument("--model", choices=["mock", "openai"], help="Model adapter (default: mock)")
    model.add_argument("--model-name", dest="model_name", help="Provider model id, e.g. gpt-4o-mini")
    model.add_argument("--base-url", dest="base_url", help="OpenAI-compatible base URL")
    model.add_argument("--api-key-env", dest="api_key_env", help="Env var holding the API key (default: OPENAI_API_KEY)")
    model.add_argument("--temperature", type=float, help="Sampling temperature (default: 0.0)")
    model.add_argument("--max-tokens", dest="max_tokens", type=int, help="Max completion tokens (default: 1024)")
    model.add_argument("--cache-dir", dest="cache_dir", help="Cache API responses here for exact replay")
    model.add_argument("--seed", type=int, help="Seed for the deterministic mock adapter (default: 1337)")

    experiment = parser.add_argument_group("experiment")
    experiment.add_argument("--trials", type=int, help="Repetitions per case (default: 1)")
    experiment.add_argument(
        "--defenses",
        help=f"'none', 'all', or comma-separated subset of: {', '.join(DEFENSE_NAMES)} (default: none)",
    )
    experiment.add_argument("--max-steps", dest="max_steps", type=int, help="Max tool-call steps per user turn (default: 6)")
    experiment.add_argument(
        "--tool-provisioning",
        dest="tool_provisioning",
        choices=["minimal", "full"],
        help="'minimal' = only the tools the case grants; 'full' = grant every tool (RQ4)",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--out", help="Output directory (default: results)")
    output.add_argument("--run-id", dest="run_id", help="Override the derived run id / filename stem")
    output.add_argument(
        "--no-transcripts",
        dest="keep_transcripts",
        action="store_const",
        const=False,
        help="Do not store full transcripts in the JSON results (smaller files)",
    )
    output.add_argument("--fail-fast", dest="fail_fast", action="store_const", const=True, help="Abort on the first error")
    output.add_argument("--quiet", action="store_const", const=True, help="Suppress per-episode progress output")
    output.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the dataset and print the first case's prompt, then exit without calling any model",
    )
    output.add_argument("--list-cases", action="store_true", help="Print the (filtered) dataset inventory and exit")
    return parser


def _split_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def config_from_args(args: argparse.Namespace) -> RunConfig:
    config = RunConfig.from_file(args.config) if args.config else RunConfig()
    overrides: dict[str, Any] = {
        "dataset": args.dataset,
        "categories": _split_list(args.categories),
        "ids": _split_list(args.ids),
        "severities": _split_list(args.severities),
        "limit": args.limit,
        "model": args.model,
        "model_name": args.model_name,
        "base_url": args.base_url,
        "api_key_env": args.api_key_env,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "cache_dir": args.cache_dir,
        "seed": args.seed,
        "trials": args.trials,
        "defenses": args.defenses,
        "max_steps": args.max_steps,
        "tool_provisioning": args.tool_provisioning,
        "out": args.out,
        "run_id": args.run_id,
        "keep_transcripts": args.keep_transcripts,
        "fail_fast": args.fail_fast,
        "quiet": args.quiet,
    }
    return config.merged(overrides)


def _print_inventory(dataset: Any) -> None:
    print(f"Dataset: {dataset.source}  (sha256 {dataset.sha256[:16]}...)")
    print(f"Cases: {len(dataset)}")
    print("\nBy category:")
    for category, count in sorted(dataset.counts_by_category().items()):
        print(f"  {category:28s} {count}")
    print("\nBy severity:")
    for severity, count in sorted(dataset.counts_by_severity().items()):
        print(f"  {severity:28s} {count}")
    print("\nCases:")
    for case in dataset:
        tools = ",".join(case.available_tools) or "-"
        print(f"  {case.id:6s} {case.category:28s} {case.severity:8s} channel={case.injection_channel:12s} tools={tools}")


def _print_dry_run(dataset: Any, config: RunConfig, defenses: DefensePipeline) -> None:
    from .agents.prompt import build_base_system_prompt
    from .tools.builtin import TOOLS_BY_NAME
    from .tools.policy import ToolPolicy
    from .tools.registry import ToolRegistry

    case = dataset[0]
    registry = (
        ToolRegistry.all_tools()
        if config.tool_provisioning == "full"
        else ToolRegistry.from_names([t for t in case.available_tools if t in TOOLS_BY_NAME])
    )
    base_system = build_base_system_prompt(case, registry)
    system_prompt = defenses.build_system_prompt(base_system, case).text

    print("=" * 78)
    print(f"DRY RUN -- no model was called. Case {case.id} ({case.category})")
    print("=" * 78)
    print(f"\n--- SYSTEM PROMPT (defenses={defenses.label}) ---\n{system_prompt}")
    for index, turn in enumerate(case.user_turns):
        print(f"\n--- USER TURN {index} ---\n{defenses.filter_user_turn(turn, case).text}")
    print(f"\n--- INJECTION CHANNEL ---\n{case.injection_channel}")
    print(f"\n--- ATTACK PAYLOAD (as authored) ---\n{case.attack_prompt}")
    print(f"\n--- POLICY ---\n{ToolPolicy.from_case(case).to_dict()}")
    print(f"\n--- SUCCESS CRITERIA ---\n{case.success_criteria}")
    print(f"\n--- TASK CRITERIA ---\n{case.task_criteria}")
    print(f"\n--- EXPECTED SAFE BEHAVIOUR ---\n{case.expected_safe_behavior}")
    print(f"\nDataset sha256: {dataset.sha256}")


def _print_summary(rows: Sequence[dict[str, Any]], json_path: Path, csv_path: Path) -> None:
    metrics = compute_metrics(rows)
    print("\n" + "=" * 78)
    print("RUN SUMMARY (computed from the episodes just executed)")
    print("=" * 78)
    for name in (*HEADLINE_METRICS, *SUPPORT_METRIC_NAMES):
        metric = metrics.get(name)
        if metric is None:
            continue
        print(f"  {SHORT_NAMES.get(name, name):10s} {name:38s} {metric.format()}")
    print("\nOutcome counts:")
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row.get("outcome"))] = counts.get(str(row.get("outcome")), 0) + 1
    for outcome, count in sorted(counts.items()):
        print(f"  {outcome:20s} {count}")
    print(f"\nResults JSON: {json_path}")
    print(f"Results CSV : {csv_path}")
    print(f"\nNext: python -m agentshield.analyze {json_path}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = config_from_args(args)

    try:
        dataset = load_dataset(config.dataset)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    dataset = dataset.filter(
        categories=config.categories or None,
        ids=config.ids or None,
        severities=config.severities or None,
        limit=config.limit,
    )
    if not len(dataset):
        print("error: no cases left after filtering", file=sys.stderr)
        return 2

    if args.list_cases:
        _print_inventory(dataset)
        return 0

    try:
        defenses = DefensePipeline.from_names(config.defenses)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        _print_dry_run(dataset, config, defenses)
        return 0

    try:
        model = build_model(config.model, config.model_options())
    except Exception as exc:
        print(f"error: could not build model adapter: {exc}", file=sys.stderr)
        return 2

    run_id = config.resolved_run_id(model_label=model.model_name, defense_label=defenses.label)
    runner_config = RunnerConfig(
        trials=config.trials,
        max_steps=config.max_steps,
        tool_provisioning=config.tool_provisioning,
        run_id=run_id,
        keep_transcripts=config.keep_transcripts,
        fail_fast=config.fail_fast,
    )
    runner = BenchmarkRunner(
        model=model,
        defenses=defenses,
        config=runner_config,
        progress=None if config.quiet else (lambda message: print(message, file=sys.stderr, flush=True)),
    )

    print(
        f"AgentShield: {len(dataset)} case(s) x {config.trials} trial(s) = "
        f"{len(dataset) * config.trials} episode(s) | model={model.model_name} "
        f"| defenses={defenses.label} | tools={config.tool_provisioning}",
        file=sys.stderr,
    )

    try:
        result = runner.run(dataset, extra_metadata={"effective_config": config.to_dict()})
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: run failed: {exc}", file=sys.stderr)
        return 1

    out_dir = Path(config.out)
    json_path = result.save_json(out_dir / f"{run_id}.json", include_transcripts=config.keep_transcripts)
    csv_path = result.save_csv(out_dir / f"{run_id}.csv")
    _print_summary(flatten_records(result.to_dict(include_transcripts=False)), json_path, csv_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
