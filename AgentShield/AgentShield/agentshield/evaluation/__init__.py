"""Evaluation: detectors, outcome classification, runner, result records."""

from __future__ import annotations

from .classifier import (
    ClassificationResult,
    CriteriaContext,
    Outcome,
    OutcomeClassifier,
    evaluate_criteria,
)
from .detectors import EpisodeSignals, detect_signals
from .results import (
    CSV_COLUMNS,
    SCHEMA_VERSION,
    EpisodeResult,
    RunResult,
    build_run_metadata,
    flatten_records,
    iter_result_files,
    load_results,
)
from .runner import BenchmarkRunner, RunnerConfig

__all__ = [
    "BenchmarkRunner",
    "CSV_COLUMNS",
    "ClassificationResult",
    "CriteriaContext",
    "EpisodeResult",
    "EpisodeSignals",
    "Outcome",
    "OutcomeClassifier",
    "RunResult",
    "RunnerConfig",
    "SCHEMA_VERSION",
    "build_run_metadata",
    "detect_signals",
    "evaluate_criteria",
    "flatten_records",
    "iter_result_files",
    "load_results",
]
