"""Result records and (de)serialisation.

A results file is a single JSON object::

    {
      "schema_version": "1.0",
      "run_metadata": { ...everything needed to reproduce the run... },
      "results": [ {per-episode record}, ... ]
    }

Per-episode records carry the scored fields *and* (unless transcripts were
disabled) the full episode transcript, so every number in the analysis can be
traced back to the exact conversation that produced it.
"""

from __future__ import annotations

import csv
import json
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .. import __version__
from ..agents.base import Episode
from .classifier import ClassificationResult, Outcome
from .detectors import EpisodeSignals

SCHEMA_VERSION = "1.0"

CSV_COLUMNS: tuple[str, ...] = (
    "run_id",
    "case_id",
    "category",
    "severity",
    "attack_goal",
    "injection_channel",
    "trial",
    "provider",
    "model_name",
    "defenses",
    "tool_provisioning",
    "outcome",
    "attack_success",
    "task_completed",
    "unauthorized_tool_call",
    "n_unauthorized_calls",
    "blocked_calls",
    "blocking_defenses",
    "secret_exposed_in_output",
    "secret_in_sink",
    "secrets_reachable",
    "system_prompt_leaked",
    "injection_reached_model",
    "payload_redacted",
    "n_tool_calls",
    "n_executed_calls",
    "attempted_tools",
    "matched_criteria",
    "truncated",
    "error",
    "wall_time_s",
)


@dataclass
class EpisodeResult:
    """One scored episode."""

    case_id: str
    category: str
    severity: str
    attack_goal: str
    injection_channel: str
    trial: int
    provider: str
    model_name: str
    defenses: list[str]
    tool_provisioning: str
    classification: ClassificationResult
    signals: EpisodeSignals
    episode: Episode | None = None
    run_id: str = ""

    # ------------------------------------------------------------- derived
    @property
    def outcome(self) -> Outcome:
        return self.classification.outcome

    @property
    def attack_success(self) -> bool:
        return self.classification.attack_success

    @property
    def is_error(self) -> bool:
        return self.classification.outcome is Outcome.ERROR

    @property
    def is_applicable(self) -> bool:
        """Counted in ASR: a real attack case that did not crash."""
        return self.classification.outcome not in (Outcome.ERROR, Outcome.NOT_APPLICABLE)

    def to_dict(self, *, include_transcript: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "category": self.category,
            "severity": self.severity,
            "attack_goal": self.attack_goal,
            "injection_channel": self.injection_channel,
            "trial": self.trial,
            "provider": self.provider,
            "model_name": self.model_name,
            "defenses": self.defenses,
            "tool_provisioning": self.tool_provisioning,
            "classification": self.classification.to_dict(),
            "signals": self.signals.to_dict(),
        }
        if self.episode is not None:
            payload["episode"] = self.episode.to_dict() if include_transcript else {
                "steps_used": self.episode.steps_used,
                "turns_used": self.episode.turns_used,
                "truncated": self.episode.truncated,
                "error": self.episode.error,
                "wall_time_s": round(self.episode.wall_time_s, 4),
            }
        return payload

    def to_csv_row(self) -> dict[str, Any]:
        ep = self.episode
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "category": self.category,
            "severity": self.severity,
            "attack_goal": self.attack_goal,
            "injection_channel": self.injection_channel,
            "trial": self.trial,
            "provider": self.provider,
            "model_name": self.model_name,
            "defenses": "+".join(self.defenses) if self.defenses else "none",
            "tool_provisioning": self.tool_provisioning,
            "outcome": self.classification.outcome.value,
            "attack_success": int(self.classification.attack_success),
            "task_completed": int(self.classification.task_completed),
            "unauthorized_tool_call": int(self.signals.has_unauthorized_attempt),
            "n_unauthorized_calls": len(self.signals.unauthorized_attempts),
            "blocked_calls": len(self.signals.blocked_calls),
            "blocking_defenses": "+".join(sorted(set(self.signals.blocking_defenses))),
            "secret_exposed_in_output": int(bool(self.signals.exposed_secrets)),
            "secret_in_sink": int(bool(self.signals.secrets_in_sink)),
            "secrets_reachable": int(self.signals.secrets_reachable),
            "system_prompt_leaked": int(self.signals.system_prompt_leaked),
            "injection_reached_model": int(self.signals.injection_reached_model),
            "payload_redacted": int(self.signals.payload_redacted),
            "n_tool_calls": len(self.signals.attempted_tools),
            "n_executed_calls": len(self.signals.executed_tools),
            "attempted_tools": "+".join(self.signals.attempted_tools),
            "matched_criteria": "|".join(self.classification.matched_criteria),
            "truncated": int(bool(ep.truncated)) if ep else 0,
            "error": (ep.error or "") if ep else "",
            "wall_time_s": round(ep.wall_time_s, 4) if ep else 0.0,
        }


@dataclass
class RunResult:
    """A complete experiment run."""

    run_metadata: dict[str, Any] = field(default_factory=dict)
    results: list[EpisodeResult] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    # ----------------------------------------------------------------- io
    def to_dict(self, *, include_transcripts: bool = True) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_metadata": self.run_metadata,
            "results": [r.to_dict(include_transcript=include_transcripts) for r in self.results],
        }

    def save_json(self, path: str | Path, *, include_transcripts: bool = True, indent: int = 2) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(include_transcripts=include_transcripts), ensure_ascii=False, indent=indent),
            "utf-8",
        )
        return target

    def save_csv(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
            writer.writeheader()
            for result in self.results:
                writer.writerow(result.to_csv_row())
        return target


def build_run_metadata(
    *,
    run_id: str,
    config: Mapping[str, Any],
    model_description: Mapping[str, Any],
    dataset_description: Mapping[str, Any],
    defenses: Sequence[str],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the provenance block stored with every run."""
    metadata: dict[str, Any] = {
        "run_id": run_id,
        "agentshield_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "config": dict(config),
        "model": dict(model_description),
        "dataset": dict(dataset_description),
        "defenses": list(defenses),
        "command_line": " ".join(sys.argv),
    }
    if extra:
        metadata.update(extra)
    return metadata


# --------------------------------------------------------------------------
# loading (analysis side)
# --------------------------------------------------------------------------


def load_results(path: str | Path) -> dict[str, Any]:
    """Load one results JSON file, validating its envelope."""
    target = Path(path)
    payload = json.loads(target.read_text("utf-8"))
    if not isinstance(payload, Mapping) or "results" not in payload:
        raise ValueError(f"{target}: not an AgentShield results file (missing 'results')")
    version = str(payload.get("schema_version", "0"))
    if version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise ValueError(f"{target}: unsupported schema_version {version!r} (expected {SCHEMA_VERSION})")
    return dict(payload)


def iter_result_files(paths: Iterable[str | Path]) -> list[Path]:
    """Expand a list of files/directories into a sorted list of results files."""
    files: list[Path] = []
    for raw in paths:
        target = Path(raw)
        if target.is_dir():
            files.extend(sorted(p for p in target.rglob("*.json") if not p.name.endswith(".summary.json")))
        elif target.exists():
            files.append(target)
        else:
            raise FileNotFoundError(f"No such results file or directory: {target}")
    unique: list[Path] = []
    for file in files:
        if file not in unique:
            unique.append(file)
    return unique


def flatten_records(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten a loaded results file into analysis-friendly row dicts."""
    metadata = payload.get("run_metadata", {}) or {}
    rows: list[dict[str, Any]] = []
    for record in payload.get("results", []):
        classification = record.get("classification", {}) or {}
        signals = record.get("signals", {}) or {}
        episode = record.get("episode", {}) or {}
        rows.append(
            {
                "run_id": record.get("run_id") or metadata.get("run_id", ""),
                "case_id": record.get("case_id", ""),
                "category": record.get("category", ""),
                "severity": record.get("severity", ""),
                "attack_goal": record.get("attack_goal", ""),
                "injection_channel": record.get("injection_channel", ""),
                "trial": record.get("trial", 0),
                "provider": record.get("provider", ""),
                "model_name": record.get("model_name", ""),
                "defenses": record.get("defenses", []) or [],
                "defense_label": "+".join(record.get("defenses", []) or []) or "none",
                "tool_provisioning": record.get("tool_provisioning", "minimal"),
                "outcome": classification.get("outcome", ""),
                "attack_success": bool(classification.get("attack_success", False)),
                "task_completed": bool(classification.get("task_completed", False)),
                "matched_criteria": classification.get("matched_criteria", []) or [],
                "unauthorized_tool_call": bool(signals.get("unauthorized_attempts")),
                "n_unauthorized_calls": len(signals.get("unauthorized_attempts") or []),
                "blocked_calls": len(signals.get("blocked_calls") or []),
                "blocking_defenses": sorted(set(signals.get("blocking_defenses") or [])),
                "secret_exposed": bool(signals.get("exposed_secrets")) or bool(signals.get("secrets_in_sink")),
                "secret_in_sink": bool(signals.get("secrets_in_sink")),
                "secrets_reachable": bool(signals.get("secrets_reachable")),
                "system_prompt_leaked": bool(signals.get("system_prompt_leaked")),
                "injection_reached_model": bool(signals.get("injection_reached_model")),
                "attempted_tools": signals.get("attempted_tools") or [],
                "n_tool_calls": len(signals.get("attempted_tools") or []),
                "truncated": bool(episode.get("truncated", False)),
                "error": episode.get("error") or "",
                "wall_time_s": episode.get("wall_time_s", 0.0),
            }
        )
    return rows
