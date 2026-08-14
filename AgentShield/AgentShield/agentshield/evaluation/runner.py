"""Experiment runner: cases x trials -> scored episodes.

One *condition* = (model, dataset, defense set, tool provisioning). The runner
executes every (case, trial) pair under that condition, scores it, and returns a
:class:`~agentshield.evaluation.results.RunResult`.

Determinism
-----------
With ``--model mock`` the whole pipeline is deterministic: the sandbox is rebuilt
per episode, the mock's Bernoulli draw is a hash of
``(seed, model, case_id, trial, turn)``, and nothing else consults a random source.
Re-running the same command reproduces every episode byte-for-byte (modulo
timestamps and wall-clock fields).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from ..agents.tool_agent import ToolUsingAgent
from ..attacks.dataset import Dataset
from ..attacks.schema import TestCase
from ..defenses.pipeline import DefensePipeline
from ..models.base import ModelAdapter
from ..tools.builtin import TOOLS_BY_NAME
from ..tools.policy import ToolPolicy
from ..tools.registry import ToolRegistry
from ..tools.sandbox import Sandbox
from .classifier import OutcomeClassifier, Outcome
from .detectors import detect_signals
from .results import EpisodeResult, RunResult, build_run_metadata

ProgressHook = Callable[[str], None]


def _default_progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class RunnerConfig:
    """Knobs for one experimental condition."""

    trials: int = 1
    max_steps: int = 6
    tool_provisioning: str = "minimal"  # "minimal" (case's tools) | "full" (all tools)
    run_id: str = "run"
    keep_transcripts: bool = True
    fail_fast: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "trials": self.trials,
            "max_steps": self.max_steps,
            "tool_provisioning": self.tool_provisioning,
            "run_id": self.run_id,
            "keep_transcripts": self.keep_transcripts,
            "fail_fast": self.fail_fast,
        }


class BenchmarkRunner:
    """Executes one condition over a dataset."""

    def __init__(
        self,
        model: ModelAdapter,
        defenses: DefensePipeline | None = None,
        config: RunnerConfig | None = None,
        *,
        progress: ProgressHook | None = _default_progress,
    ) -> None:
        self.model = model
        self.defenses = defenses or DefensePipeline()
        self.config = config or RunnerConfig()
        self.classifier = OutcomeClassifier()
        self.progress = progress

    # ------------------------------------------------------------------
    def _registry_for(self, case: TestCase) -> ToolRegistry:
        if self.config.tool_provisioning == "full":
            return ToolRegistry.all_tools()
        names = [n for n in case.available_tools if n in TOOLS_BY_NAME]
        return ToolRegistry.from_names(names)

    def run_case(self, case: TestCase, trial: int) -> EpisodeResult:
        registry = self._registry_for(case)
        policy = ToolPolicy.from_case(case, provisioned_tools=registry.names)
        agent = ToolUsingAgent(
            model=self.model,
            registry=registry,
            policy=policy,
            defenses=self.defenses,
            max_steps=self.config.max_steps,
            tool_provisioning=self.config.tool_provisioning,
        )
        episode = agent.run(case, trial=trial, sandbox=Sandbox.from_case(case))
        signals = detect_signals(episode, case, policy)
        classification = self.classifier.classify(episode, case, signals)
        return EpisodeResult(
            case_id=case.id,
            category=case.category,
            severity=case.severity,
            attack_goal=case.attack_goal.type,
            injection_channel=case.injection_channel,
            trial=trial,
            provider=getattr(self.model, "provider", "unknown"),
            model_name=self.model.model_name,
            defenses=self.defenses.names,
            tool_provisioning=self.config.tool_provisioning,
            classification=classification,
            signals=signals,
            episode=episode,
            run_id=self.config.run_id,
        )

    def run(self, dataset: Dataset | Sequence[TestCase], *, extra_metadata: dict[str, Any] | None = None) -> RunResult:
        cases: Iterable[TestCase] = dataset.cases if isinstance(dataset, Dataset) else list(dataset)
        cases = list(cases)
        total = len(cases) * self.config.trials
        results: list[EpisodeResult] = []
        counter = 0

        for trial in range(self.config.trials):
            for case in cases:
                counter += 1
                if self.progress:
                    self.progress(
                        f"[{counter}/{total}] {case.id} ({case.category}) "
                        f"trial={trial} defenses={self.defenses.label} model={self.model.model_name}"
                    )
                try:
                    result = self.run_case(case, trial)
                except Exception as exc:  # pragma: no cover - runner-level guard
                    if self.config.fail_fast:
                        raise
                    if self.progress:
                        self.progress(f"    !! {case.id}: {type(exc).__name__}: {exc}")
                    from ..agents.base import Episode
                    from .classifier import ClassificationResult
                    from .detectors import EpisodeSignals

                    empty_episode = Episode(
                        case_id=case.id,
                        category=case.category,
                        trial=trial,
                        model_name=self.model.model_name,
                        provider=getattr(self.model, "provider", "unknown"),
                        defenses=self.defenses.names,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    result = EpisodeResult(
                        case_id=case.id,
                        category=case.category,
                        severity=case.severity,
                        attack_goal=case.attack_goal.type,
                        injection_channel=case.injection_channel,
                        trial=trial,
                        provider=getattr(self.model, "provider", "unknown"),
                        model_name=self.model.model_name,
                        defenses=self.defenses.names,
                        tool_provisioning=self.config.tool_provisioning,
                        classification=ClassificationResult(
                            Outcome.ERROR, False, False, [f"runner_error:{type(exc).__name__}"]
                        ),
                        signals=EpisodeSignals(),
                        episode=empty_episode,
                        run_id=self.config.run_id,
                    )
                results.append(result)

        dataset_description = (
            dataset.describe() if isinstance(dataset, Dataset) else {"n_cases": len(cases), "source": "in-memory"}
        )
        metadata = build_run_metadata(
            run_id=self.config.run_id,
            config=self.config.to_dict(),
            model_description=self.model.describe(),
            dataset_description=dataset_description,
            defenses=self.defenses.names,
            extra={"defense_details": self.defenses.describe(), **(extra_metadata or {})},
        )
        return RunResult(run_metadata=metadata, results=results)
