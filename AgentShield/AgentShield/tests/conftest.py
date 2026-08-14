"""Shared pytest fixtures for the AgentShield test suite.

These fixtures build the *real* dataset and agent objects so that unit tests
exercise the actual harness rather than mocks of the harness.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "data" / "attacks.json"


@pytest.fixture(scope="session")
def dataset_path() -> Path:
    """Absolute path to the canonical built dataset."""
    return DATASET_PATH


@pytest.fixture(scope="session")
def dataset():
    """Loaded canonical 30-case dataset (validated on load)."""
    from agentshield.attacks.dataset import load_dataset

    return load_dataset(str(DATASET_PATH))


@pytest.fixture
def mock_model():
    """A fresh deterministic mock adapter."""
    from agentshield.models.mock import MockModelAdapter

    return MockModelAdapter(seed=1337, model_name="mock-gullible-v1")


@pytest.fixture
def sample_case():
    """A single real case (A-01, direct prompt injection) for end-to-end tests."""
    from agentshield.attacks.dataset import load_dataset

    ds = load_dataset(str(DATASET_PATH))
    return next(c for c in ds.cases if c.id == "A-01")


def run_single_case(case, *, defenses=(), trials=1, seed=1337, max_steps=6, tool_provisioning="minimal"):
    """Drive one case through a full episode and return the RunResult.

    A small convenience wrapper used by several tests so they exercise the real
    agent loop, defenses, detectors, classifier and metrics together.
    """
    from agentshield.defenses.pipeline import DefensePipeline
    from agentshield.evaluation.runner import BenchmarkRunner, RunnerConfig
    from agentshield.attacks.dataset import Dataset
    from agentshield.models.mock import MockModelAdapter

    model = MockModelAdapter(seed=seed, model_name="mock-gullible-v1")
    pipeline = DefensePipeline.from_names(list(defenses))
    runner = BenchmarkRunner(
        model,
        pipeline,
        RunnerConfig(
            trials=trials,
            max_steps=max_steps,
            tool_provisioning=tool_provisioning,
        ),
    )
    return runner.run(Dataset(cases=[case]))
