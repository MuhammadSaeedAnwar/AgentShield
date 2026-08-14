"""Tests for loading and filtering the attack dataset."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agentshield.attacks.dataset import DatasetError, load_dataset

ROOT = Path(__file__).resolve().parents[1]


def test_load_dataset_returns_thirty_cases(dataset):
    assert len(dataset) == 30


def test_load_dataset_has_five_per_category(dataset):
    counts = dataset.counts_by_category()
    assert len(counts) == 6
    assert all(c == 5 for c in counts.values())


def test_load_dataset_source_and_sha(dataset):
    assert dataset.source.endswith("attacks.json")
    assert len(dataset.sha256) == 64  # sha256 hex digest


def test_load_dataset_from_directory(tmp_path):
    # Point at a directory of *.json files (the authoring sources).
    ds = load_dataset(str(ROOT / "data" / "cases"))
    assert len(ds) == 30


def test_filter_by_category(dataset):
    subset = dataset.filter(categories=["rag_injection"])
    assert len(subset) == 5
    assert all(c.category == "rag_injection" for c in subset)


def test_filter_by_ids(dataset):
    subset = dataset.filter(ids=["A-01", "C-03", "F-05"])
    assert {c.id for c in subset} == {"A-01", "C-03", "F-05"}


def test_filter_by_severity(dataset):
    subset = dataset.filter(severities=["critical"])
    assert len(subset) > 0
    assert all(c.severity == "critical" for c in subset)


def test_filter_limit(dataset):
    subset = dataset.filter(limit=3)
    assert len(subset) == 3


def test_load_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_dataset(str(ROOT / "data" / "does_not_exist.json"))


def test_load_invalid_dataset_does_not_validate():
    # A directory of authoring files is valid; here we force `validate=False`.
    ds = load_dataset(str(ROOT / "data" / "cases"), validate=False)
    assert len(ds) == 30


def test_build_dataset_script_rebuilds_artifact():
    """scripts/build_dataset.py must run and write a 30-case, valid artefact."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_dataset.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    ds = load_dataset(str(ROOT / "data" / "attacks.json"))
    assert len(ds) == 30
