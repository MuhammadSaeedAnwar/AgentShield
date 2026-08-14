"""Dataset loading and filtering."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .schema import DatasetError, TestCase, validate_dataset


@dataclass
class Dataset:
    """An ordered collection of test cases plus provenance metadata."""

    cases: list[TestCase] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    sha256: str = ""

    def __iter__(self) -> Iterator[TestCase]:
        return iter(self.cases)

    def __len__(self) -> int:
        return len(self.cases)

    def __getitem__(self, index: int) -> TestCase:
        return self.cases[index]

    @property
    def ids(self) -> list[str]:
        return [c.id for c in self.cases]

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for case in self.cases:
            if case.category not in seen:
                seen.append(case.category)
        return seen

    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.category] = counts.get(case.category, 0) + 1
        return counts

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.severity] = counts.get(case.severity, 0) + 1
        return counts

    def filter(
        self,
        *,
        categories: Iterable[str] | None = None,
        ids: Iterable[str] | None = None,
        severities: Iterable[str] | None = None,
        limit: int | None = None,
    ) -> "Dataset":
        cases = list(self.cases)
        if categories:
            wanted = {c.strip().lower() for c in categories}
            cases = [c for c in cases if c.category.lower() in wanted]
        if ids:
            wanted_ids = {i.strip().upper() for i in ids}
            cases = [c for c in cases if c.id.upper() in wanted_ids]
        if severities:
            wanted_sev = {s.strip().lower() for s in severities}
            cases = [c for c in cases if c.severity.lower() in wanted_sev]
        if limit is not None:
            cases = cases[: max(0, limit)]
        return Dataset(cases=cases, metadata=dict(self.metadata), source=self.source, sha256=self.sha256)

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sha256": self.sha256,
            "n_cases": len(self.cases),
            "case_ids": self.ids,
            "counts_by_category": self.counts_by_category(),
            "counts_by_severity": self.counts_by_severity(),
            "metadata": self.metadata,
        }


def _parse_payload(payload: Any, source: str) -> tuple[list[Mapping[str, Any]], dict[str, Any]]:
    """Accept either ``{"metadata": {...}, "cases": [...]}`` or a bare list."""
    if isinstance(payload, Mapping):
        raw_cases = payload.get("cases")
        if raw_cases is None:
            raise DatasetError(f"{source}: object datasets must contain a 'cases' list")
        metadata = {k: v for k, v in payload.items() if k != "cases"}
    elif isinstance(payload, Sequence):
        raw_cases, metadata = payload, {}
    else:
        raise DatasetError(f"{source}: unsupported dataset payload type {type(payload).__name__}")

    if not isinstance(raw_cases, Sequence):
        raise DatasetError(f"{source}: 'cases' must be a list")
    out: list[Mapping[str, Any]] = []
    for index, item in enumerate(raw_cases):
        if not isinstance(item, Mapping):
            raise DatasetError(f"{source}: case #{index} must be an object, got {type(item).__name__}")
        out.append(item)
    return out, dict(metadata)


def load_dataset(
    path: str | Path,
    *,
    strict: bool = True,
    validate: bool = True,
) -> Dataset:
    """Load a dataset from a JSON file (or a directory of JSON files).

    Parameters
    ----------
    path:
        JSON file, or a directory whose ``*.json`` files are concatenated in
        sorted filename order.
    strict:
        Include integrity checks (e.g. "the documented payload is actually
        delivered to the agent").
    validate:
        Raise :class:`DatasetError` when validation finds problems. Set to
        ``False`` only when deliberately loading a malformed dataset in a test.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Dataset not found: {target}")

    files = sorted(target.glob("*.json")) if target.is_dir() else [target]
    if not files:
        raise DatasetError(f"No .json dataset files found in directory {target}")

    raw_cases: list[Mapping[str, Any]] = []
    metadata: dict[str, Any] = {}
    hasher = hashlib.sha256()
    for file in files:
        text = file.read_text("utf-8")
        hasher.update(text.encode("utf-8"))
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DatasetError(f"{file}: invalid JSON ({exc})") from exc
        cases, meta = _parse_payload(payload, str(file))
        raw_cases.extend(cases)
        metadata.update(meta)

    cases = [TestCase.from_dict(raw) for raw in raw_cases]
    dataset = Dataset(
        cases=cases,
        metadata=metadata,
        source=str(target),
        sha256=hasher.hexdigest(),
    )

    issues = validate_dataset(cases, strict=strict)
    if issues:
        if validate:
            listing = "\n  - ".join(issues[:25])
            more = f"\n  ... and {len(issues) - 25} more" if len(issues) > 25 else ""
            raise DatasetError(f"Dataset validation failed for {target} ({len(issues)} issue(s)):\n  - {listing}{more}")
        dataset.metadata["validation_issues"] = issues
    return dataset
