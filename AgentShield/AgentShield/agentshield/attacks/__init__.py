"""Attack dataset: schema, loading, taxonomy."""

from __future__ import annotations

from .dataset import Dataset, load_dataset
from .schema import (
    CRITERION_TYPES,
    REQUIRED_FIELDS,
    AttackGoal,
    DatasetError,
    TestCase,
    validate_case,
    validate_dataset,
)
from .taxonomy import (
    CATEGORIES,
    CATEGORY_BY_LETTER,
    CATEGORY_KEYS,
    INJECTION_CHANNELS,
    SEVERITIES,
    CategoryInfo,
    category_label,
    category_letter,
)

__all__ = [
    "AttackGoal",
    "CATEGORIES",
    "CATEGORY_BY_LETTER",
    "CATEGORY_KEYS",
    "CRITERION_TYPES",
    "CategoryInfo",
    "Dataset",
    "DatasetError",
    "INJECTION_CHANNELS",
    "REQUIRED_FIELDS",
    "SEVERITIES",
    "TestCase",
    "category_label",
    "category_letter",
    "load_dataset",
    "validate_case",
    "validate_dataset",
]
