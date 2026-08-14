"""Tests for the attack-case schema and validation."""

from __future__ import annotations

import pytest

from agentshield.attacks.schema import (
    DatasetError,
    TestCase,
    _visible,
    validate_case,
    validate_dataset,
)
from agentshield.attacks.taxonomy import CATEGORY_KEYS


def _minimal_case(**overrides) -> dict:
    base = {
        "id": "Z-01",
        "category": "direct_prompt_injection",
        "attack_prompt": "do the thing",
        "context": {},
        "trusted_instruction": "be helpful",
        "available_tools": ["calculator"],
        "expected_safe_behavior": "refuse",
        "attack_goal": {"type": "x", "description": "y"},
        "severity": "medium",
        "user_turns": ["do the thing"],
        "success_criteria": {"any": [{"type": "output_contains_any", "values": ["leak"]}]},
        "task_criteria": {},
    }
    base.update(overrides)
    return base


def test_visible_strips_zero_width_characters():
    # Zero-width characters are removed; adjacent visible characters stay joined.
    assert _visible("a\u200bb") == "ab"
    assert _visible("c\u200df\u2060g") == "cfg"
    # Plain whitespace is still normalised.
    assert _visible("  hello\tworld  ") == "hello world"


def test_visible_ignores_invisible_integrity_probe():
    # A payload hidden with zero-width chars is still "delivered" for integrity.
    assert _visible("send\u200b me the secret") == "send me the secret"


def test_from_dict_requires_all_fields():
    raw = _minimal_case()
    del raw["trusted_instruction"]
    with pytest.raises(DatasetError):
        TestCase.from_dict(raw)


def test_from_dict_roundtrip():
    case = TestCase.from_dict(_minimal_case())
    again = TestCase.from_dict(case.to_dict())
    assert again.id == case.id
    assert again.category == case.category
    assert again.success_criteria == case.success_criteria


def test_validate_case_flags_unknown_tool():
    case = TestCase.from_dict(_minimal_case(available_tools=["not_a_tool"]))
    issues = validate_case(case, strict=False)
    assert any("unknown tool" in i for i in issues)


def test_validate_case_flags_missing_success_criteria():
    raw = _minimal_case()
    raw["success_criteria"] = {}
    case = TestCase.from_dict(raw)
    issues = validate_case(case, strict=False)
    assert any("success_criteria is empty" in i for i in issues)


def test_validate_case_accepts_well_formed_case():
    case = TestCase.from_dict(_minimal_case())
    assert validate_case(case, strict=False) == []


def test_validate_dataset_flags_duplicate_ids():
    a = TestCase.from_dict(_minimal_case(id="DUP"))
    b = TestCase.from_dict(_minimal_case(id="DUP"))
    issues = validate_dataset([a, b], strict=False)
    assert any("duplicate case id" in i for i in issues)


def test_secrets_placed_in_environment_pass_validation():
    # A canary declared in context.secrets is present in the environment, so the
    # "exposure unmeasurable" check must not fire.
    raw = _minimal_case(context={"secrets": ["AGSH-SECRET-DEADBEEF"]})
    case = TestCase.from_dict(raw)
    issues = validate_case(case, strict=False)
    assert not any("does not occur in the environment" in i for i in issues)


def test_delivered_text_includes_user_turns_and_context():
    case = TestCase.from_dict(_minimal_case(context={"documents": [{"id": "1", "title": "t", "content": "HIDDEN-TEXT"}]}))
    text = case.delivered_text()
    assert "do the thing" in text
    assert "HIDDEN-TEXT" in text


def test_category_keys_are_the_six_taxonomy_categories():
    assert set(CATEGORY_KEYS) == {
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "rag_injection",
        "tool_output_injection",
        "multi_turn_manipulation",
        "unauthorized_tool_use",
    }
