"""Tests for metric computation, Wilson intervals, and defense comparison."""

from __future__ import annotations

import pytest

from agentshield.metrics.core import (
    DefenseComparison,
    Metric,
    attack_success_rate,
    compare_defense,
    compute_metrics,
    sensitive_information_exposure_rate,
    unauthorized_tool_call_rate,
)
from agentshield.metrics.stats import two_proportion_z_test, wilson_interval


def test_wilson_interval_undefined_for_zero_denominator():
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_interval_is_symmetric_bounds_within_unit():
    low, high = wilson_interval(10, 10)
    assert 0.0 < low < high <= 1.0


def test_wilson_interval_lower_bound_zero_for_no_successes():
    low, high = wilson_interval(0, 20)
    assert low == 0.0
    assert 0.0 < high < 1.0


def test_wilson_interval_contains_point_estimate():
    low, high = wilson_interval(5, 20)
    assert low <= 0.25 <= high


def test_metric_value_and_percent():
    from agentshield.metrics.core import _metric

    m = _metric("attack_success_rate", 9, 30)
    assert m.value == pytest.approx(0.3)
    assert m.percent == pytest.approx(30.0)
    assert m.ci_low < m.ci_high


def test_metric_zero_denominator_is_none():
    m = Metric("x", 0, 0)
    assert m.value is None
    assert m.percent is None
    assert "n/a" in m.format()


def test_attack_success_rate_counts_applicable():
    rows = [{"outcome": "attack_success", "attack_success": True}] * 6
    rows += [{"outcome": "safe_completion", "attack_success": False}] * 4
    rows += [{"outcome": "error", "attack_success": False}] * 2  # excluded
    m = attack_success_rate(rows)
    assert m.numerator == 6
    assert m.denominator == 10
    assert m.value == pytest.approx(0.6)


def test_sensitive_information_exposure_rate_denominator():
    # Only episodes where a canary was reachable count.
    rows = [
        {"outcome": "attack_success", "secrets_reachable": True, "secret_exposed": True},
        {"outcome": "attack_success", "secrets_reachable": True, "secret_exposed": False},
        {"outcome": "attack_success", "secrets_reachable": False, "secret_exposed": True},  # ignored
    ]
    m = sensitive_information_exposure_rate(rows)
    assert m.denominator == 2
    assert m.numerator == 1


def test_unauthorized_tool_call_rate():
    rows = [
        {"outcome": "safe_incomplete", "unauthorized_tool_call": True},
        {"outcome": "safe_incomplete", "unauthorized_tool_call": True},
        {"outcome": "safe_completion", "unauthorized_tool_call": False},
    ]
    m = unauthorized_tool_call_rate(rows)
    assert m.numerator == 2
    assert m.denominator == 3


def test_compute_metrics_returns_all_headline_and_supporting():
    rows = [{"outcome": "safe_completion", "attack_success": False, "task_completed": True}] * 10
    metrics = compute_metrics(rows)
    for name in (
        "attack_success_rate",
        "safe_completion_rate",
        "unauthorized_tool_call_rate",
        "sensitive_information_exposure_rate",
        "task_completion_rate",
        "blocked_call_rate",
        "system_prompt_leak_rate",
        "injection_delivery_rate",
        "error_rate",
    ):
        assert name in metrics


def test_compare_defense_computes_dsr():
    base = []
    defended = []
    for i in range(3):
        base.append(
            {
                "case_id": f"A-0{i}",
                "trial": 0,
                "model_name": "mock",
                "tool_provisioning": "minimal",
                "defense_label": "none",
                "outcome": "attack_success",
                "attack_success": True,
            }
        )
        defended.append(
            {
                "case_id": f"A-0{i}",
                "trial": 0,
                "model_name": "mock",
                "tool_provisioning": "minimal",
                "defense_label": "authorization",
                "outcome": "safe_completion",
                "attack_success": False,
            }
        )
    comp = compare_defense(base, defended)
    assert isinstance(comp, DefenseComparison)
    assert comp.defense_success_rate.value == pytest.approx(1.0)
    assert comp.baseline_asr.value == pytest.approx(1.0)
    assert comp.defended_asr.value == pytest.approx(0.0)
    assert comp.n_paired == 3


def test_compare_defense_ignores_unpaired_rows():
    base = [{"case_id": "A-01", "trial": 0, "model_name": "mock", "tool_provisioning": "minimal",
             "defense_label": "none", "outcome": "attack_success", "attack_success": True}]
    defended = [{"case_id": "B-02", "trial": 0, "model_name": "mock", "tool_provisioning": "minimal",
                 "defense_label": "authorization", "outcome": "safe_completion", "attack_success": False}]
    comp = compare_defense(base, defended)
    assert comp.n_paired == 0


def test_two_proportion_z_test_returns_valid_p():
    z, p = two_proportion_z_test(30, 90, 0, 90)
    assert isinstance(z, float)
    assert 0.0 <= p <= 1.0
