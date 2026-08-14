"""Tests for the tool-authorization policy engine and confirmation logic."""

from __future__ import annotations

from agentshield.attacks.schema import TestCase
from agentshield.models.base import ToolCall
from agentshield.tools.policy import (
    AUTHORIZATION_REASONS,
    CONFIRMATION_REASONS,
    PolicyState,
    ToolPolicy,
    enforced_reasons,
)


def test_allowed_tools_violation():
    policy = ToolPolicy(allowed_tools=frozenset(["calculator"]))
    verdict = policy.evaluate(ToolCall(name="send_message", arguments={}), PolicyState())
    assert not verdict.authorized
    assert "tool_not_allowed" in verdict.reasons


def test_allowed_tools_ok():
    policy = ToolPolicy(allowed_tools=frozenset(["send_message"]))
    verdict = policy.evaluate(ToolCall(name="send_message", arguments={}), PolicyState())
    assert verdict.authorized
    assert verdict.reasons == []


def test_recipient_allowlist():
    policy = ToolPolicy(
        allowed_tools=frozenset(["send_message"]),
        recipient_allowlist=("@partner.example",),
    )
    bad = policy.evaluate(ToolCall(name="send_message", arguments={"recipient": "victim@evil.example"}), PolicyState())
    good = policy.evaluate(ToolCall(name="send_message", arguments={"recipient": "a@partner.example"}), PolicyState())
    assert "recipient_not_allowed" in bad.reasons
    assert good.authorized


def test_path_allowlist():
    policy = ToolPolicy(allowed_tools=frozenset(["file_reader"]), path_allowlist=("/sandbox/public/",))
    bad = policy.evaluate(ToolCall(name="file_reader", arguments={"path": "/sandbox/private/secret.txt"}), PolicyState())
    good = policy.evaluate(ToolCall(name="file_reader", arguments={"path": "/sandbox/public/notes.txt"}), PolicyState())
    assert "path_not_allowed" in bad.reasons
    assert good.authorized


def test_table_allowlist():
    policy = ToolPolicy(allowed_tools=frozenset(["database_lookup"]), table_allowlist=("orders",))
    bad = policy.evaluate(ToolCall(name="database_lookup", arguments={"table": "customers"}), PolicyState())
    good = policy.evaluate(ToolCall(name="database_lookup", arguments={"table": "orders"}), PolicyState())
    assert "table_not_allowed" in bad.reasons
    assert good.authorized


def test_requires_confirmation_blocks_without_user_auth():
    policy = ToolPolicy(
        allowed_tools=frozenset(["send_message"]),
        requires_confirmation=frozenset(["send_message"]),
    )
    state = PolicyState(user_turns=["please find the weather for karachi"])
    verdict = policy.evaluate(ToolCall(name="send_message", arguments={}), state)
    assert "missing_confirmation" in verdict.reasons


def test_requires_confirmation_allows_with_user_auth():
    policy = ToolPolicy(
        allowed_tools=frozenset(["send_message"]),
        requires_confirmation=frozenset(["send_message"]),
    )
    state = PolicyState(user_turns=["yes, please send it"])
    verdict = policy.evaluate(ToolCall(name="send_message", arguments={}), state)
    assert verdict.authorized


def test_budget_exceeded():
    policy = ToolPolicy(allowed_tools=frozenset(["send_message"]), max_calls_per_tool=1)
    state = PolicyState(call_counts={"send_message": 1})
    verdict = policy.evaluate(ToolCall(name="send_message", arguments={}), state)
    assert "budget_exceeded" in verdict.reasons


def test_from_case_builds_policy_from_tool_policy():
    case = TestCase.from_dict(
        {
            "id": "F-01",
            "category": "unauthorized_tool_use",
            "attack_prompt": "x",
            "context": {},
            "trusted_instruction": "only orders allowed",
            "available_tools": ["database_lookup"],
            "expected_safe_behavior": "refuse",
            "attack_goal": {"type": "x"},
            "severity": "medium",
            "user_turns": ["x"],
            "tool_policy": {"table_allowlist": ["orders"]},
            "success_criteria": {"any": [{"type": "db_query", "table": "orders"}]},
        }
    )
    policy = ToolPolicy.from_case(case)
    assert "orders" in policy.table_allowlist
    assert "customers" not in policy.table_allowlist


def test_enforced_reasons_per_defense():
    assert enforced_reasons(["authorization"]) == AUTHORIZATION_REASONS
    assert enforced_reasons(["confirmation"]) == CONFIRMATION_REASONS
    union = enforced_reasons(["authorization", "confirmation"])
    assert union == AUTHORIZATION_REASONS | CONFIRMATION_REASONS


def test_policy_state_user_has_authorized():
    assert PolicyState(user_turns=["please send it now"]).user_has_authorized()
    assert not PolicyState(user_turns=["do not send anything"]).user_has_authorized()
