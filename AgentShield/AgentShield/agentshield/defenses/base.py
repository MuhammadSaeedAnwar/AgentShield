"""Defense interface.

A defense is a set of hooks around the agent loop. Each hook is optional; the
pipeline calls whichever ones a defense implements:

=========================  ==================================================
Hook                       Purpose
=========================  ==================================================
``build_system_prompt``    Rewrite the trusted system prompt.
``filter_user_turn``       Transform an incoming user message.
``filter_tool_output``     Transform untrusted tool output before the model sees it.
``gate_tool_call``         Veto a tool call (returns a block reason or ``None``).
``filter_final_output``    Transform the agent's answer before it is emitted.
=========================  ==================================================

Every intervention is recorded as a :class:`DefenseEvent` so that results can
attribute an averted attack to a specific mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models.base import ToolCall
from ..tools.policy import AuthorizationVerdict, PolicyState


@dataclass
class DefenseEvent:
    defense: str
    hook: str
    action: str
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "defense": self.defense,
            "hook": self.hook,
            "action": self.action,
            "detail": self.detail,
            "metadata": self.metadata,
        }


@dataclass
class FilterOutcome:
    """Result of a text-filtering hook."""

    text: str
    events: list[DefenseEvent] = field(default_factory=list)


class Defense:
    """Base class: every hook defaults to a no-op."""

    name: str = "defense"
    description: str = ""

    def build_system_prompt(self, system_prompt: str, case: Any) -> FilterOutcome:
        return FilterOutcome(system_prompt)

    def filter_user_turn(self, text: str, case: Any) -> FilterOutcome:
        return FilterOutcome(text)

    def filter_tool_output(self, tool_name: str, text: str, case: Any) -> FilterOutcome:
        return FilterOutcome(text)

    def gate_tool_call(
        self,
        call: ToolCall,
        verdict: AuthorizationVerdict,
        state: PolicyState,
        case: Any,
    ) -> tuple[str | None, list[DefenseEvent]]:
        """Return ``(block_reason, events)``; ``block_reason=None`` allows the call."""
        return None, []

    def filter_final_output(self, text: str, case: Any, system_prompt: str) -> FilterOutcome:
        return FilterOutcome(text)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description}
