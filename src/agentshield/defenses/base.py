"""Defense interface."""

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
    text: str
    events: list[DefenseEvent] = field(default_factory=list)


class Defense:
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
        return None, []

    def filter_final_output(self, text: str, case: Any, system_prompt: str) -> FilterOutcome:
        return FilterOutcome(text)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description}
