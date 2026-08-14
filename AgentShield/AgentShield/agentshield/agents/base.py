"""Episode data structures.

An :class:`Episode` is the complete, replayable record of one agent run against
one test case: the exact transcript the model saw, every attempted tool call with
its authorization verdict, every defense intervention, and the final answer(s).
Detectors and the outcome classifier read *only* the episode, never the model, so
scoring is deterministic and auditable after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..defenses.base import DefenseEvent
from ..tools.registry import ToolCallRecord


@dataclass
class Episode:
    """Everything observable about one agent run."""

    case_id: str
    category: str
    trial: int
    model_name: str
    provider: str
    defenses: list[str] = field(default_factory=list)
    tool_provisioning: str = "minimal"
    provisioned_tools: list[str] = field(default_factory=list)
    system_prompt: str = ""
    messages: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    assistant_texts: list[str] = field(default_factory=list)
    raw_assistant_texts: list[str] = field(default_factory=list)
    defense_events: list[DefenseEvent] = field(default_factory=list)
    sandbox_snapshot: dict[str, Any] = field(default_factory=dict)
    steps_used: int = 0
    turns_used: int = 0
    truncated: bool = False
    error: str | None = None
    wall_time_s: float = 0.0
    model_debug: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------- helpers
    @property
    def final_output(self) -> str:
        return self.assistant_texts[-1] if self.assistant_texts else ""

    @property
    def all_output(self) -> str:
        """Concatenation of every assistant message (disclosure can happen anywhere)."""
        return "\n".join(self.assistant_texts)

    @property
    def outbox(self) -> list[dict[str, Any]]:
        return list(self.sandbox_snapshot.get("outbox") or [])

    def executed_calls(self) -> list[ToolCallRecord]:
        return [r for r in self.tool_calls if r.executed]

    def unauthorized_calls(self) -> list[ToolCallRecord]:
        return [r for r in self.tool_calls if not r.verdict.authorized]

    def blocked_calls(self) -> list[ToolCallRecord]:
        return [r for r in self.tool_calls if r.blocked_by]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "trial": self.trial,
            "model_name": self.model_name,
            "provider": self.provider,
            "defenses": self.defenses,
            "tool_provisioning": self.tool_provisioning,
            "provisioned_tools": self.provisioned_tools,
            "system_prompt": self.system_prompt,
            "messages": self.messages,
            "tool_calls": [r.to_dict() for r in self.tool_calls],
            "assistant_texts": self.assistant_texts,
            "raw_assistant_texts": self.raw_assistant_texts,
            "defense_events": [e.to_dict() for e in self.defense_events],
            "sandbox_snapshot": self.sandbox_snapshot,
            "steps_used": self.steps_used,
            "turns_used": self.turns_used,
            "truncated": self.truncated,
            "error": self.error,
            "wall_time_s": round(self.wall_time_s, 4),
            "model_debug": self.model_debug,
        }
