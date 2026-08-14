"""Defense 2: tool authorization checks (enforcement of the policy engine).

The policy engine in :mod:`agentshield.tools.policy` always *audits* calls. This
defense is what turns an audit finding into a blocked call, for the violation
classes ``tool_not_allowed``, ``recipient_not_allowed``, ``path_not_allowed``,
``table_not_allowed`` and ``budget_exceeded``.

Unlike the prompt-level defenses, this one does not depend on the model's
cooperation: it sits between the model's requested action and the environment.
That property is exactly what the benchmark is designed to expose.
"""

from __future__ import annotations

from typing import Any

from ..models.base import ToolCall
from ..tools.policy import AUTHORIZATION_REASONS, AuthorizationVerdict, PolicyState
from .base import Defense, DefenseEvent


class ToolAuthorizationDefense(Defense):
    name = "authorization"
    description = "Blocks tool calls that violate the case's authorization policy (allowlists, budgets)."
    enforced_reasons = AUTHORIZATION_REASONS

    def gate_tool_call(
        self,
        call: ToolCall,
        verdict: AuthorizationVerdict,
        state: PolicyState,
        case: Any,
    ) -> tuple[str | None, list[DefenseEvent]]:
        hits = [v for v in verdict.violations if v.reason in self.enforced_reasons]
        if not hits:
            return None, []
        detail = "; ".join(f"{v.reason}: {v.detail}" for v in hits)
        return (
            self.name,
            [
                DefenseEvent(
                    self.name,
                    "gate_tool_call",
                    "blocked",
                    f"blocked call to '{call.name}' ({detail})",
                    {"tool": call.name, "reasons": [v.reason for v in hits]},
                )
            ],
        )
