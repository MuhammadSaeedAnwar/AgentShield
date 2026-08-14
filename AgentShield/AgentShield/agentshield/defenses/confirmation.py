"""Defense 4: confirmation requirement before sensitive actions.

Mechanism
---------
A tool listed in the case's ``requires_confirmation`` set may only run if an
explicit approval phrase appears in a *user-channel* message (see
``agentshield.tools.policy.APPROVAL_RE``). Approval found in untrusted content
never counts -- that is the whole point: a document cannot consent on the user's
behalf.

When a call is blocked, the tool result handed back to the model is an
instruction to ask the user for authorization, so the agent can still complete
the conversation gracefully.

Known limitation
----------------
Phrase-matched consent is coarse: it is action-agnostic (a "yes, send it" for one
recipient authorises the tool for that turn) and it can be spoofed if the user's
own words are quoted back by an attacker who controls the user channel. This is
recorded as a threat to validity in the README rather than papered over.
"""

from __future__ import annotations

from typing import Any

from ..models.base import ToolCall
from ..tools.policy import CONFIRMATION_REASONS, AuthorizationVerdict, PolicyState
from .base import Defense, DefenseEvent


class ConfirmationDefense(Defense):
    name = "confirmation"
    description = "Requires explicit user authorization in the user channel before a sensitive tool runs."
    enforced_reasons = CONFIRMATION_REASONS

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
        detail = "; ".join(v.detail for v in hits)
        return (
            self.name,
            [
                DefenseEvent(
                    self.name,
                    "gate_tool_call",
                    "blocked",
                    f"'{call.name}' requires user confirmation ({detail})",
                    {"tool": call.name, "reasons": [v.reason for v in hits]},
                )
            ],
        )
