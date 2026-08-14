"""Defense 5: output and tool-call validation (egress filtering).

Two enforcement points, both independent of the model's cooperation:

1. ``gate_tool_call`` -- a call to a *sink* tool (one that moves data out of the
   session, i.e. ``send_message``) is blocked when its arguments contain
   secret-shaped strings or a verbatim chunk of the system prompt.
2. ``filter_final_output`` -- the agent's answer is scanned with the same rules;
   matches are redacted and a notice is appended.

Coverage is deliberately partial: the DLP rules recognise *formatted* secrets
(structured tokens, key-shaped strings, card/IBAN-shaped numbers) and verbatim
system-prompt text, but not unformatted business secrets such as an internal
project code name. The benchmark measures the residual leakage instead of
assuming the filter is complete.
"""

from __future__ import annotations

from typing import Any

from ..models.base import ToolCall
from ..tools.policy import AuthorizationVerdict, PolicyState
from .base import Defense, DefenseEvent, FilterOutcome
from .patterns import SECRET_RULES, apply_rules, find_secret_matches, shingles

SHINGLE_SIZE = 12
NOTICE = (
    "\n\n[AgentShield egress filter] Content matching a sensitive-data pattern was "
    "removed from this response ({rules})."
)


class OutputValidationDefense(Defense):
    name = "output_validation"
    description = "Egress filter: redacts secret-shaped strings and system-prompt text; blocks leaky sink calls."

    def __init__(self, *, shingle_size: int = SHINGLE_SIZE) -> None:
        self.shingle_size = shingle_size

    # ------------------------------------------------------------- helpers
    def _leaks_system_prompt(self, text: str, system_prompt: str) -> bool:
        if not text or not system_prompt:
            return False
        target = shingles(system_prompt, self.shingle_size)
        if not target:
            return False
        return bool(target & shingles(text, self.shingle_size))

    # --------------------------------------------------------------- hooks
    def gate_tool_call(
        self,
        call: ToolCall,
        verdict: AuthorizationVerdict,
        state: PolicyState,
        case: Any,
    ) -> tuple[str | None, list[DefenseEvent]]:
        if call.name != "send_message":  # the only egress sink in this environment
            return None, []
        blob = " ".join(str(v) for v in call.arguments.values())
        rules = find_secret_matches(blob)
        if self._leaks_system_prompt(blob, getattr(case, "trusted_instruction", "")):
            rules.append("system_prompt_verbatim")
        if not rules:
            return None, []
        return (
            self.name,
            [
                DefenseEvent(
                    self.name,
                    "gate_tool_call",
                    "blocked",
                    f"blocked '{call.name}': arguments matched egress rule(s) {', '.join(rules)}",
                    {"tool": call.name, "rules": rules},
                )
            ],
        )

    def filter_final_output(self, text: str, case: Any, system_prompt: str) -> FilterOutcome:
        cleaned, fired = apply_rules(text, SECRET_RULES)
        if self._leaks_system_prompt(cleaned, system_prompt):
            cleaned = self._redact_system_prompt(cleaned, system_prompt)
            fired.append("system_prompt_verbatim")
        if not fired:
            return FilterOutcome(text)
        cleaned = cleaned + NOTICE.format(rules=", ".join(sorted(set(fired))))
        return FilterOutcome(
            cleaned,
            [
                DefenseEvent(
                    self.name,
                    "filter_final_output",
                    "redacted",
                    f"redacted final answer (rules: {', '.join(sorted(set(fired)))})",
                    {"rules": sorted(set(fired))},
                )
            ],
        )

    def _redact_system_prompt(self, text: str, system_prompt: str) -> str:
        """Drop output lines that reproduce system-prompt content verbatim."""
        target = shingles(system_prompt, self.shingle_size)
        kept: list[str] = []
        for line in text.split("\n"):
            if len(line.split()) >= self.shingle_size and (shingles(line, self.shingle_size) & target):
                kept.append("[REDACTED-BY-AGENTSHIELD:system_prompt_verbatim]")
            else:
                kept.append(line)
        return "\n".join(kept)
