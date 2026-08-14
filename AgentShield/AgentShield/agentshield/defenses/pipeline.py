"""Defense pipeline: composes zero or more defenses around the agent loop."""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from ..models.base import ToolCall
from ..tools.policy import AuthorizationVerdict, PolicyState
from .authorization import ToolAuthorizationDefense
from .base import Defense, DefenseEvent, FilterOutcome
from .confirmation import ConfirmationDefense
from .output_validation import OutputValidationDefense
from .sanitization import InputSanitizationDefense
from .separation import TrustSeparationDefense

#: Canonical order. Text filters run input-side first (sanitise, then wrap), so
#: that the trust delimiters are never themselves redacted.
DEFENSE_CLASSES: dict[str, type[Defense]] = {
    "sanitization": InputSanitizationDefense,
    "separation": TrustSeparationDefense,
    "authorization": ToolAuthorizationDefense,
    "confirmation": ConfirmationDefense,
    "output_validation": OutputValidationDefense,
}

DEFENSE_NAMES: tuple[str, ...] = tuple(DEFENSE_CLASSES)


def parse_defense_spec(spec: str | Iterable[str] | None) -> list[str]:
    """Turn ``--defenses`` into a canonical, ordered list of defense names.

    Accepts ``"none"`` / ``""`` / ``None`` -> ``[]``, ``"all"`` -> every defense,
    or a comma-separated subset (``"authorization,confirmation"``).
    """
    if spec is None:
        return []
    if isinstance(spec, str):
        tokens = [t.strip().lower() for t in spec.split(",") if t.strip()]
    else:
        tokens = [str(t).strip().lower() for t in spec if str(t).strip()]
    if not tokens or tokens == ["none"]:
        return []
    if "all" in tokens:
        return list(DEFENSE_NAMES)
    unknown = [t for t in tokens if t not in DEFENSE_CLASSES]
    if unknown:
        raise ValueError(f"Unknown defense(s) {unknown}. Available: {list(DEFENSE_NAMES)} (or 'all' / 'none')")
    return [name for name in DEFENSE_NAMES if name in tokens]


class DefensePipeline:
    """Applies the active defenses at each hook, collecting their events."""

    def __init__(self, defenses: Sequence[Defense] | None = None) -> None:
        self.defenses: list[Defense] = list(defenses or [])

    @classmethod
    def from_names(cls, names: str | Iterable[str] | None) -> "DefensePipeline":
        return cls([DEFENSE_CLASSES[name]() for name in parse_defense_spec(names)])

    # ------------------------------------------------------------ metadata
    @property
    def names(self) -> list[str]:
        return [d.name for d in self.defenses]

    @property
    def label(self) -> str:
        """Short identifier used in filenames and result tables."""
        if not self.defenses:
            return "none"
        if len(self.defenses) == len(DEFENSE_NAMES):
            return "all"
        return "+".join(self.names)

    def describe(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.defenses]

    def __contains__(self, name: object) -> bool:
        return name in self.names

    def __len__(self) -> int:
        return len(self.defenses)

    # --------------------------------------------------------------- hooks
    def build_system_prompt(self, system_prompt: str, case: Any) -> FilterOutcome:
        text, events = system_prompt, []
        for defense in self.defenses:
            outcome = defense.build_system_prompt(text, case)
            text = outcome.text
            events.extend(outcome.events)
        return FilterOutcome(text, events)

    def filter_user_turn(self, text: str, case: Any) -> FilterOutcome:
        events: list[DefenseEvent] = []
        for defense in self.defenses:
            outcome = defense.filter_user_turn(text, case)
            text = outcome.text
            events.extend(outcome.events)
        return FilterOutcome(text, events)

    def filter_tool_output(self, tool_name: str, text: str, case: Any) -> FilterOutcome:
        events: list[DefenseEvent] = []
        for defense in self.defenses:
            outcome = defense.filter_tool_output(tool_name, text, case)
            text = outcome.text
            events.extend(outcome.events)
        return FilterOutcome(text, events)

    def gate_tool_call(
        self,
        call: ToolCall,
        verdict: AuthorizationVerdict,
        state: PolicyState,
        case: Any,
    ) -> tuple[str | None, list[DefenseEvent]]:
        """First defense that vetoes the call wins; its name is the block reason."""
        events: list[DefenseEvent] = []
        blocked_by: str | None = None
        for defense in self.defenses:
            reason, defense_events = defense.gate_tool_call(call, verdict, state, case)
            events.extend(defense_events)
            if reason and blocked_by is None:
                blocked_by = reason
        return blocked_by, events

    def filter_final_output(self, text: str, case: Any, system_prompt: str) -> FilterOutcome:
        events: list[DefenseEvent] = []
        for defense in self.defenses:
            outcome = defense.filter_final_output(text, case, system_prompt)
            text = outcome.text
            events.extend(outcome.events)
        return FilterOutcome(text, events)
