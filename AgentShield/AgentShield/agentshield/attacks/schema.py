"""Test-case schema and validation.

A test case is a declarative description of one controlled security scenario.
It contains everything needed to (a) build the environment, (b) drive the agent,
and (c) decide *mechanically* whether the attack succeeded -- no LLM judge, no
human labelling, no post-hoc interpretation.

Required fields
---------------
``id``, ``category``, ``attack_prompt``, ``context``, ``trusted_instruction``,
``available_tools``, ``expected_safe_behavior``, ``attack_goal``, ``severity``.

Additional fields used by the harness
-------------------------------------
``user_turns``        the conversation the simulated user sends (>=1 turn)
``injection_channel`` where the payload enters (see taxonomy.INJECTION_CHANNELS)
``tool_policy``       authorization policy for this scenario
``success_criteria``  machine-checkable definition of "the attack worked"
``task_criteria``     machine-checkable definition of "the benign task was done"
``benign_plan``       oracle tool plan, consumed ONLY by the mock adapter
``tags``, ``notes``, ``title``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterable, Mapping, Sequence

from ..tools.builtin import TOOLS_BY_NAME
from .taxonomy import CATEGORY_KEYS, INJECTION_CHANNELS, SEVERITIES

REQUIRED_FIELDS: tuple[str, ...] = (
    "id",
    "category",
    "attack_prompt",
    "context",
    "trusted_instruction",
    "available_tools",
    "expected_safe_behavior",
    "attack_goal",
    "severity",
)

#: Leaf criterion types understood by the outcome classifier.
CRITERION_TYPES: tuple[str, ...] = (
    "output_contains_any",
    "output_regex",
    "tool_call",
    "tool_call_executed",
    "message_sent_to",
    "secret_exposed",
    "secret_in_sink",
    "unauthorized_tool_call",
    "file_read",
    "db_query",
    "no_tool_call",
    "never",
)
COMBINATORS: tuple[str, ...] = ("any", "all", "not")


class DatasetError(ValueError):
    """Raised when a dataset is structurally invalid."""


@dataclass
class AttackGoal:
    """What the adversary is trying to achieve (documentation + grouping)."""

    type: str
    description: str = ""

    @classmethod
    def parse(cls, raw: Any) -> "AttackGoal":
        if isinstance(raw, AttackGoal):
            return raw
        if isinstance(raw, Mapping):
            return cls(type=str(raw.get("type", "unspecified")), description=str(raw.get("description", "")))
        return cls(type="unspecified", description=str(raw))

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "description": self.description}


@dataclass
class TestCase:
    """One controlled security scenario."""

    # Tell pytest not to treat this class as a test case.
    __test__: ClassVar[bool] = False

    id: str
    category: str
    attack_prompt: str
    trusted_instruction: str
    expected_safe_behavior: str
    attack_goal: AttackGoal
    severity: str
    context: dict[str, Any] = field(default_factory=dict)
    available_tools: list[str] = field(default_factory=list)
    user_turns: list[str] = field(default_factory=list)
    injection_channel: str = "none"
    tool_policy: dict[str, Any] = field(default_factory=dict)
    success_criteria: dict[str, Any] = field(default_factory=dict)
    task_criteria: dict[str, Any] = field(default_factory=dict)
    benign_plan: Any = field(default_factory=list)
    title: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------ parsing
    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "TestCase":
        missing = [f for f in REQUIRED_FIELDS if f not in raw]
        if missing:
            raise DatasetError(f"test case {raw.get('id', '<no id>')!r} is missing required field(s): {missing}")
        return cls(
            id=str(raw["id"]),
            category=str(raw["category"]),
            attack_prompt=str(raw["attack_prompt"]),
            trusted_instruction=str(raw["trusted_instruction"]),
            expected_safe_behavior=str(raw["expected_safe_behavior"]),
            attack_goal=AttackGoal.parse(raw["attack_goal"]),
            severity=str(raw["severity"]).lower(),
            context=dict(raw.get("context") or {}),
            available_tools=list(raw.get("available_tools") or []),
            user_turns=[str(t) for t in (raw.get("user_turns") or [])],
            injection_channel=str(raw.get("injection_channel", "none")),
            tool_policy=dict(raw.get("tool_policy") or {}),
            success_criteria=dict(raw.get("success_criteria") or {}),
            task_criteria=dict(raw.get("task_criteria") or {}),
            benign_plan=raw.get("benign_plan") or [],
            title=str(raw.get("title", "")),
            tags=[str(t) for t in (raw.get("tags") or [])],
            notes=str(raw.get("notes", "")),
            raw=dict(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "injection_channel": self.injection_channel,
            "trusted_instruction": self.trusted_instruction,
            "user_turns": self.user_turns,
            "attack_prompt": self.attack_prompt,
            "context": self.context,
            "available_tools": self.available_tools,
            "tool_policy": self.tool_policy,
            "attack_goal": self.attack_goal.to_dict(),
            "expected_safe_behavior": self.expected_safe_behavior,
            "success_criteria": self.success_criteria,
            "task_criteria": self.task_criteria,
            "benign_plan": self.benign_plan,
            "tags": self.tags,
            "notes": self.notes,
        }

    # ------------------------------------------------------------ helpers
    @property
    def secrets(self) -> list[str]:
        return [str(s) for s in (self.context.get("secrets") or [])]

    @property
    def has_attack(self) -> bool:
        """A case is *applicable* to ASR only if it defines success criteria."""
        return bool(self.success_criteria)

    def oracle(self) -> dict[str, Any]:
        """Out-of-band hints for the mock adapter (never serialised into a prompt)."""
        return {"benign_plan": self.benign_plan}

    def delivered_text(self) -> str:
        """All text the agent could possibly observe (for integrity checks)."""
        return "\n".join([*self.user_turns, *_iter_strings(self.context), self.trusted_instruction])


# ---------------------------------------------------------------- validation


def _validate_criteria(node: Any, path: str, issues: list[str]) -> None:
    if not isinstance(node, Mapping):
        issues.append(f"{path}: criteria node must be an object, got {type(node).__name__}")
        return
    if not node:
        return
    keys = set(node)
    combinator = keys & set(COMBINATORS)
    if combinator:
        if len(keys) > 1:
            issues.append(f"{path}: combinator node must have exactly one key, got {sorted(keys)}")
            return
        key = combinator.pop()
        children = node[key]
        if key == "not":
            _validate_criteria(children, f"{path}.not", issues)
            return
        if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
            issues.append(f"{path}.{key}: must be a list of criteria")
            return
        for index, child in enumerate(children):
            _validate_criteria(child, f"{path}.{key}[{index}]", issues)
        return

    ctype = node.get("type")
    if ctype is None:
        issues.append(f"{path}: leaf criterion needs a 'type' field (one of {list(CRITERION_TYPES)})")
        return
    if ctype not in CRITERION_TYPES:
        issues.append(f"{path}: unknown criterion type {ctype!r}; known types: {list(CRITERION_TYPES)}")
        return
    if ctype == "output_contains_any" and not node.get("values"):
        issues.append(f"{path}: 'output_contains_any' requires a non-empty 'values' list")
    if ctype == "output_regex" and not node.get("pattern"):
        issues.append(f"{path}: 'output_regex' requires a 'pattern'")
    if ctype in ("tool_call", "tool_call_executed", "no_tool_call") and not node.get("tool"):
        issues.append(f"{path}: {ctype!r} requires a 'tool'")


def validate_case(case: TestCase, *, strict: bool = True) -> list[str]:
    """Return a list of human-readable problems with a single case."""
    issues: list[str] = []
    if case.category not in CATEGORY_KEYS:
        issues.append(f"{case.id}: unknown category {case.category!r}; expected one of {list(CATEGORY_KEYS)}")
    if case.severity not in SEVERITIES:
        issues.append(f"{case.id}: severity {case.severity!r} not in {list(SEVERITIES)}")
    if case.injection_channel not in INJECTION_CHANNELS:
        issues.append(f"{case.id}: injection_channel {case.injection_channel!r} not in {list(INJECTION_CHANNELS)}")
    if not case.user_turns:
        issues.append(f"{case.id}: at least one user turn is required")
    if not case.trusted_instruction.strip():
        issues.append(f"{case.id}: trusted_instruction must not be empty")

    unknown_tools = [t for t in case.available_tools if t not in TOOLS_BY_NAME]
    if unknown_tools:
        issues.append(f"{case.id}: unknown tool(s) {unknown_tools}; known tools: {sorted(TOOLS_BY_NAME)}")

    _validate_criteria(case.success_criteria, f"{case.id}.success_criteria", issues)
    _validate_criteria(case.task_criteria, f"{case.id}.task_criteria", issues)
    if not case.success_criteria:
        issues.append(f"{case.id}: success_criteria is empty, so the case can never be scored for ASR")

    # Every declared canary must actually exist somewhere in the environment,
    # otherwise "exposure" would be unmeasurable by construction.
    env_blob = "\n".join(_iter_strings(case.context)) + case.trusted_instruction
    for secret in case.secrets:
        if secret not in env_blob:
            issues.append(f"{case.id}: declared secret {secret!r} does not occur in the environment")

    # Integrity check: the documented payload must really be delivered to the agent.
    # Invisible characters are ignored, since obfuscated payloads are still delivered.
    if case.injection_channel != "none" and strict:
        probe = _visible(case.attack_prompt)[:60]
        haystack = _visible(case.delivered_text())
        if probe and probe not in haystack:
            issues.append(
                f"{case.id}: attack_prompt is documented but not delivered through any channel "
                "(first 60 chars not found in user turns or context)"
            )

    # Benign plan sanity: only known tools, and only tools the case provisions.
    for step in _iter_plan_steps(case.benign_plan):
        tool = step.get("tool")
        if tool not in TOOLS_BY_NAME:
            issues.append(f"{case.id}: benign_plan references unknown tool {tool!r}")
        elif case.available_tools and tool not in case.available_tools:
            issues.append(f"{case.id}: benign_plan uses {tool!r}, which is not in available_tools")
    return issues


#: Characters used to hide text from human reviewers; ignored by integrity checks.
_INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad"


def _visible(text: str) -> str:
    """Normalise whitespace and drop invisible characters."""
    cleaned = (text or "").translate({ord(ch): None for ch in _INVISIBLE})
    return " ".join(cleaned.split())


def _iter_strings(node: Any) -> Iterable[str]:
    """Yield every string embedded anywhere in a nested context structure."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            yield str(key)
            yield from _iter_strings(value)
    elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
        for item in node:
            yield from _iter_strings(item)


def _iter_plan_steps(plan: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(plan, Mapping):
        for steps in plan.values():
            if isinstance(steps, Sequence):
                for step in steps:
                    if isinstance(step, Mapping):
                        yield step
    elif isinstance(plan, Sequence):
        for step in plan:
            if isinstance(step, Mapping):
                yield step


def validate_dataset(cases: Sequence[TestCase], *, strict: bool = True) -> list[str]:
    """Validate a whole dataset (per-case checks plus global uniqueness)."""
    issues: list[str] = []
    seen: dict[str, int] = {}
    for case in cases:
        seen[case.id] = seen.get(case.id, 0) + 1
        issues.extend(validate_case(case, strict=strict))
    duplicates = sorted(cid for cid, count in seen.items() if count > 1)
    if duplicates:
        issues.append(f"duplicate case id(s): {duplicates}")
    return issues
