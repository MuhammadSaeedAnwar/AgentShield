"""Tool registry and executor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..models.base import ToolCall, ToolSpec
from .base import Tool, ToolResult
from .builtin import ALL_TOOLS, TOOLS_BY_NAME
from .policy import AuthorizationVerdict
from .sandbox import Sandbox


class ToolRegistry:
    """The set of tools an agent can actually reach in an episode."""

    def __init__(self, tools: Iterable[Tool]) -> None:
        self._tools: dict[str, Tool] = {t.name: t for t in tools}

    # ------------------------------------------------------------- builders
    @classmethod
    def from_names(cls, names: Sequence[str]) -> "ToolRegistry":
        unknown = [n for n in names if n not in TOOLS_BY_NAME]
        if unknown:
            raise KeyError(f"Unknown tool name(s): {unknown}. Known tools: {sorted(TOOLS_BY_NAME)}")
        return cls([TOOLS_BY_NAME[n]() for n in names])

    @classmethod
    def all_tools(cls) -> "ToolRegistry":
        return cls([cls_() for cls_ in ALL_TOOLS])

    # ---------------------------------------------------------------- access
    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    @property
    def names(self) -> list[str]:
        return sorted(self._tools)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def specs(self) -> list[ToolSpec]:
        return [self._tools[name].spec() for name in sorted(self._tools)]

    def describe(self) -> list[dict[str, Any]]:
        return [self._tools[name].to_dict() for name in sorted(self._tools)]


@dataclass
class ToolCallRecord:
    """Everything the benchmark needs to know about one attempted tool call."""

    call: ToolCall
    verdict: AuthorizationVerdict
    executed: bool
    blocked_by: str | None = None
    result: ToolResult | None = None
    turn_index: int = 0
    step_index: int = 0
    origin: str = "model"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.call.name

    @property
    def authorized(self) -> bool:
        return self.verdict.authorized

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_index": self.turn_index,
            "step_index": self.step_index,
            "tool": self.call.name,
            "arguments": self.call.arguments,
            "authorized": self.verdict.authorized,
            "violations": [v.to_dict() for v in self.verdict.violations],
            "executed": self.executed,
            "blocked_by": self.blocked_by,
            "result": self.result.to_dict() if self.result else None,
            "origin": self.origin,
            "metadata": self.metadata,
        }


class ToolExecutor:
    """Runs a tool call against the sandbox and applies output injections."""

    def __init__(self, registry: ToolRegistry, sandbox: Sandbox) -> None:
        self.registry = registry
        self.sandbox = sandbox

    def execute(self, call: ToolCall) -> ToolResult:
        tool = self.registry.get(call.name)
        if tool is None:
            # The model asked for a tool it was never given. This is an
            # environment constraint, not a defense: it is recorded as an
            # attempted (unauthorized) call that could not run.
            return ToolResult(
                ok=False,
                content=(
                    f"error: tool '{call.name}' is not available in this session. "
                    f"Available tools: {', '.join(self.registry.names) or 'none'}"
                ),
                error="tool_not_available",
                trust="trusted",
            )
        try:
            result = tool.run(dict(call.arguments), self.sandbox)
        except Exception as exc:  # pragma: no cover - defensive: a tool bug must not kill a run
            result = ToolResult(False, f"error: tool '{call.name}' raised {type(exc).__name__}: {exc}", error="tool_exception")

        content, injected = self.sandbox.apply_injection(call.name, result.content)
        if injected:
            result.content = content
            result.metadata = {**result.metadata, "tool_output_injection": True}
        self.sandbox.record(call.name, dict(call.arguments), result)
        return result
