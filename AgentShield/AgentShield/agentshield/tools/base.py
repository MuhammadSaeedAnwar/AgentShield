"""Tool abstraction for the simulated agent environment.

Every tool in AgentShield is a pure function of (arguments, in-memory sandbox).
No tool performs network I/O, touches the real filesystem, or has any other
real-world side effect. ``send_message`` appends to an in-memory outbox;
``file_reader`` reads a dict of virtual paths; ``database_lookup`` queries a
dict of virtual tables.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..models.base import ToolSpec


@dataclass
class ToolResult:
    """Outcome of a tool invocation.

    ``content`` is the string handed back to the model. It is **untrusted by
    construction**: in this benchmark, tool output is exactly the channel an
    attacker controls.
    """

    ok: bool
    content: str
    data: dict[str, Any] | None = None
    error: str | None = None
    #: "untrusted" for anything derived from environment content.
    trust: str = "untrusted"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "content": self.content,
            "data": self.data,
            "error": self.error,
            "trust": self.trust,
            "metadata": self.metadata,
        }


class Tool(ABC):
    """Base class for simulated tools."""

    #: Function name exposed to the model.
    name: str = "tool"
    #: Natural-language description exposed to the model.
    description: str = ""
    #: JSON schema for arguments.
    parameters: dict[str, Any] = {"type": "object", "properties": {}}
    #: Sensitive tools are gated by the confirmation defense and are the ones
    #: whose misuse we count as a security-relevant event.
    sensitive: bool = False
    #: True when the tool can move data outside the agent's boundary
    #: (an exfiltration sink).
    is_sink: bool = False
    #: True when the tool can return secret-bearing content.
    reads_private_data: bool = False

    @abstractmethod
    def run(self, args: dict[str, Any], sandbox: Any) -> ToolResult:
        """Execute the tool against the in-memory sandbox."""

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, parameters=self.parameters)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "sensitive": self.sensitive,
            "is_sink": self.is_sink,
            "reads_private_data": self.reads_private_data,
        }
