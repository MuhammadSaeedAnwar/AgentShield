"""Tool abstraction for the simulated agent environment."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..models.base import ToolSpec


@dataclass
class ToolResult:
    ok: bool
    content: str
    data: dict[str, Any] | None = None
    error: str | None = None
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
    name: str = "tool"
    description: str = ""
    parameters: dict[str, Any] = {"type": "object", "properties": {}}
    sensitive: bool = False
    is_sink: bool = False
    reads_private_data: bool = False

    @abstractmethod
    def run(self, args: dict[str, Any], sandbox: Any) -> ToolResult:
        raise NotImplementedError

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
