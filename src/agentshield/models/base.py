"""Abstract model interface used by every AgentShield agent."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

Role = str


@dataclass
class Message:
    role: Role
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list["ToolCall"] = field(default_factory=list)
    trust: str = "trusted"

    def to_provider_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.role == "tool":
            out["tool_call_id"] = self.tool_call_id or "call_0"
            if self.name:
                out["name"] = self.name
        elif self.name:
            out["name"] = self.name
        if self.tool_calls:
            out["tool_calls"] = [tc.to_provider_dict() for tc in self.tool_calls]
            out["content"] = self.content or ""
        return out

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "role": self.role,
            "content": self.content,
            "trust": self.trust,
        }
        if self.name:
            out["name"] = self.name
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            out["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
        return out


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str = "call_0"

    def to_provider_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": json.dumps(self.arguments)},
        }

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]

    def to_provider_dict(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ModelResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    debug: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "finish_reason": self.finish_reason,
            "usage": self.usage,
            "debug": self.debug,
        }


class ModelAdapter(ABC):
    provider: str = "unknown"

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Identifier recorded in results."""

    @abstractmethod
    def generate(
        self,
        messages: Sequence[Message],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Plain text completion."""

    @abstractmethod
    def generate_with_tools(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Completion where the model may emit tool calls."""

    def close(self) -> None:
        return None

    def describe(self) -> dict[str, Any]:
        return {"provider": self.provider, "model_name": self.model_name}
