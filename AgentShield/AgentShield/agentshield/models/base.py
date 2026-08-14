"""Abstract model interface used by every AgentShield agent.

The benchmark never talks to a provider SDK directly. It talks to a
:class:`ModelAdapter`, which is the only place provider-specific behaviour
lives. That makes the harness provider-agnostic and keeps the experiment
protocol identical across models.

Implementations shipped with AgentShield
---------------------------------------
* :class:`agentshield.models.mock.MockModelAdapter` -- deterministic, offline,
  no API key required. It is a *susceptibility simulator*, not a language model
  (see ``docs/mock_model.md``).
* :class:`agentshield.models.openai_compatible.OpenAICompatibleAdapter` --
  any OpenAI-compatible ``/v1/chat/completions`` endpoint (OpenAI, vLLM,
  Ollama, Together, Groq, LM Studio, ...), stdlib HTTP only.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

Role = str  # "system" | "user" | "assistant" | "tool"


@dataclass
class Message:
    """One chat message.

    ``trust`` is AgentShield metadata (not sent to the provider). It records the
    provenance of the content so that experiments can reason about the
    trust boundary:

    * ``"trusted"``   -- system policy written by the deployer.
    * ``"user"``      -- the (semi-trusted) human request.
    * ``"untrusted"`` -- content that originated outside the trust boundary:
      tool results, retrieved documents, files, database rows.
    """

    role: Role
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list["ToolCall"] = field(default_factory=list)
    trust: str = "trusted"

    def to_provider_dict(self) -> dict[str, Any]:
        """Render in OpenAI chat-completions wire format (drops AgentShield metadata)."""
        out: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.role == "tool":
            out["tool_call_id"] = self.tool_call_id or "call_0"
            if self.name:
                out["name"] = self.name
        elif self.name:
            out["name"] = self.name
        if self.tool_calls:
            out["tool_calls"] = [tc.to_provider_dict() for tc in self.tool_calls]
            # OpenAI requires content=null (or empty) when tool_calls are present.
            out["content"] = self.content or ""
        return out

    def to_dict(self) -> dict[str, Any]:
        """Render for the results transcript (keeps AgentShield metadata)."""
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
    """A model-requested tool invocation."""

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
    """JSON-schema description of a tool, as advertised to the model."""

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
    """Normalised model output."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    # Free-form adapter diagnostics (e.g. the mock's decision trace). Recorded
    # in the transcript; useful for auditing *why* an episode went one way.
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
    """Minimal contract every model backend must satisfy."""

    #: Adapter family identifier, e.g. "mock" or "openai".
    provider: str = "unknown"

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Identifier recorded in results (e.g. ``mock-gullible-v1``, ``gpt-4o-mini``)."""

    @abstractmethod
    def generate(
        self,
        messages: Sequence[Message],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Plain text completion (no tools advertised)."""

    @abstractmethod
    def generate_with_tools(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Completion where the model may emit tool calls.

        ``context`` carries harness bookkeeping (case id, trial index, step
        index, and -- for the mock adapter only -- the benign task oracle).
        API-backed adapters MUST ignore ``context``: it is never serialised into
        a prompt, so it cannot leak the oracle to a real model.
        """

    # Optional lifecycle hook; adapters that cache to disk override this.
    def close(self) -> None:  # pragma: no cover - trivial
        return None

    def describe(self) -> dict[str, Any]:
        """Configuration snapshot recorded in run metadata for reproducibility."""
        return {"provider": self.provider, "model_name": self.model_name}
