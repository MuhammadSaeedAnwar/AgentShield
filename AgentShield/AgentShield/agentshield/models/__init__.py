"""Model adapters: the only provider-specific layer in AgentShield."""

from __future__ import annotations

from typing import Any, Mapping

from .base import Message, ModelAdapter, ModelResponse, ToolCall, ToolSpec
from .mock import MockModelAdapter
from .openai_compatible import ModelCallError, OpenAICompatibleAdapter

#: Registry of adapter factories keyed by the value of ``--model``.
ADAPTERS = {
    "mock": MockModelAdapter,
    "openai": OpenAICompatibleAdapter,
}


def build_model(spec: str, options: Mapping[str, Any] | None = None) -> ModelAdapter:
    """Instantiate a model adapter.

    Parameters
    ----------
    spec:
        Adapter key (``"mock"`` or ``"openai"``).
    options:
        Adapter keyword arguments (model name, base url, seed, ...). Unknown keys
        are ignored so that one config file can describe several adapters.
    """
    key = (spec or "mock").strip().lower()
    if key not in ADAPTERS:
        raise ValueError(f"Unknown model adapter '{spec}'. Available: {sorted(ADAPTERS)}")
    cls = ADAPTERS[key]
    opts = dict(options or {})

    if key == "mock":
        allowed = {"seed", "model_name", "base_compliance", "feature_weights"}
        return cls(**{k: v for k, v in opts.items() if k in allowed})

    allowed = {
        "model",
        "base_url",
        "api_key",
        "api_key_env",
        "temperature",
        "max_tokens",
        "timeout",
        "max_retries",
        "cache_dir",
        "extra_headers",
    }
    return cls(**{k: v for k, v in opts.items() if k in allowed})


__all__ = [
    "ADAPTERS",
    "Message",
    "ModelAdapter",
    "ModelCallError",
    "ModelResponse",
    "MockModelAdapter",
    "OpenAICompatibleAdapter",
    "ToolCall",
    "ToolSpec",
    "build_model",
    "build_model",
]
