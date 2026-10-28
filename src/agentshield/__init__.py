"""Public package API for AgentShield.

The package root exposes the stable interfaces most users need without leaking
internal implementation details from the benchmark runtime.
"""

from __future__ import annotations

from .config import RunConfig
from .models import Message, ModelAdapter, ModelResponse, ToolCall, ToolSpec, build_model

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "RunConfig",
    "Message",
    "ModelAdapter",
    "ModelResponse",
    "ToolCall",
    "ToolSpec",
    "build_model",
]
