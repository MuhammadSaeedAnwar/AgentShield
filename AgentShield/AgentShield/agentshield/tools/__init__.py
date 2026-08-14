"""Simulated, side-effect-free tools for the agent environment."""

from __future__ import annotations

from .base import Tool, ToolResult
from .builtin import (
    ALL_TOOLS,
    TOOLS_BY_NAME,
    CalculatorTool,
    DatabaseLookupTool,
    DocumentSearchTool,
    FileReaderTool,
    SendMessageTool,
    WeatherLookupTool,
    safe_eval_arithmetic,
)
from .policy import (
    AUTHORIZATION_REASONS,
    CONFIRMATION_REASONS,
    AuthorizationVerdict,
    PolicyState,
    ToolPolicy,
    Violation,
    enforced_reasons,
)
from .registry import ToolCallRecord, ToolExecutor, ToolRegistry
from .sandbox import Sandbox

__all__ = [
    "ALL_TOOLS",
    "AUTHORIZATION_REASONS",
    "AuthorizationVerdict",
    "CONFIRMATION_REASONS",
    "CalculatorTool",
    "DatabaseLookupTool",
    "DocumentSearchTool",
    "FileReaderTool",
    "PolicyState",
    "Sandbox",
    "SendMessageTool",
    "TOOLS_BY_NAME",
    "Tool",
    "ToolCallRecord",
    "ToolExecutor",
    "ToolPolicy",
    "ToolRegistry",
    "ToolResult",
    "Violation",
    "WeatherLookupTool",
    "enforced_reasons",
    "safe_eval_arithmetic",
]
