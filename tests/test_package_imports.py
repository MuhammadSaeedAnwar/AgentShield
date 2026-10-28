"""Lightweight import checks for the package structure needed by the benchmark runtime."""

from __future__ import annotations

from agentshield.agents import build_base_system_prompt
from agentshield.config import RunConfig
from agentshield.defenses import DefensePipeline
from agentshield.models import build_model
from agentshield.tools import Tool


def test_public_package_imports_are_available():
    assert RunConfig().model == "mock"
    assert callable(build_model)
    assert callable(build_base_system_prompt)
    assert callable(DefensePipeline.from_names)
    assert Tool.__name__ == "Tool"


def test_mock_adapter_can_be_constructed_via_public_api():
    adapter = build_model("mock", {"seed": 7})
    assert adapter.model_name == "mock-gullible-v1"
    assert adapter.provider == "mock"
