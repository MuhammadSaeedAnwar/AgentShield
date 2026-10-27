"""Tests for config validation and helper behaviour.

These tests focus on the public configuration surface rather than any specific
model backend, making the project easier to evolve without brittle integration
assumptions.
"""

from __future__ import annotations

import json

import pytest

from agentshield.config import RunConfig, load_config_file


def test_run_config_rejects_invalid_values():
    with pytest.raises(ValueError, match="trials"):
        RunConfig(trials=0).validate()

    with pytest.raises(ValueError, match="tool_provisioning"):
        RunConfig(tool_provisioning="bad").validate()

    with pytest.raises(ValueError, match="model"):
        RunConfig(model="gpt-4").validate()


def test_run_config_model_options_for_mock_and_openai():
    mock_cfg = RunConfig(model="mock", model_name="mock-test")
    assert mock_cfg.model_options() == {"seed": 1337, "model_name": "mock-test"}

    openai_cfg = RunConfig(model="openai", model_name="gpt-4o-mini", api_key_env="CUSTOM_KEY")
    assert openai_cfg.model_options()["model"] == "gpt-4o-mini"
    assert openai_cfg.model_options()["api_key_env"] == "CUSTOM_KEY"


def test_load_config_file_accepts_json(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"trials": 3, "defenses": "all"}), encoding="utf-8")

    payload = load_config_file(config_path)
    assert payload["trials"] == 3
    assert payload["defenses"] == "all"


def test_merged_config_keeps_known_fields_and_validates():
    cfg = RunConfig().merged({"trials": 2, "defenses": "all"})
    assert cfg.trials == 2
    assert cfg.defenses == "all"

    with pytest.raises(ValueError, match="Unknown configuration key"):
        RunConfig().merged({"unknown": 1})
