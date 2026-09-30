"""Experiment configuration.

Precedence (highest first): explicit CLI flags > config file > defaults. A config
file may be JSON or YAML (YAML needs ``pyyaml``; JSON always works).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

DEFAULT_DATASET = "data/attacks.json"
DEFAULT_OUTPUT_DIR = "results"


@dataclass
class RunConfig:
    """Everything that defines one experimental condition."""

    dataset: str = DEFAULT_DATASET
    categories: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    limit: int | None = None

    model: str = "mock"
    model_name: str | None = None
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    max_tokens: int = 1024
    cache_dir: str | None = None
    seed: int = 1337

    trials: int = 1
    defenses: str = "none"
    max_steps: int = 6
    tool_provisioning: str = "minimal"

    out: str = DEFAULT_OUTPUT_DIR
    run_id: str | None = None
    keep_transcripts: bool = True
    fail_fast: bool = False
    quiet: bool = False

    @classmethod
    def from_file(cls, path: str | Path) -> "RunConfig":
        return cls().merged(load_config_file(path))

    def merged(self, overrides: Mapping[str, Any] | None) -> "RunConfig":
        if not overrides:
            return self
        known = {f.name for f in fields(self)}
        unknown = [k for k in overrides if k not in known]
        if unknown:
            raise ValueError(f"Unknown configuration key(s): {sorted(unknown)}. Known keys: {sorted(known)}")
        data = asdict(self)
        for key, value in overrides.items():
            if value is not None:
                data[key] = value
        return RunConfig(**data)

    def model_options(self) -> dict[str, Any]:
        if self.model == "mock":
            return {"seed": self.seed, "model_name": self.model_name or "mock-gullible-v1"}
        return {
            "model": self.model_name or "gpt-4o-mini",
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "cache_dir": self.cache_dir,
        }

    def resolved_run_id(self, *, model_label: str, defense_label: str) -> str:
        if self.run_id:
            return _slug(self.run_id)
        return _slug(
            f"{self.model}-{model_label}__def-{defense_label}__tools-{self.tool_provisioning}__trials-{self.trials}"
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", text).strip("-")


def load_config_file(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Config file not found: {target}")
    text = target.read_text("utf-8")
    if target.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                f"{target} is YAML but pyyaml is not installed. Install it (pip install pyyaml) "
                "or use a JSON config file."
            ) from exc
        payload = yaml.safe_load(text) or {}
    else:
        payload = json.loads(text)
    if not isinstance(payload, Mapping):
        raise ValueError(f"{target}: config must be a mapping at the top level")
    return {k: v for k, v in payload.items() if k not in ("description", "notes", "name")}
