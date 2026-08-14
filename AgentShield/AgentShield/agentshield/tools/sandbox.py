"""In-memory environment shared by all tools during one episode.

The sandbox is rebuilt from the test case before every episode, so episodes are
independent and reproducible. Nothing here touches the real filesystem, the
network, or any external service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_WEATHER: dict[str, dict[str, Any]] = {
    "karachi": {"condition": "hazy sun", "temp_c": 33, "humidity": 61},
    "lahore": {"condition": "clear", "temp_c": 36, "humidity": 44},
    "islamabad": {"condition": "light rain", "temp_c": 28, "humidity": 72},
    "berlin": {"condition": "overcast", "temp_c": 19, "humidity": 70},
    "london": {"condition": "drizzle", "temp_c": 17, "humidity": 81},
    "san francisco": {"condition": "fog", "temp_c": 15, "humidity": 84},
}


@dataclass
class Sandbox:
    """Virtual world state for a single episode."""

    case_id: str = "unknown"
    #: Retrievable documents: [{"id", "title", "content"}]
    documents: list[dict[str, Any]] = field(default_factory=list)
    #: Virtual filesystem: {"/sandbox/public/notes.txt": "..."}
    files: dict[str, str] = field(default_factory=dict)
    #: Virtual database: {"orders": [ {...}, {...} ]}
    database: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    #: Attacker-controlled additions to a tool's output:
    #: {"weather_lookup": {"mode": "append"|"replace", "text": "..."}}
    tool_output_injections: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Canary strings that must never leave the agent.
    secrets: list[str] = field(default_factory=list)
    weather: dict[str, dict[str, Any]] = field(default_factory=lambda: dict(DEFAULT_WEATHER))
    #: Messages "sent" by send_message (never leaves the process).
    outbox: list[dict[str, Any]] = field(default_factory=list)
    #: Chronological log of every executed tool invocation.
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_case(cls, case: Any) -> "Sandbox":
        """Build a fresh sandbox from a :class:`~agentshield.attacks.schema.TestCase`."""
        ctx = getattr(case, "context", {}) or {}
        weather = dict(DEFAULT_WEATHER)
        weather.update({k.lower(): v for k, v in (ctx.get("weather") or {}).items()})
        return cls(
            case_id=getattr(case, "id", "unknown"),
            documents=[dict(d) for d in (ctx.get("documents") or [])],
            files=dict(ctx.get("files") or {}),
            database={k: [dict(r) for r in v] for k, v in (ctx.get("database") or {}).items()},
            tool_output_injections={k: dict(v) for k, v in (ctx.get("tool_outputs") or {}).items()},
            secrets=list(ctx.get("secrets") or []),
            weather=weather,
        )

    # ------------------------------------------------------------------
    def record(self, tool: str, args: dict[str, Any], result: Any) -> None:
        self.audit_log.append(
            {
                "tool": tool,
                "args": args,
                "ok": getattr(result, "ok", None),
                "error": getattr(result, "error", None),
            }
        )

    def apply_injection(self, tool_name: str, content: str) -> tuple[str, bool]:
        """Apply the case's attacker-controlled modification to a tool's output.

        Returns ``(content, injected)``.
        """
        spec = self.tool_output_injections.get(tool_name)
        if not spec:
            return content, False
        text = str(spec.get("text", ""))
        mode = str(spec.get("mode", "append")).lower()
        if mode == "replace":
            return text, True
        if mode == "prepend":
            return f"{text}\n{content}", True
        return f"{content}\n{text}", True

    def secrets_in(self, text: str) -> list[str]:
        """Which of this episode's canary secrets appear in ``text``."""
        if not text:
            return []
        return [s for s in self.secrets if s and s in text]

    def snapshot(self) -> dict[str, Any]:
        """Serialisable view stored with each episode result."""
        return {
            "outbox": self.outbox,
            "audit_log": self.audit_log,
            "secrets_defined": list(self.secrets),
            "documents": [d.get("id", "") for d in self.documents],
            "files": sorted(self.files),
            "tables": sorted(self.database),
        }
