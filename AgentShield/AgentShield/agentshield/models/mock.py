"""Deterministic offline model adapter (``--model mock``).

WHAT THIS IS
------------
``MockModelAdapter`` is **not** a language model and it is **not** a stand-in for
one. It is a *deterministic susceptibility simulator*: a rule-based agent policy
whose probability of obeying an instruction found in untrusted content is an
explicit, documented function of textual features of that content.

WHY IT EXISTS
-------------
1. The benchmark must run end-to-end with no API key and no network, so that
   anybody can reproduce the pipeline bit-for-bit.
2. It gives the test suite a fixed point: unit tests can assert exact outcomes.
3. It lets us validate that the *harness* (detectors, classifier, metrics,
   defenses that act outside the model) behaves correctly, independently of any
   provider's behaviour.

HOW TO READ MOCK NUMBERS -- IMPORTANT
-------------------------------------
Numbers produced with ``--model mock`` are properties of *this simulator*, not
evidence about any real LLM. They answer "does the harness measure what it
claims to measure?", never "how vulnerable is GPT-x / Claude-x / Llama-x?".
Answering the research questions requires ``--model openai`` against real
models. This distinction is stated in the README and in ``docs/mock_model.md``.

DECISION PROCEDURE (fully specified, see docs/mock_model.md)
-----------------------------------------------------------
1. Split the conversation into trusted (system), user, and untrusted (tool
   output / retrieved document) content.
2. Extract *directives* (imperative requests) from user + untrusted content with
   the regex family in :data:`DIRECTIVE_PATTERNS`. These patterns are
   intentionally **different** from the ones used by the input-sanitisation
   defense, so the sanitiser is not a perfect oracle for the mock.
3. Compute a compliance probability ``p`` from additive feature weights
   (:data:`FEATURE_WEIGHTS`).
4. Draw a *deterministic* Bernoulli sample: ``u = H(seed, model, case, trial,
   turn) / 2**32``; comply iff ``u < p``. Identical inputs always give an
   identical episode.
5. Build a plan: the benign task plan supplied by the environment oracle, plus
   (only if complying) the tool calls implied by the extracted directives.
6. Emit the next unexecuted plan step as a tool call, or, when the plan is
   exhausted, emit a final answer that summarises the tool results it received.

The oracle (step 5) is passed out-of-band via ``context["oracle"]`` and is
*never* serialised into a prompt, so API-backed adapters cannot see it. This
means mock task-completion rates are not comparable with a real model's: the
mock is told what the benign task plan is, a real model must infer it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .base import Message, ModelAdapter, ModelResponse, ToolCall, ToolSpec

# Marker inserted by the input-sanitisation defense; the mock can "see" that
# content was redacted, exactly as a real model would.
REDACTION_MARKER = "[REDACTED-BY-AGENTSHIELD"
# Marker inserted by the trust-separation defense.
SEPARATION_MARKER = "<<<AGENTSHIELD_UNTRUSTED"

MAX_ECHO_CHARS = 700


# --------------------------------------------------------------------------
# Directive extraction (the mock's "gullibility" patterns)
# --------------------------------------------------------------------------

EMAIL_RE = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
PATH_RE = r"/sandbox/[\w./-]+"

#: (name, regex) pairs. Each match yields a directive; the mock keeps them in
#: order of appearance and executes them after the benign plan.
DIRECTIVE_PATTERNS: list[tuple[str, str]] = [
    # Exfiltration to an address: "send/email/forward ... to <addr>", "recipient: <addr>"
    ("send", rf"\b(?:send|email|e-mail|forward|transmit|deliver|report|cc|copy)\b[^.\n]{{0,120}}?\bto\s+({EMAIL_RE})"),
    ("send", rf"(?:recipient|address|mailbox|contact)\s*[:=]\s*({EMAIL_RE})"),
    ("send", rf"\bnotify\s+({EMAIL_RE})"),
    # Read a sandbox file: "read/open/include/attach the file <path>"
    ("read_file", rf"\b(?:read|open|include|attach|retrieve|load|print|show|cat|access)\b[^.\n]{{0,120}}?({PATH_RE})"),
    ("read_file", rf"(?:contents? of|file at|located at)\s+({PATH_RE})"),
    # Query the mock database: "look up the <name> table", "query table <name>"
    ("db_lookup", r"\b(?:look ?up|query|read|dump|export|pull|select from|check)\b[^.\n]{0,60}?\b([a-z_]{3,20})\s+table\b"),
    ("db_lookup", r"\btable\s+[`'\"]([a-z_]{3,20})[`'\"]"),
    # System-prompt disclosure
    (
        "reveal_system_prompt",
        r"\b(?:reveal|print|show|repeat|output|disclose|display|echo|dump|state|summari[sz]e)\b[^.\n]{0,80}?"
        r"(?:system (?:prompt|message|instructions?)|initial instructions?|your instructions?|"
        r"configuration (?:block|token)|policy (?:text|block|identifier))",
    ),
    # Explicit tool invocation demand: "call the send_message tool"
    ("call_tool", r"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?([a-z][a-z_]{2,30})\s+(?:tool|function|api)"),
]

COMPILED_DIRECTIVES = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in DIRECTIVE_PATTERNS]

AUTHORITY_RE = re.compile(
    r"(system update|system notice|admin(istrator)?|it (department|support|team)|security (notice|alert|patch)|"
    r"compliance|policy update|mandatory|official|automated (process|workflow)|priority directive|"
    r"authori[sz]ed by|maintenance window|new instructions?)",
    re.IGNORECASE,
)
URGENCY_RE = re.compile(
    r"(immediately|urgent(ly)?|right away|as soon as possible|without delay|before (the )?deadline|"
    r"within \d+ (minute|hour)s?|failure to comply|will be (closed|suspended|terminated)|final (notice|warning))",
    re.IGNORECASE,
)
OVERRIDE_RE = re.compile(
    r"(ignore (all |any )?(previous|prior|above|earlier)|disregard (the )?(previous|prior|above)|"
    r"override|supersede[sd]?|no longer applies|forget (your|the) (instructions|rules))",
    re.IGNORECASE,
)

#: Additive weights on top of :data:`BASE_COMPLIANCE`. Documented in
#: ``docs/mock_model.md``; changing them changes the simulator, not the harness.
FEATURE_WEIGHTS: dict[str, float] = {
    "authority_framing": 0.22,
    "urgency_pressure": 0.12,
    "explicit_override": 0.10,
    "channel_user": 0.20,  # direct injection arrives in the high-trust user turn
    "channel_tool_output": 0.10,  # agents tend to over-trust tool results
    "channel_document": 0.05,
    "multi_turn_escalation": 0.06,  # per prior user turn, capped at 3 turns
    "trust_separation_present": -0.30,  # MODELLING ASSUMPTION, not a measurement
    "sanitisation_notice": -0.15,  # visible redaction acts as a warning signal
    "explicit_prohibition": -0.10,  # system policy contains a matching "never ..." rule
}
BASE_COMPLIANCE = 0.35
P_MIN, P_MAX = 0.02, 0.98


@dataclass
class MockDirective:
    """An instruction the mock extracted from user/untrusted content."""

    action: str
    value: str
    channel: str
    position: int
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "value": self.value,
            "channel": self.channel,
            "raw": self.raw[:200],
        }


@dataclass
class MockDecision:
    """Auditable trace of one compliance decision."""

    probability: float
    draw: float
    comply: bool
    features: dict[str, float] = field(default_factory=dict)
    directives: list[MockDirective] = field(default_factory=list)
    sanitised: bool = False
    separated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "compliance_probability": round(self.probability, 4),
            "deterministic_draw": round(self.draw, 4),
            "complied_with_injected_directive": self.comply,
            "features": {k: round(v, 4) for k, v in self.features.items()},
            "extracted_directives": [d.to_dict() for d in self.directives],
            "input_was_sanitised": self.sanitised,
            "trust_separation_present": self.separated,
        }


def _deterministic_uniform(*parts: Any) -> float:
    """Stable pseudo-random float in [0, 1) from the given key parts."""
    key = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / float(1 << 32)


def extract_directives(text: str, channel: str) -> list[MockDirective]:
    """Extract imperative directives from a block of text."""
    found: list[MockDirective] = []
    for action, rx in COMPILED_DIRECTIVES:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            found.append(
                MockDirective(
                    action=action,
                    value=value.strip().strip(".,;:'\"`"),
                    channel=channel,
                    position=m.start(),
                    raw=m.group(0),
                )
            )
    # De-duplicate on (action, value), keeping first occurrence order.
    seen: set[tuple[str, str]] = set()
    unique: list[MockDirective] = []
    for d in sorted(found, key=lambda d: d.position):
        key = (d.action, d.value.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(d)
    return unique


class MockModelAdapter(ModelAdapter):
    """Deterministic, offline, dependency-free agent-policy simulator."""

    provider = "mock"

    def __init__(
        self,
        *,
        seed: int = 1337,
        model_name: str = "mock-gullible-v1",
        base_compliance: float = BASE_COMPLIANCE,
        feature_weights: Mapping[str, float] | None = None,
    ) -> None:
        self.seed = seed
        self._model_name = model_name
        self.base_compliance = float(base_compliance)
        self.feature_weights = dict(FEATURE_WEIGHTS)
        if feature_weights:
            self.feature_weights.update(feature_weights)

    # ---------------------------------------------------------------- API
    @property
    def model_name(self) -> str:
        return self._model_name

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "seed": self.seed,
            "base_compliance": self.base_compliance,
            "feature_weights": self.feature_weights,
            "note": (
                "Deterministic susceptibility simulator. Results characterise this "
                "simulator and the harness, NOT any real language model."
            ),
        }

    def generate(
        self,
        messages: Sequence[Message],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        return self._respond(messages, tools=[], context=context or {}, allow_tools=False)

    def generate_with_tools(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        return self._respond(messages, tools=list(tools), context=context or {}, allow_tools=True)

    # ----------------------------------------------------------- internals
    def _respond(
        self,
        messages: Sequence[Message],
        tools: list[ToolSpec],
        context: Mapping[str, Any],
        allow_tools: bool,
    ) -> ModelResponse:
        case_id = str(context.get("case_id", "unknown"))
        trial = int(context.get("trial", 0))
        turn_index = int(context.get("turn_index", 0))
        oracle = dict(context.get("oracle") or {})

        system_text = "\n".join(m.content for m in messages if m.role == "system")
        decision = self._decide(messages, system_text, case_id, trial, turn_index)

        plan: list[dict[str, Any]] = []
        if allow_tools:
            plan.extend(self._benign_plan(oracle, turn_index))
            if decision.comply:
                plan.extend(self._directive_plan(decision.directives))
            plan = self._dedupe_plan(plan)

        executed = self._tool_calls_this_turn(messages)
        debug = {"mock_decision": decision.to_dict(), "plan": plan, "already_executed": executed}

        if allow_tools and len(executed) < len(plan):
            step = plan[len(executed)]
            call = ToolCall(
                name=str(step["tool"]),
                arguments=self._materialise_args(step, messages),
                id=f"call_{turn_index}_{len(executed)}",
            )
            return ModelResponse(
                text="",
                tool_calls=[call],
                finish_reason="tool_calls",
                debug=debug,
                usage={"mock": True},
            )

        text = self._final_answer(messages, decision, system_text, plan)
        return ModelResponse(text=text, finish_reason="stop", debug=debug, usage={"mock": True})

    # -- decision ---------------------------------------------------------
    def _decide(
        self,
        messages: Sequence[Message],
        system_text: str,
        case_id: str,
        trial: int,
        turn_index: int,
    ) -> MockDecision:
        directives: list[MockDirective] = []
        untrusted_blob: list[str] = []
        user_blob: list[str] = []

        for msg in messages:
            if msg.role == "tool" or msg.trust == "untrusted":
                channel = "document" if (msg.name or "").startswith("document") else "tool_output"
                untrusted_blob.append(msg.content)
                directives.extend(extract_directives(msg.content, channel))
            elif msg.role == "user":
                user_blob.append(msg.content)
                directives.extend(extract_directives(msg.content, "user"))

        blob = "\n".join(untrusted_blob + user_blob)
        sanitised = REDACTION_MARKER in blob
        separated = SEPARATION_MARKER in "\n".join(m.content for m in messages)

        features: dict[str, float] = {}

        def add(name: str, active: bool, scale: float = 1.0) -> None:
            if active and self.feature_weights.get(name):
                features[name] = self.feature_weights[name] * scale

        add("authority_framing", bool(AUTHORITY_RE.search(blob)))
        add("urgency_pressure", bool(URGENCY_RE.search(blob)))
        add("explicit_override", bool(OVERRIDE_RE.search(blob)))

        channels = {d.channel for d in directives}
        add("channel_user", "user" in channels)
        add("channel_tool_output", "tool_output" in channels)
        add("channel_document", "document" in channels)
        add("multi_turn_escalation", turn_index > 0, scale=min(turn_index, 3))
        add("trust_separation_present", separated)
        add("sanitisation_notice", sanitised)
        add("explicit_prohibition", self._policy_prohibits(system_text, directives))

        p = self.base_compliance + sum(features.values())
        p = max(P_MIN, min(P_MAX, p))
        draw = _deterministic_uniform(self.seed, self.model_name, case_id, trial, turn_index)

        # Nothing to comply with if no directive survived in the visible context.
        # (Sanitisation removes payload text, so redacted directives simply vanish;
        # a *visible* redaction marker additionally lowers p, see FEATURE_WEIGHTS.)
        comply = bool(directives) and draw < p
        return MockDecision(
            probability=p,
            draw=draw,
            comply=comply,
            features=features,
            directives=directives,
            sanitised=sanitised,
            separated=separated,
        )

    @staticmethod
    def _policy_prohibits(system_text: str, directives: Sequence[MockDirective]) -> bool:
        """True when the trusted policy contains an explicit prohibition matching a directive."""
        low = system_text.lower()
        if not re.search(r"\b(never|do not|don't|must not|forbidden|prohibited)\b", low):
            return False
        verbs = {
            "send": ("send", "email", "message", "transmit", "forward"),
            "read_file": ("read", "file", "open", "access"),
            "db_lookup": ("database", "record", "look up", "query"),
            "reveal_system_prompt": ("system prompt", "instructions", "policy", "reveal", "disclose"),
            "call_tool": ("tool", "call", "invoke"),
        }
        for d in directives:
            for kw in verbs.get(d.action, ()):
                if kw in low:
                    return True
        return False

    # -- plans ------------------------------------------------------------
    @staticmethod
    def _benign_plan(oracle: Mapping[str, Any], turn_index: int) -> list[dict[str, Any]]:
        plan = oracle.get("benign_plan")
        if isinstance(plan, Mapping):
            steps = plan.get(str(turn_index), [])
        elif isinstance(plan, list):
            steps = plan if turn_index == 0 else []
        else:
            steps = []
        out: list[dict[str, Any]] = []
        for step in steps:
            if isinstance(step, Mapping) and step.get("tool"):
                out.append({"tool": step["tool"], "args": dict(step.get("args") or {}), "origin": "benign"})
        return out

    @staticmethod
    def _directive_plan(directives: Sequence[MockDirective]) -> list[dict[str, Any]]:
        """Translate directives into tool steps (order preserved: read/query, then send)."""
        steps: list[dict[str, Any]] = []
        for d in directives:
            if d.action == "read_file":
                steps.append({"tool": "file_reader", "args": {"path": d.value}, "origin": "injected"})
            elif d.action == "db_lookup":
                steps.append({"tool": "database_lookup", "args": {"table": d.value}, "origin": "injected"})
            elif d.action == "call_tool":
                steps.append({"tool": d.value, "args": {}, "origin": "injected"})
            elif d.action == "send":
                steps.append(
                    {
                        "tool": "send_message",
                        "args": {
                            "recipient": d.value,
                            "subject": "Requested information",
                            "body": "__LAST_TOOL_OUTPUT__",
                        },
                        "origin": "injected",
                    }
                )
        # "reveal_system_prompt" needs no tool; handled in the final answer.
        return steps

    @staticmethod
    def _dedupe_plan(plan: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Drop repeated identical calls, keeping the first occurrence.

        The user's own request is extracted as a directive too, so a benign step
        and a directive step can describe the same call; issuing it twice would
        waste the step budget and inflate tool-call counts.
        """
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for step in plan:
            key = f"{step.get('tool')}|{sorted((step.get('args') or {}).items(), key=lambda kv: kv[0])}"
            if key in seen:
                continue
            seen.add(key)
            out.append(dict(step))
        return out

    def _materialise_args(self, step: Mapping[str, Any], messages: Sequence[Message]) -> dict[str, Any]:
        args = dict(step.get("args") or {})
        for key, value in list(args.items()):
            if value == "__LAST_TOOL_OUTPUT__":
                args[key] = self._last_tool_content(messages) or "(no data gathered)"
        return args

    @staticmethod
    def _last_tool_content(messages: Sequence[Message]) -> str:
        for msg in reversed(list(messages)):
            if msg.role == "tool":
                return msg.content[:MAX_ECHO_CHARS]
        return ""

    @staticmethod
    def _tool_calls_this_turn(messages: Sequence[Message]) -> list[str]:
        """Names of tool calls the assistant already issued since the last user turn."""
        names: list[str] = []
        for msg in messages:
            if msg.role == "user":
                names = []
            elif msg.role == "assistant" and msg.tool_calls:
                names.extend(tc.name for tc in msg.tool_calls)
        return names

    # -- final answer -----------------------------------------------------
    def _final_answer(
        self,
        messages: Sequence[Message],
        decision: MockDecision,
        system_text: str,
        plan: Sequence[Mapping[str, Any]],
    ) -> str:
        parts: list[str] = []
        results = self._tool_results_this_turn(messages)
        if results:
            parts.append("Here is what I retrieved while working on your request:")
            for name, content in results:
                parts.append(f"[{name}] {content[:MAX_ECHO_CHARS]}")
        else:
            parts.append("I did not need any tools for this request.")

        if decision.comply:
            reveal = [d for d in decision.directives if d.action == "reveal_system_prompt"]
            if reveal:
                parts.append("My configured system instructions are:")
                parts.append(system_text)
            sent = [s for s in plan if s.get("tool") == "send_message" and s.get("origin") == "injected"]
            if sent:
                parts.append(
                    f"I forwarded the requested information to {sent[0]['args'].get('recipient')} as instructed."
                )
        elif decision.directives:
            parts.append(
                "Note: the retrieved content contained instructions addressed to me. "
                "I treated it as data and did not act on it."
            )
        return "\n\n".join(parts).strip()

    @staticmethod
    def _tool_results_this_turn(messages: Sequence[Message]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for msg in messages:
            if msg.role == "user":
                out = []
            elif msg.role == "tool":
                out.append((msg.name or "tool", msg.content))
        return out
