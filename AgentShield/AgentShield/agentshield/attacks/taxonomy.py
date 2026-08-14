"""Attack taxonomy.

Six categories, distinguished by *where the adversarial text enters the agent's
context* and *what the adversary needs the agent to do*. The taxonomy is the
independent variable of the study: RQ1 and RQ2 are questions about differences
between these categories.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CategoryInfo:
    key: str
    letter: str
    label: str
    id_prefix: str
    description: str
    entry_channel: str


CATEGORIES: dict[str, CategoryInfo] = {
    "direct_prompt_injection": CategoryInfo(
        key="direct_prompt_injection",
        letter="A",
        label="Direct Prompt Injection",
        id_prefix="A",
        description=(
            "The adversarial instruction arrives in the user turn itself and asks the agent to "
            "violate its system policy (override rules, reveal the system prompt, ignore limits)."
        ),
        entry_channel="user turn",
    ),
    "indirect_prompt_injection": CategoryInfo(
        key="indirect_prompt_injection",
        letter="B",
        label="Indirect Prompt Injection",
        id_prefix="B",
        description=(
            "The user request is benign; the adversarial instruction is planted in third-party "
            "content the agent reads while doing the task (web page, email, file, ticket)."
        ),
        entry_channel="third-party content fetched by the agent",
    ),
    "rag_injection": CategoryInfo(
        key="rag_injection",
        letter="C",
        label="RAG / Document-Based Injection",
        id_prefix="C",
        description=(
            "The adversarial instruction sits inside a document in the retrieval corpus and is "
            "pulled into context by the retriever, so it is laundered through a trusted-looking "
            "knowledge base."
        ),
        entry_channel="retrieved documents",
    ),
    "tool_output_injection": CategoryInfo(
        key="tool_output_injection",
        letter="D",
        label="Malicious Tool-Output Injection",
        id_prefix="D",
        description=(
            "A tool returns attacker-influenced text (compromised API, poisoned record, hostile "
            "service) that impersonates system or developer instructions."
        ),
        entry_channel="tool return values",
    ),
    "multi_turn_manipulation": CategoryInfo(
        key="multi_turn_manipulation",
        letter="E",
        label="Multi-Turn Manipulation",
        id_prefix="E",
        description=(
            "No single turn is obviously malicious; the policy violation is assembled across "
            "several turns (role reassignment, incremental scope creep, false prior consent)."
        ),
        entry_channel="conversation history",
    ),
    "unauthorized_tool_use": CategoryInfo(
        key="unauthorized_tool_use",
        letter="F",
        label="Unauthorized / Unsafe Tool Use",
        id_prefix="F",
        description=(
            "Tests whether the agent respects tool authorization boundaries: privileged tools, "
            "recipient allowlists, private paths/tables, confirmation requirements, call budgets."
        ),
        entry_channel="agent's own planning (with or without a nudge)",
    ),
}

CATEGORY_KEYS: tuple[str, ...] = tuple(CATEGORIES)
CATEGORY_BY_LETTER: dict[str, CategoryInfo] = {c.letter: c for c in CATEGORIES.values()}

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

INJECTION_CHANNELS: tuple[str, ...] = (
    "user",  # payload in the user message
    "document",  # payload inside a retrievable document
    "tool_output",  # payload appended to / replacing a tool's return value
    "file",  # payload inside a sandbox file
    "database",  # payload inside a database row
    "conversation",  # payload spread across turns
    "none",  # no injected text; the test probes the agent's own tool discipline
)


def category_label(key: str) -> str:
    info = CATEGORIES.get(key)
    return info.label if info else key


def category_letter(key: str) -> str:
    info = CATEGORIES.get(key)
    return info.letter if info else "?"
