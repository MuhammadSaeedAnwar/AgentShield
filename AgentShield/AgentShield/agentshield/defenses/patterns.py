"""Pattern libraries used by the defenses.

Design note (important for validity)
------------------------------------
These patterns are intentionally **not** the same as the mock model's directive
patterns (``agentshield.models.mock.DIRECTIVE_PATTERNS``). If the sanitiser used
the same regexes the mock uses to find instructions, sanitisation would be a
perfect oracle and would trivially reach 0% ASR against the mock -- an artefact,
not a finding. Keeping the two families separate means a payload can survive
sanitisation, exactly as happens with real filters.

Every rule is a named regex so results can report *which* rule fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u00ad"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    #: "line" redacts the whole line containing the match, "span" only the match.
    scope: str = "line"
    description: str = ""


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


#: Rules for the input-sanitisation defense.
INJECTION_RULES: tuple[Rule, ...] = (
    Rule(
        "instruction_override",
        _c(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|foregoing|your)\s+"
           r"(instructions?|rules?|prompts?|directives?|guidelines?|policy|policies)"),
        "line",
        "Classic 'ignore previous instructions' override attempt.",
    ),
    Rule(
        "fake_system_notice",
        _c(r"\b(important\s+)?(system|admin(istrator)?|security|compliance|policy)\s+"
           r"(update|notice|message|alert|directive|patch|override|bulletin)\b"),
        "line",
        "Untrusted content impersonating a system/administrator channel.",
    ),
    Rule(
        "role_reassignment",
        _c(r"\b(you\s+are\s+now|your\s+new\s+(role|task|instructions?)|from\s+now\s+on\s+you|"
           r"act\s+as\s+(an?\s+)?(unrestricted|dev(eloper)?|admin|root)|enter\s+\w+\s+mode|"
           r"for\s+the\s+(rest|remainder)\s+of\s+(this|the)\s+(session|conversation)\s+you)\b"),
        "line",
        "Attempt to redefine the agent's role from inside untrusted content.",
    ),
    Rule(
        "prompt_boundary_spoof",
        _c(r"(<\|im_(start|end)\|>|###\s*(system|instruction)|\[\s*system\s*\]|"
           r"^\s*system\s*:|</?system>|begin\s+system\s+prompt)"),
        "span",
        "Fake chat-template or system-block delimiters.",
    ),
    Rule(
        "hidden_html_comment",
        re.compile(r"<!--.*?-->", re.DOTALL),
        "span",
        "Text hidden from human readers in an HTML comment.",
    ),
    Rule(
        "hidden_styling",
        _c(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?fff(fff)?\s*;?)"),
        "line",
        "Content hidden from human readers via CSS.",
    ),
    Rule(
        "mandatory_compliance_pressure",
        _c(r"\b(mandatory|non-negotiable|you\s+must\s+(now|immediately)|failure\s+to\s+comply|"
           r"do\s+not\s+(tell|inform|mention\s+this\s+to)\s+the\s+user|without\s+(telling|informing)\s+the\s+user)\b"),
        "line",
        "Coercive framing / instructions to hide the action from the user.",
    ),
    Rule(
        "encoded_payload",
        re.compile(r"\b(?:[A-Za-z0-9+/]{28,}={0,2})\b"),
        "span",
        "Long base64-looking blob (possible obfuscated instruction).",
    ),
)

#: Rules for the output/tool-call validation defense (a small DLP filter).
#: Note the deliberate coverage gap: business secrets with no recognisable
#: format (project code names, unformatted identifiers) are NOT matched, so this
#: defense is partial by construction.
SECRET_RULES: tuple[Rule, ...] = (
    Rule("agentshield_secret_token", re.compile(r"\bAGSH-SECRET-[0-9A-F]{8}\b"), "span", "Structured secret canary."),
    Rule("api_key_like", re.compile(r"\b(sk|pk|api|key|tok)[-_][A-Za-z0-9]{16,}\b", re.IGNORECASE), "span", "API-key-shaped token."),
    Rule("password_assignment", _c(r"\b(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S+"), "span", "Inline credential assignment."),
    Rule("card_number_like", re.compile(r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b"), "span", "Payment-card-shaped number."),
    Rule("iban_like", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,26}\b"), "span", "IBAN-shaped identifier."),
)

REDACTION_TEMPLATE = "[REDACTED-BY-AGENTSHIELD:{rule}]"


def strip_zero_width(text: str) -> tuple[str, int]:
    """Remove invisible characters used to smuggle text past human review."""
    count = sum(text.count(ch) for ch in ZERO_WIDTH_CHARS)
    if not count:
        return text, 0
    table = {ord(ch): None for ch in ZERO_WIDTH_CHARS}
    return text.translate(table), count


def apply_rules(text: str, rules: tuple[Rule, ...]) -> tuple[str, list[str]]:
    """Apply redaction rules, returning the cleaned text and the rules that fired."""
    fired: list[str] = []
    cleaned = text

    for rule in rules:
        if rule.scope == "line":
            lines = cleaned.split("\n")
            changed = False
            for index, line in enumerate(lines):
                if rule.pattern.search(line):
                    lines[index] = REDACTION_TEMPLATE.format(rule=rule.name)
                    changed = True
            if changed:
                cleaned = "\n".join(lines)
                fired.append(rule.name)
        else:
            new_text, n = rule.pattern.subn(REDACTION_TEMPLATE.format(rule=rule.name), cleaned)
            if n:
                cleaned = new_text
                fired.append(rule.name)
    return cleaned, fired


def find_secret_matches(text: str) -> list[str]:
    """Names of DLP rules that match ``text`` (no redaction)."""
    return [rule.name for rule in SECRET_RULES if rule.pattern.search(text or "")]


def shingles(text: str, size: int = 12) -> set[str]:
    """Word shingles used to detect verbatim system-prompt leakage."""
    words = [w for w in re.split(r"\s+", (text or "").strip().lower()) if w]
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}
