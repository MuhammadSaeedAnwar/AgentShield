"""AgentShield: security evaluation of tool-using LLM agents.

AgentShield is a small, reproducible benchmark harness that measures whether a
tool-using LLM agent keeps the boundary between *trusted instructions* (the
system policy and the user's request) and *untrusted content* (retrieved
documents, tool outputs, files, database rows).

Pipeline
--------
    attack test case
        -> agent (ModelAdapter + tools + optional defenses)
        -> simulated tool environment (no real side effects)
        -> detectors (signals extracted from the episode)
        -> outcome classification (rule-based, per-case criteria)
        -> metrics (ASR, safe completion, unauthorized tool calls, ...)
        -> results (JSON + CSV + tables/charts)

Nothing in this package fabricates results: every number is produced by
executing episodes and counting outcomes.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
