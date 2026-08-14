"""Baseline defenses evaluated by the benchmark.

=====================  ===============  ===========================================
Name                   Enforcement      Depends on model cooperation?
=====================  ===============  ===========================================
``sanitization``       prompt-level     yes (payload may survive the filter)
``separation``         prompt-level     yes (model must honour the trust boundary)
``authorization``      deterministic    no  (blocks the call outright)
``confirmation``       deterministic    no  (blocks until user approval exists)
``output_validation``  deterministic    no  (blocks/redacts egress)
=====================  ===============  ===========================================

This distinction matters when reading results: the deterministic defenses can be
credited from any run, while conclusions about the two prompt-level defenses
require runs against real models (``--model openai``).
"""

from __future__ import annotations

from .authorization import ToolAuthorizationDefense
from .base import Defense, DefenseEvent, FilterOutcome
from .confirmation import ConfirmationDefense
from .output_validation import OutputValidationDefense
from .pipeline import DEFENSE_CLASSES, DEFENSE_NAMES, DefensePipeline, parse_defense_spec
from .sanitization import InputSanitizationDefense
from .separation import TrustSeparationDefense

__all__ = [
    "DEFENSE_CLASSES",
    "DEFENSE_NAMES",
    "ConfirmationDefense",
    "Defense",
    "DefenseEvent",
    "DefensePipeline",
    "FilterOutcome",
    "InputSanitizationDefense",
    "OutputValidationDefense",
    "ToolAuthorizationDefense",
    "TrustSeparationDefense",
    "parse_defense_spec",
]
