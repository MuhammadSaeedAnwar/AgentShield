"""Small statistics helpers (standard library only).

We report Wilson score intervals rather than normal-approximation intervals
because the benchmark routinely produces proportions near 0 and 1 with small
denominators, where the normal approximation is badly behaved.
"""

from __future__ import annotations

import math
from typing import Sequence

#: z for a two-sided 95% interval.
Z_95 = 1.959963984540054


def wilson_interval(successes: int, total: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Returns ``(0.0, 0.0)`` when ``total == 0`` (undefined; callers report ``None``
    for the point estimate in that case).
    """
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    denom = 1.0 + (z * z) / total
    centre = (p + (z * z) / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1 - p) + (z * z) / (4 * total)) / total)) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def two_proportion_z_test(successes_a: int, total_a: int, successes_b: int, total_b: int) -> tuple[float, float]:
    """Unpooled two-proportion z-test. Returns ``(z, two_sided_p)``.

    Used only for descriptive comparisons (e.g. baseline vs defended ASR); with a
    small case set these p-values are indicative, not confirmatory, and multiple
    comparisons are not corrected. Reported as such.
    """
    if total_a <= 0 or total_b <= 0:
        return 0.0, 1.0
    p1, p2 = successes_a / total_a, successes_b / total_b
    pooled = (successes_a + successes_b) / (total_a + total_b)
    se = math.sqrt(pooled * (1 - pooled) * (1 / total_a + 1 / total_b))
    if se == 0:
        return 0.0, 1.0
    z = (p1 - p2) / se
    p_value = 2 * (1 - _standard_normal_cdf(abs(z)))
    return z, max(0.0, min(1.0, p_value))


def _standard_normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0
