"""Risk-scoring logic for the assurance platform.

Kept deliberately small and pure (no I/O) so it is easy to unit-test and easy
to explain: inherent risk is a 5x5 likelihood x impact matrix, and residual
risk is the inherent score reduced by the effectiveness of the controls that
have actually been implemented against it.
"""

from __future__ import annotations

LIKELIHOOD_LEVELS = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost certain"}
IMPACT_LEVELS = {1: "Negligible", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Severe"}

# Score band thresholds on the 1..25 scale.
_BANDS = ((1, 4, "Low"), (5, 9, "Medium"), (10, 15, "High"), (16, 25, "Critical"))


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def inherent_score(likelihood: int, impact: int) -> int:
    """Inherent risk = likelihood x impact on a 1..25 scale.

    Inputs are clamped to 1..5 so a malformed record cannot produce a score
    outside the matrix.
    """
    return _clamp(likelihood, 1, 5) * _clamp(impact, 1, 5)


def residual_score(likelihood: int, impact: int, control_effectiveness: float) -> int:
    """Residual risk after controls.

    ``control_effectiveness`` is 0.0 (no mitigation) .. 1.0 (fully mitigated).
    Residual never drops below 1 while any risk remains, reflecting that no
    control set reduces real-world risk to exactly zero.
    """
    effectiveness = max(0.0, min(1.0, control_effectiveness))
    inherent = inherent_score(likelihood, impact)
    residual = round(inherent * (1.0 - effectiveness))
    return max(1, residual)


def band(score: int) -> str:
    """Map a 1..25 score to a qualitative band."""
    for low, high, label in _BANDS:
        if low <= score <= high:
            return label
    return "Critical" if score > 25 else "Low"


def aggregate_effectiveness(control_statuses: list[str]) -> float:
    """Combine per-control implementation statuses into one effectiveness value.

    Each control contributes a weight; the result is the mean weight, so a risk
    with several partially-implemented controls lands between "none" and "full".
    An empty list means no controls, i.e. zero effectiveness.
    """
    weights = {"implemented": 1.0, "partial": 0.5, "planned": 0.1, "not_implemented": 0.0}
    if not control_statuses:
        return 0.0
    total = sum(weights.get(s, 0.0) for s in control_statuses)
    return total / len(control_statuses)
