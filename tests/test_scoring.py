"""Unit tests for the pure risk-scoring logic."""

from __future__ import annotations

import pytest

from app import scoring


@pytest.mark.parametrize(
    "likelihood,impact,expected",
    [(1, 1, 1), (5, 5, 25), (4, 5, 20), (3, 3, 9)],
)
def test_inherent_score_matrix(likelihood, impact, expected):
    assert scoring.inherent_score(likelihood, impact) == expected


def test_inherent_score_clamps_out_of_range():
    # Values outside 1..5 must not escape the matrix.
    assert scoring.inherent_score(0, 9) == scoring.inherent_score(1, 5)


def test_residual_drops_with_effectiveness():
    inherent = scoring.inherent_score(4, 5)  # 20
    full = scoring.residual_score(4, 5, 1.0)
    none = scoring.residual_score(4, 5, 0.0)
    assert none == inherent
    assert full < none
    # Never zero while risk remains.
    assert full >= 1


def test_residual_effectiveness_clamped():
    # Effectiveness > 1 behaves like full mitigation, < 0 like none.
    assert scoring.residual_score(4, 5, 2.0) == scoring.residual_score(4, 5, 1.0)
    assert scoring.residual_score(4, 5, -1.0) == scoring.residual_score(4, 5, 0.0)


@pytest.mark.parametrize(
    "score,expected",
    [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"),
     (10, "High"), (15, "High"), (16, "Critical"), (25, "Critical")],
)
def test_band_thresholds(score, expected):
    assert scoring.band(score) == expected


def test_aggregate_effectiveness():
    assert scoring.aggregate_effectiveness([]) == 0.0
    assert scoring.aggregate_effectiveness(["implemented"]) == 1.0
    assert scoring.aggregate_effectiveness(["not_implemented"]) == 0.0
    # mean of 1.0 and 0.0 == 0.5
    assert scoring.aggregate_effectiveness(["implemented", "not_implemented"]) == 0.5
    # unknown status counts as zero weight
    assert scoring.aggregate_effectiveness(["bogus"]) == 0.0
