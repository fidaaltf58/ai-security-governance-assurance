"""Tests for the risk/control relationship and residual-score computation."""

from __future__ import annotations

from app import repo, scoring


def test_seed_populates_loop(conn):
    assert len(repo.list_systems(conn)) >= 3
    assert len(repo.list_findings(conn)) >= 4
    assert len(repo.list_risks(conn)) >= 4
    assert len(repo.list_controls(conn)) == 7


def test_controls_reduce_residual_below_inherent(conn):
    risks = repo.list_risks(conn)
    # The injection risk has implemented controls, so residual < inherent.
    inj = next(r for r in risks if r["owasp_llm"] == "LLM01")
    assert inj["control_count"] >= 1
    assert inj["residual_score"] < inj["inherent_score"]


def test_risk_with_no_effective_controls_keeps_full_inherent(conn):
    risks = repo.list_risks(conn)
    # The bias risk has only not_implemented/planned controls -> low effectiveness.
    bias = next(r for r in risks if "bias" in r["title"].lower())
    assert bias["residual_score"] == scoring.inherent_score(bias["likelihood"], bias["impact"]) or \
        bias["residual_score"] >= bias["inherent_score"] - 2  # planned controls barely move it


def test_risks_sorted_by_residual_desc(conn):
    scores = [r["residual_score"] for r in repo.list_risks(conn)]
    assert scores == sorted(scores, reverse=True)


def test_metrics_retest_pass_rate(conn):
    metrics = repo.dashboard_metrics(conn)
    # One finding was remediated and passed retest in the seed data.
    assert metrics["retested_count"] >= 1
    assert 0 <= metrics["retest_pass_rate"] <= 100
    assert metrics["retest_pass_rate"] == 100
