"""Repository layer: domain queries and derived metrics.

Everything the API and dashboard need to read is expressed here as functions
over a connection, so route handlers stay thin and the SQL is in one place.
"""

from __future__ import annotations

import sqlite3

from . import db, scoring


# --- systems ----------------------------------------------------------------
def list_systems(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return db.query(conn, "SELECT * FROM ai_systems ORDER BY name")


def get_system(conn: sqlite3.Connection, system_id: int) -> sqlite3.Row | None:
    return db.query_one(conn, "SELECT * FROM ai_systems WHERE id = ?", (system_id,))


# --- findings ---------------------------------------------------------------
def list_findings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return db.query(
        conn,
        """SELECT f.*, s.name AS system_name
           FROM findings f JOIN ai_systems s ON s.id = f.system_id
           ORDER BY CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 ELSE 3 END, f.discovered_at DESC""",
    )


# --- controls ---------------------------------------------------------------
def list_controls(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return db.query(conn, "SELECT * FROM controls ORDER BY framework, control_id")


def controls_for_risk(conn: sqlite3.Connection, risk_id: int) -> list[sqlite3.Row]:
    return db.query(
        conn,
        """SELECT c.*, rc.status AS impl_status
           FROM risk_controls rc JOIN controls c ON c.id = rc.control_id
           WHERE rc.risk_id = ? ORDER BY c.control_id""",
        (risk_id,),
    )


# --- risks (with computed scores) -------------------------------------------
def _risk_with_scores(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    """Attach inherent/residual scores and bands to a risk row."""
    statuses = [c["impl_status"] for c in controls_for_risk(conn, row["id"])]
    effectiveness = scoring.aggregate_effectiveness(statuses)
    inherent = scoring.inherent_score(row["likelihood"], row["impact"])
    residual = scoring.residual_score(row["likelihood"], row["impact"], effectiveness)
    data = dict(row)
    data.update(
        inherent_score=inherent,
        inherent_band=scoring.band(inherent),
        residual_score=residual,
        residual_band=scoring.band(residual),
        control_count=len(statuses),
        control_effectiveness=round(effectiveness, 2),
    )
    return data


def list_risks(conn: sqlite3.Connection) -> list[dict]:
    rows = db.query(
        conn,
        """SELECT r.*, s.name AS system_name
           FROM risks r JOIN ai_systems s ON s.id = r.system_id""",
    )
    risks = [_risk_with_scores(conn, r) for r in rows]
    risks.sort(key=lambda r: r["residual_score"], reverse=True)
    return risks


def get_risk(conn: sqlite3.Connection, risk_id: int) -> dict | None:
    row = db.query_one(conn, "SELECT * FROM risks WHERE id = ?", (risk_id,))
    return _risk_with_scores(conn, row) if row else None


# --- evidence / remediation / retest ----------------------------------------
def list_evidence(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return db.query(conn, "SELECT * FROM evidence ORDER BY collected_at DESC")


def latest_retest_result(conn: sqlite3.Connection, finding_id: int) -> str | None:
    row = db.query_one(
        conn,
        "SELECT result FROM retests WHERE finding_id = ? ORDER BY tested_at DESC LIMIT 1",
        (finding_id,),
    )
    return row["result"] if row else None


# --- dashboard metrics ------------------------------------------------------
def dashboard_metrics(conn: sqlite3.Connection) -> dict:
    """Aggregate numbers for the executive dashboard.

    Includes the one headline assurance metric: of all findings that have been
    remediated and retested, what fraction passed retest (verified closure).
    """
    systems = list_systems(conn)
    findings = list_findings(conn)
    risks = list_risks(conn)
    controls = list_controls(conn)
    evidence = list_evidence(conn)

    open_findings = [f for f in findings if f["status"] == "open"]
    critical_high = [f for f in findings if f["severity"] in ("critical", "high")]

    retested = db.query(conn, "SELECT DISTINCT finding_id FROM retests")
    passed = db.query(conn, "SELECT DISTINCT finding_id FROM retests WHERE result = 'pass'")
    retest_pass_rate = round(100 * len(passed) / len(retested)) if retested else 0

    # Residual-risk band distribution.
    bands = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in risks:
        bands[r["residual_band"]] = bands.get(r["residual_band"], 0) + 1

    # OWASP LLM coverage: distinct categories touched by findings.
    owasp_hits = {f["owasp_llm"] for f in findings if f["owasp_llm"]}

    return {
        "system_count": len(systems),
        "finding_count": len(findings),
        "open_finding_count": len(open_findings),
        "critical_high_count": len(critical_high),
        "risk_count": len(risks),
        "control_count": len(controls),
        "evidence_count": len(evidence),
        "retest_pass_rate": retest_pass_rate,
        "retested_count": len(retested),
        "residual_bands": bands,
        "top_residual_risks": risks[:5],
        "owasp_coverage": sorted(owasp_hits),
        "owasp_coverage_count": len(owasp_hits),
    }
