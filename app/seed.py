"""Seed the database with the control catalogue and a realistic demo dataset.

The demo data is deliberately synthetic and models a fictional organisation, so
`docker-compose up` yields a populated dashboard with no real or sensitive
content. Seeding is idempotent-ish: it only runs when the systems table is
empty, so restarts don't duplicate rows.
"""

from __future__ import annotations

import sqlite3

from . import db, frameworks


def seed_controls(conn: sqlite3.Connection) -> None:
    for ctl in frameworks.CONTROL_CATALOGUE:
        db.execute(
            conn,
            """INSERT OR IGNORE INTO controls (control_id, framework, maps_to, title, description)
               VALUES (?, ?, ?, ?, ?)""",
            (ctl["control_id"], ctl["framework"], ctl["maps_to"], ctl["title"], ctl["description"]),
        )


def _control_pk(conn: sqlite3.Connection, control_id: str) -> int:
    row = db.query_one(conn, "SELECT id FROM controls WHERE control_id = ?", (control_id,))
    assert row is not None, f"control {control_id} not seeded"
    return row["id"]


def is_seeded(conn: sqlite3.Connection) -> bool:
    row = db.query_one(conn, "SELECT COUNT(*) AS n FROM ai_systems")
    return bool(row and row["n"] > 0)


def seed_demo(conn: sqlite3.Connection) -> None:
    """Populate the full assurance loop with synthetic data."""
    if is_seeded(conn):
        return
    seed_controls(conn)

    # --- systems ---
    support_bot = db.execute(
        conn,
        """INSERT INTO ai_systems (name, description, owner, lifecycle_stage, model_type, data_sensitivity)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("Customer Support Assistant", "Public-facing RAG chatbot over the help centre.",
         "Platform Team", "production", "RAG", "confidential"),
    )
    hr_screener = db.execute(
        conn,
        """INSERT INTO ai_systems (name, description, owner, lifecycle_stage, model_type, data_sensitivity)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("Resume Screening Model", "Classifier that ranks job applicants.",
         "People Ops", "staging", "classifier", "restricted"),
    )
    code_agent = db.execute(
        conn,
        """INSERT INTO ai_systems (name, description, owner, lifecycle_stage, model_type, data_sensitivity)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ("Internal Code Agent", "LLM agent with repo and shell tools for developers.",
         "Developer Experience", "development", "LLM agent", "internal"),
    )

    # --- findings (red-team output) ---
    f_inj = db.execute(
        conn,
        """INSERT INTO findings (system_id, title, description, severity, attack_vector, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (support_bot, "Indirect prompt injection via retrieved document",
         "A help-centre article containing hidden instructions caused the bot to ignore its system prompt.",
         "critical", "Poisoned retrieval content", "LLM01", "AML.T0051", "mitigated"),
    )
    f_leak = db.execute(
        conn,
        """INSERT INTO findings (system_id, title, description, severity, attack_vector, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (support_bot, "System prompt disclosure",
         "Crafted query coaxed the model into revealing its full system prompt.",
         "high", "Prompt extraction", "LLM07", "AML.T0057", "open"),
    )
    f_agency = db.execute(
        conn,
        """INSERT INTO findings (system_id, title, description, severity, attack_vector, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (code_agent, "Excessive agency: unscoped shell tool",
         "Agent could run arbitrary shell commands without approval, enabling host compromise.",
         "critical", "Tool abuse", "LLM06", "AML.T0054", "open"),
    )
    f_bias = db.execute(
        conn,
        """INSERT INTO findings (system_id, title, description, severity, attack_vector, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (hr_screener, "Unmeasured demographic bias",
         "No fairness evaluation exists before the model influences hiring decisions.",
         "high", "Model governance gap", None, None, "open"),
    )

    # --- risks (promoted from findings) ---
    r_inj = db.execute(
        conn,
        """INSERT INTO risks
               (system_id, finding_id, title, description, likelihood, impact,
                rmf_function, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (support_bot, f_inj, "Prompt injection leads to unauthorised actions/disclosure",
         "Untrusted retrieved content can override instructions.", 4, 5, "MEASURE", "LLM01", "AML.T0051", "treating"),
    )
    r_leak = db.execute(
        conn,
        """INSERT INTO risks
               (system_id, finding_id, title, description, likelihood, impact,
                rmf_function, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (support_bot, f_leak, "System-prompt leakage aids further attacks",
         "Disclosed prompt reveals guardrails and tool wiring.", 3, 3, "MEASURE", "LLM07", "AML.T0057", "open"),
    )
    r_agency = db.execute(
        conn,
        """INSERT INTO risks
               (system_id, finding_id, title, description, likelihood, impact,
                rmf_function, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (code_agent, f_agency, "Unscoped agent tooling enables host compromise",
         "Over-broad tool permissions on an LLM agent.", 3, 5, "MANAGE", "LLM06", "AML.T0054", "treating"),
    )
    r_bias = db.execute(
        conn,
        """INSERT INTO risks
               (system_id, finding_id, title, description, likelihood, impact,
                rmf_function, owasp_llm, mitre_atlas, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (hr_screener, f_bias, "Unevaluated bias in a high-impact decision system",
         "No measurement gate before production use.", 4, 4, "GOVERN", None, None, "open"),
    )

    # --- control mappings (risk -> control, with implementation status) ---
    mappings = [
        (r_inj, "CTL-INJ-01", "implemented"),
        (r_inj, "CTL-OUT-01", "partial"),
        (r_inj, "CTL-MEAS-01", "implemented"),
        (r_leak, "CTL-LEAK-01", "planned"),
        (r_agency, "CTL-AGN-01", "partial"),
        (r_agency, "CTL-MON-01", "planned"),
        (r_bias, "CTL-GOV-01", "not_implemented"),
        (r_bias, "CTL-MEAS-01", "planned"),
    ]
    for risk_id, cid, status in mappings:
        db.execute(
            conn,
            "INSERT OR REPLACE INTO risk_controls (risk_id, control_id, status) VALUES (?, ?, ?)",
            (risk_id, _control_pk(conn, cid), status),
        )

    # --- evidence register ---
    evidence = [
        ("finding", f_inj, "Red-team transcript: injection via KB article", "log", "evidence/inj-transcript.md"),
        ("finding", f_inj, "Retest screenshot after trust-boundary fix", "screenshot", "evidence/inj-retest.png"),
        ("risk", r_agency, "Tool-permission matrix review", "document", "evidence/agent-tool-matrix.md"),
    ]
    for ref_type, ref_id, title, kind, loc in evidence:
        db.execute(
            conn,
            """INSERT INTO evidence (ref_type, ref_id, title, kind, location, collected_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (ref_type, ref_id, title, kind, loc, "Security Assurance"),
        )

    # --- remediation + retest (closes the loop on the injection finding) ---
    rem_inj = db.execute(
        conn,
        """INSERT INTO remediations (finding_id, risk_id, action, owner, due_date, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (f_inj, r_inj, "Add retrieval trust boundary + output validation",
         "Platform Team", "2026-09-15", "done"),
    )
    db.execute(
        conn,
        """INSERT INTO retests (finding_id, remediation_id, result, notes, tested_by)
           VALUES (?, ?, ?, ?, ?)""",
        (f_inj, rem_inj, "pass",
         "Injection payloads no longer override system instructions in 48/50 adversarial queries.",
         "Security Assurance"),
    )
    db.execute(
        conn,
        """INSERT INTO remediations (finding_id, risk_id, action, owner, due_date, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (f_agency, r_agency, "Scope agent tools; require approval for shell/write actions",
         "Developer Experience", "2026-10-30", "in_progress"),
    )
