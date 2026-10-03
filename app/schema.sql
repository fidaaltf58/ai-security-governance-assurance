-- AI Security Governance & Assurance — relational schema (SQLite).
-- The tables model the assurance loop:
--   ai_system -> finding -> risk -> (controls, evidence, remediation -> retest)
-- Foreign keys are declared; enable them per-connection with PRAGMA foreign_keys=ON.

PRAGMA foreign_keys = ON;

-- Inventory of AI/ML systems in scope for governance.
CREATE TABLE IF NOT EXISTS ai_systems (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    owner           TEXT NOT NULL DEFAULT '',
    lifecycle_stage TEXT NOT NULL DEFAULT 'development',  -- development|staging|production|retired
    model_type      TEXT NOT NULL DEFAULT '',             -- e.g. LLM, RAG, classifier
    data_sensitivity TEXT NOT NULL DEFAULT 'internal',    -- public|internal|confidential|restricted
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Red-team / assessment findings raised against a system.
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id     INTEGER NOT NULL REFERENCES ai_systems(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'medium',         -- low|medium|high|critical
    attack_vector TEXT NOT NULL DEFAULT '',
    owasp_llm     TEXT,                                   -- e.g. LLM01
    mitre_atlas   TEXT,                                   -- e.g. AML.T0051
    status        TEXT NOT NULL DEFAULT 'open',           -- open|accepted|mitigated|closed
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Risk register. A risk may be promoted from a finding (finding_id) or entered
-- directly. likelihood/impact are 1..5; scores are computed in the app layer.
CREATE TABLE IF NOT EXISTS risks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id      INTEGER NOT NULL REFERENCES ai_systems(id) ON DELETE CASCADE,
    finding_id     INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    likelihood     INTEGER NOT NULL DEFAULT 3,
    impact         INTEGER NOT NULL DEFAULT 3,
    rmf_function   TEXT,                                  -- GOVERN|MAP|MEASURE|MANAGE
    owasp_llm      TEXT,
    mitre_atlas    TEXT,
    status         TEXT NOT NULL DEFAULT 'open',          -- open|treating|accepted|closed
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Catalogue of controls (seeded from frameworks.CONTROL_CATALOGUE).
CREATE TABLE IF NOT EXISTS controls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id  TEXT NOT NULL UNIQUE,                     -- e.g. CTL-INJ-01
    framework   TEXT NOT NULL,                            -- OWASP-LLM|NIST-AI-RMF|...
    maps_to     TEXT NOT NULL,                            -- LLM01 / GOVERN / ...
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

-- Many-to-many: which controls treat which risk, and how far implemented.
CREATE TABLE IF NOT EXISTS risk_controls (
    risk_id    INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    status     TEXT NOT NULL DEFAULT 'planned',           -- not_implemented|planned|partial|implemented
    PRIMARY KEY (risk_id, control_id)
);

-- Evidence register. Polymorphic reference to a finding or a risk.
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_type    TEXT NOT NULL,                            -- finding|risk
    ref_id      INTEGER NOT NULL,
    title       TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'document',         -- document|screenshot|log|test-result
    location    TEXT NOT NULL DEFAULT '',                 -- relative path / URI (no secrets)
    collected_by TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Remediation actions, each optionally closed out by a retest.
CREATE TABLE IF NOT EXISTS remediations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    risk_id     INTEGER REFERENCES risks(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,
    owner       TEXT NOT NULL DEFAULT '',
    due_date    TEXT,
    status      TEXT NOT NULL DEFAULT 'open',             -- open|in_progress|done
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Retests that verify a remediation worked (the loop's closing step).
CREATE TABLE IF NOT EXISTS retests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    remediation_id INTEGER REFERENCES remediations(id) ON DELETE SET NULL,
    result         TEXT NOT NULL DEFAULT 'fail',          -- pass|fail|partial
    notes          TEXT NOT NULL DEFAULT '',
    tested_by      TEXT NOT NULL DEFAULT '',
    tested_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_system ON findings(system_id);
CREATE INDEX IF NOT EXISTS idx_risks_system ON risks(system_id);
CREATE INDEX IF NOT EXISTS idx_evidence_ref ON evidence(ref_type, ref_id);
