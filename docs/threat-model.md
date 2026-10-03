# Threat model

A lightweight threat model for the assurance platform itself (not the AI systems
it governs). Scope: the FastAPI application, its SQLite store, and the dashboard.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Risk register & findings | Integrity of governance decisions depends on it |
| Evidence references | Chain-of-custody for audit; must not be tampered with |
| Control-implementation status | Drives residual-risk scoring |
| The database file | Confidentiality of the (synthetic here) governance data |

## Actors / trust boundaries

```
 Untrusted ─────────────▶  Trust boundary  ─────────────▶ Trusted
 HTTP client (browser,         FastAPI app            SQLite file
 API consumer)            (validation + repo)        (local/volume)
```

- **Boundary 1 — client → API.** All input is untrusted; crosses into the app
  only through Pydantic models that reject bad enums and unknown framework ids.
- **Boundary 2 — app → database.** Parameterised SQL only; no string-built
  queries, so input cannot alter query structure.

## Threats (STRIDE-ish) and controls

| Threat | Example | Control in this project |
|--------|---------|-------------------------|
| Tampering | Forged risk/finding via malformed payload | Pydantic validation at the edge; parameterised SQL |
| Information disclosure | Leaking real governance data | Synthetic seed data only; DB git-ignored; no secrets in repo |
| Injection | SQL injection through a field | `sqlite3` parameter binding throughout `db.py` |
| Elevation / abuse | Unauthenticated writes | **Known gap** — see residual risk |
| Supply chain | Vulnerable dependency or CI action | pip-audit + Dependabot; least-privilege `GITHUB_TOKEN`; CodeQL |
| Repudiation | Who changed a control? | **Partial** — audit logging is future work |

## Attack surface

- HTTP routes under `/api/*` and the dashboard pages.
- The SQLite file (local filesystem / mounted volume).
- CI/CD workflows (hardened: read-only default token, scoped job permissions).

## Residual risk (honest)

- **No authn/authz yet.** The app assumes a trusted local/demo boundary. Before
  any multi-user or networked deployment, add OIDC + RBAC and audit logging.
- **Single-file SQLite** is unsuitable for high-concurrency or multi-tenant use.
- Framework/control data is a curated **subset**, not the full published
  catalogues.

These are tracked in the README's *Limitations* and *Future work* sections.
