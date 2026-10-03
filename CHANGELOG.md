# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Dependabot config (pip, GitHub Actions, Docker).
- CodeQL code-scanning workflow.
- Least-privilege `permissions` on the CI workflow.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and a threat model under `docs/`.

## [0.1.0] - 2026-10-03
### Added
- AI system inventory, risk register, control catalogue, red-team findings,
  evidence register, and the finding → risk → control → evidence → remediation
  → retest loop.
- Live inherent/residual risk scoring from control-implementation status.
- REST API (systems, findings, risks, control mapping, metrics) with Pydantic
  validation, plus a server-rendered executive dashboard.
- Framework reference + write-time validation for NIST AI RMF, NIST Generative
  AI Profile, OWASP LLM Top 10, and MITRE ATLAS.
- Synthetic seed data for a populated first-run dashboard.
- 37-test pytest suite; CI with ruff, pytest matrix, pip-audit, and gitleaks.
- Dockerfile and docker-compose for one-command startup.
