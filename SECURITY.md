# Security Policy

## Scope and intent

This project is an **AI security governance and assurance platform**: it tracks
AI systems, risks, controls, red-team findings and evidence, mapped to public
frameworks (NIST AI RMF, OWASP LLM Top 10, MITRE ATLAS). It is a management and
record-keeping tool — it does **not** attack, scan, or interact with any AI
system itself.

## Data assumptions

- All data shipped in this repository is **synthetic**. The seed dataset models
  a fictional organisation and fictional findings; it contains no real system
  prompts, no real customer or vendor data, and no live exploit payloads.
- The runtime database (`data/governance.db`) is git-ignored. Do not commit a
  database that contains real engagement or customer data.
- Evidence records store a **reference/location** (a path or URI) and metadata,
  not the raw evidence. Keep sensitive evidence out of the repository.

## What not to commit

`.env`, `*.pem`, `*.key`, `credentials.json`, cloud access keys, any real
`*.db`/`*.sqlite`, or any reconstructed system prompt / working jailbreak
targeting a named production system. CI runs a secret scan (gitleaks) and a
dependency scan (pip-audit) on every push.

## Reporting a vulnerability

If you find a security issue in this code, please open a GitHub Security
Advisory on the repository (preferred) or open an issue **without** including a
working exploit. Reports are acknowledged within 7 days. Please allow a
reasonable period for a fix before any public disclosure.

## Out of scope

- The synthetic seed data and its fictional findings.
- Denial of service from obviously abusive input to a locally hosted instance.
