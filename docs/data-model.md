# Data model

The schema (`app/schema.sql`) models the assurance loop as seven tables.

```
ai_systems ──1:N── findings ──(promoted to)── risks
     │                  │                        │
     │                  │                        ├─N:M─ controls   (via risk_controls, with impl. status)
     │                  │                        │
     └──────── evidence (ref_type=finding|risk, ref_id) ───────────┘
                        │
              remediations ──1:N── retests   (retest.result closes the loop)
```

## Tables

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `ai_systems` | Inventory of AI/ML systems in scope | `name`, `lifecycle_stage`, `data_sensitivity` |
| `findings` | Red-team / assessment findings | `severity`, `owasp_llm`, `mitre_atlas`, `status` |
| `risks` | Risk register entries | `likelihood`, `impact`, `rmf_function` |
| `controls` | Control catalogue (seeded from `frameworks.py`) | `control_id`, `framework`, `maps_to` |
| `risk_controls` | Which controls treat which risk | `status` (not_implemented→implemented) |
| `evidence` | Evidence register (reference + metadata only) | `ref_type`, `ref_id`, `kind`, `location` |
| `remediations` / `retests` | Fixes and their verification | `status`, `result` |

## Derived values (not stored)

Risk scores are **computed** in `app/scoring.py`, never stored, so they always
reflect the current control implementation state:

- `inherent_score = likelihood × impact` (1..25)
- `control_effectiveness = mean(weight(status))` over mapped controls
  (`implemented`=1.0, `partial`=0.5, `planned`=0.1, `not_implemented`=0.0)
- `residual_score = round(inherent × (1 − effectiveness))`, floored at 1

## Framework references

`owasp_llm`, `mitre_atlas` and `rmf_function` columns store **identifiers**
(e.g. `LLM01`, `AML.T0051`, `MEASURE`) that are validated on write against the
taxonomies in `app/frameworks.py`. This keeps the register mapping-consistent:
a finding cannot cite an OWASP category that does not exist.
