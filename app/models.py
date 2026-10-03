"""Pydantic models for API request/response validation.

These validate inbound payloads (so the API rejects an out-of-range likelihood
or an unknown OWASP id before it touches the database) and shape JSON output.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from . import frameworks

Severity = str
Status = str


class AISystemIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    owner: str = ""
    lifecycle_stage: str = "development"
    model_type: str = ""
    data_sensitivity: str = "internal"

    @field_validator("lifecycle_stage")
    @classmethod
    def _stage(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "retired"}
        if v not in allowed:
            raise ValueError(f"lifecycle_stage must be one of {sorted(allowed)}")
        return v

    @field_validator("data_sensitivity")
    @classmethod
    def _sens(cls, v: str) -> str:
        allowed = {"public", "internal", "confidential", "restricted"}
        if v not in allowed:
            raise ValueError(f"data_sensitivity must be one of {sorted(allowed)}")
        return v


class FindingIn(BaseModel):
    system_id: int
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    severity: Severity = "medium"
    attack_vector: str = ""
    owasp_llm: str | None = None
    mitre_atlas: str | None = None

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v

    @field_validator("owasp_llm")
    @classmethod
    def _owasp(cls, v: str | None) -> str | None:
        if not frameworks.is_valid_owasp_llm(v):
            raise ValueError(f"unknown OWASP LLM id: {v}")
        return v

    @field_validator("mitre_atlas")
    @classmethod
    def _atlas(cls, v: str | None) -> str | None:
        if not frameworks.is_valid_atlas(v):
            raise ValueError(f"unknown MITRE ATLAS id: {v}")
        return v


class RiskIn(BaseModel):
    system_id: int
    finding_id: int | None = None
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    likelihood: int = Field(ge=1, le=5, default=3)
    impact: int = Field(ge=1, le=5, default=3)
    rmf_function: str | None = None
    owasp_llm: str | None = None
    mitre_atlas: str | None = None

    @field_validator("rmf_function")
    @classmethod
    def _rmf(cls, v: str | None) -> str | None:
        if not frameworks.is_valid_rmf_function(v):
            raise ValueError(f"unknown NIST AI RMF function: {v}")
        return v

    @field_validator("owasp_llm")
    @classmethod
    def _owasp(cls, v: str | None) -> str | None:
        if not frameworks.is_valid_owasp_llm(v):
            raise ValueError(f"unknown OWASP LLM id: {v}")
        return v


class RiskControlIn(BaseModel):
    control_id: int
    status: str = "planned"

    @field_validator("status")
    @classmethod
    def _st(cls, v: str) -> str:
        allowed = {"not_implemented", "planned", "partial", "implemented"}
        if v not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v
