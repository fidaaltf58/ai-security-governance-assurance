"""Security-framework reference data used across the assurance platform.

Everything here is *reference* data (taxonomies and control catalogues), kept in
code so the platform has no network dependency and the mappings are reviewable
in version control. Risk and finding records reference these identifiers; the
helpers below validate those references so a typo can't silently create an
unmapped risk.

Sources (public, non-proprietary identifiers only):
- NIST AI RMF 1.0 — the four functions GOVERN / MAP / MEASURE / MANAGE.
- NIST AI 600-1, Generative AI Profile — a subset of representative actions.
- OWASP Top 10 for LLM Applications (2025).
- MITRE ATLAS — a subset of adversary tactics relevant to this project.
"""

from __future__ import annotations

# --- NIST AI Risk Management Framework (AI RMF 1.0) -------------------------
# The RMF is organised around four high-level functions.
NIST_AI_RMF_FUNCTIONS: dict[str, str] = {
    "GOVERN": "Cultivate a culture of risk management; policies, accountability, oversight.",
    "MAP": "Establish context and identify risks related to the AI system.",
    "MEASURE": "Analyse, assess and track identified AI risks with metrics.",
    "MANAGE": "Prioritise and act on risks; allocate resources; monitor over time.",
}

# --- NIST Generative AI Profile (NIST AI 600-1) -----------------------------
# Representative actions a GenAI deployment is expected to take, keyed by a
# short local id and tagged with the RMF function they support.
NIST_GENAI_PROFILE: dict[str, dict[str, str]] = {
    "GV-1.2": {"function": "GOVERN", "text": "Define and document GenAI acceptable-use and escalation policy."},
    "MP-2.3": {"function": "MAP", "text": "Document intended purpose, context of use and foreseeable misuse."},
    "MS-2.6": {"function": "MEASURE", "text": "Evaluate the system for prompt-injection and data-leakage risk."},
    "MS-2.7": {"function": "MEASURE", "text": "Red-team the deployment against adversarial inputs before release."},
    "MG-4.1": {"function": "MANAGE", "text": "Monitor deployed GenAI for emergent risks and user feedback."},
}

# --- OWASP Top 10 for LLM Applications (2025) -------------------------------
OWASP_LLM_TOP_10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# --- MITRE ATLAS (subset of techniques relevant to this project) ------------
MITRE_ATLAS: dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0020": "Poison Training Data",
}

# --- Control catalogue ------------------------------------------------------
# Each control carries the framework it derives from so the dashboard can show
# coverage per framework. `framework` matches one of the taxonomies above.
CONTROL_CATALOGUE: list[dict[str, str]] = [
    {"control_id": "CTL-INJ-01", "framework": "OWASP-LLM", "maps_to": "LLM01",
     "title": "Input/retrieval trust boundary",
     "description": "Treat all retrieved and user content as untrusted; separate instructions from data."},
    {"control_id": "CTL-OUT-01", "framework": "OWASP-LLM", "maps_to": "LLM05",
     "title": "Output validation and encoding",
     "description": "Validate, encode and constrain model output before it reaches downstream systems."},
    {"control_id": "CTL-AGN-01", "framework": "OWASP-LLM", "maps_to": "LLM06",
     "title": "Least-privilege tool scoping",
     "description": "Grant the model the minimum tools/permissions; require human approval for high-impact actions."},
    {"control_id": "CTL-LEAK-01", "framework": "OWASP-LLM", "maps_to": "LLM02",
     "title": "Sensitive-data egress filter",
     "description": "Redact secrets/PII from prompts and responses; deny-list known sensitive patterns."},
    {"control_id": "CTL-GOV-01", "framework": "NIST-AI-RMF", "maps_to": "GOVERN",
     "title": "AI acceptable-use policy",
     "description": "Documented, owned policy governing permitted use and escalation paths."},
    {"control_id": "CTL-MEAS-01", "framework": "NIST-AI-RMF", "maps_to": "MEASURE",
     "title": "Pre-release adversarial evaluation",
     "description": "Mandatory red-team evaluation gate with recorded results before deployment."},
    {"control_id": "CTL-MON-01", "framework": "NIST-AI-RMF", "maps_to": "MANAGE",
     "title": "Runtime abuse monitoring",
     "description": "Log and alert on anomalous prompts, refusals and egress volume in production."},
]

# Valid framework keys a control may declare.
CONTROL_FRAMEWORKS = {"OWASP-LLM", "NIST-AI-RMF", "NIST-GENAI", "MITRE-ATLAS"}


def is_valid_rmf_function(value: str | None) -> bool:
    """True if ``value`` is a recognised NIST AI RMF function (or empty)."""
    return value in (None, "") or value in NIST_AI_RMF_FUNCTIONS


def is_valid_owasp_llm(value: str | None) -> bool:
    """True if ``value`` is a recognised OWASP LLM Top 10 id (or empty)."""
    return value in (None, "") or value in OWASP_LLM_TOP_10


def is_valid_atlas(value: str | None) -> bool:
    """True if ``value`` is a recognised MITRE ATLAS technique id (or empty)."""
    return value in (None, "") or value in MITRE_ATLAS


def control_by_id(control_id: str) -> dict[str, str] | None:
    """Return the catalogue entry for ``control_id`` or ``None``."""
    for ctl in CONTROL_CATALOGUE:
        if ctl["control_id"] == control_id:
            return ctl
    return None
