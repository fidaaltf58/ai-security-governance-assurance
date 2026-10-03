"""Tests for framework reference data and control-mapping integrity."""

from __future__ import annotations

from app import frameworks


def test_owasp_top_10_complete():
    assert len(frameworks.OWASP_LLM_TOP_10) == 10
    assert set(frameworks.OWASP_LLM_TOP_10) == {f"LLM{i:02d}" for i in range(1, 11)}


def test_rmf_has_four_functions():
    assert set(frameworks.NIST_AI_RMF_FUNCTIONS) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_genai_profile_functions_are_valid_rmf():
    for action in frameworks.NIST_GENAI_PROFILE.values():
        assert action["function"] in frameworks.NIST_AI_RMF_FUNCTIONS


def test_every_control_maps_to_a_known_reference():
    # A control's maps_to must resolve against the framework it declares.
    for ctl in frameworks.CONTROL_CATALOGUE:
        assert ctl["framework"] in frameworks.CONTROL_FRAMEWORKS
        if ctl["framework"] == "OWASP-LLM":
            assert ctl["maps_to"] in frameworks.OWASP_LLM_TOP_10
        elif ctl["framework"] == "NIST-AI-RMF":
            assert ctl["maps_to"] in frameworks.NIST_AI_RMF_FUNCTIONS


def test_control_ids_unique():
    ids = [c["control_id"] for c in frameworks.CONTROL_CATALOGUE]
    assert len(ids) == len(set(ids))


def test_validators():
    assert frameworks.is_valid_owasp_llm("LLM01")
    assert frameworks.is_valid_owasp_llm(None)
    assert not frameworks.is_valid_owasp_llm("LLM99")
    assert frameworks.is_valid_rmf_function("GOVERN")
    assert not frameworks.is_valid_rmf_function("WHATEVER")
    assert frameworks.is_valid_atlas("AML.T0051")
    assert not frameworks.is_valid_atlas("AML.T9999")
