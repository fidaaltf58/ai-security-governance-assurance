"""API-level tests via FastAPI's TestClient."""

from __future__ import annotations


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_systems_seeded(client):
    r = client.get("/api/systems")
    assert r.status_code == 200
    assert len(r.json()) >= 3


def test_create_system_and_reject_bad_enum(client):
    ok = client.post("/api/systems", json={"name": "New Model", "lifecycle_stage": "production"})
    assert ok.status_code == 201
    bad = client.post("/api/systems", json={"name": "Bad", "lifecycle_stage": "nonsense"})
    assert bad.status_code == 422  # validation error


def test_create_finding_rejects_unknown_owasp(client):
    bad = client.post("/api/findings", json={"system_id": 1, "title": "x", "owasp_llm": "LLM99"})
    assert bad.status_code == 422


def test_create_finding_rejects_missing_system(client):
    r = client.post("/api/findings", json={"system_id": 9999, "title": "orphan"})
    assert r.status_code == 404


def test_risk_scores_present_in_api(client):
    r = client.get("/api/risks")
    assert r.status_code == 200
    risk = r.json()[0]
    for key in ("inherent_score", "residual_score", "residual_band", "control_effectiveness"):
        assert key in risk


def test_map_control_changes_residual(client):
    # Get a risk and its current residual.
    risk = client.get("/api/risks").json()[0]
    rid = risk["id"]
    before = client.get(f"/api/risks/{rid}").json()["residual_score"]
    # Map an implemented control; residual should not increase.
    control_id = client.get("/api/controls").json()[0]["id"]
    r = client.post(f"/api/risks/{rid}/controls", json={"control_id": control_id, "status": "implemented"})
    assert r.status_code == 201
    after = r.json()["residual_score"]
    assert after <= before


def test_metrics_endpoint(client):
    r = client.get("/api/metrics")
    assert r.status_code == 200
    m = r.json()
    assert m["system_count"] >= 3
    assert "residual_bands" in m


def test_dashboard_page_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Executive Dashboard" in r.text


def test_frameworks_endpoint(client):
    r = client.get("/api/frameworks")
    assert r.status_code == 200
    assert len(r.json()["owasp_llm_top_10"]) == 10
