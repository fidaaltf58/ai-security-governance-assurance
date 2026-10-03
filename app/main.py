"""FastAPI application: REST API + server-rendered assurance dashboard.

The same data layer backs both a JSON API (``/api/*``) and a set of Jinja2
dashboard pages (``/``, ``/risks``, ...). One process, no front-end build step.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, frameworks, repo, seed
from .config import get_settings
from .models import AISystemIn, FindingIn, RiskControlIn, RiskIn

_BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_BASE / "templates"))

app = FastAPI(
    title="AI Security Governance & Assurance",
    description="Inventory, risk register, control mapping and evidence for AI systems, "
    "mapped to NIST AI RMF, OWASP LLM Top 10 and MITRE ATLAS.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=str(_BASE / "static")), name="static")


def get_conn():
    """Request-scoped connection dependency; initialises + seeds on first use."""
    conn = db.connect()
    try:
        db.init_db(conn)
        seed.seed_demo(conn)
        yield conn
    finally:
        conn.close()


# --------------------------------------------------------------------------
# JSON API
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "app": get_settings().app_name}


@app.get("/api/frameworks")
def get_frameworks():
    return {
        "nist_ai_rmf": frameworks.NIST_AI_RMF_FUNCTIONS,
        "nist_genai_profile": frameworks.NIST_GENAI_PROFILE,
        "owasp_llm_top_10": frameworks.OWASP_LLM_TOP_10,
        "mitre_atlas": frameworks.MITRE_ATLAS,
    }


@app.get("/api/systems")
def api_systems(conn=Depends(get_conn)):
    return [dict(r) for r in repo.list_systems(conn)]


@app.post("/api/systems", status_code=201)
def api_create_system(payload: AISystemIn, conn=Depends(get_conn)):
    try:
        new_id = db.execute(
            conn,
            """INSERT INTO ai_systems (name, description, owner, lifecycle_stage, model_type, data_sensitivity)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (payload.name, payload.description, payload.owner, payload.lifecycle_stage,
             payload.model_type, payload.data_sensitivity),
        )
    except Exception as exc:  # unique-name violation etc.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": new_id}


@app.get("/api/findings")
def api_findings(conn=Depends(get_conn)):
    return [dict(r) for r in repo.list_findings(conn)]


@app.post("/api/findings", status_code=201)
def api_create_finding(payload: FindingIn, conn=Depends(get_conn)):
    if repo.get_system(conn, payload.system_id) is None:
        raise HTTPException(status_code=404, detail="system not found")
    new_id = db.execute(
        conn,
        """INSERT INTO findings (system_id, title, description, severity, attack_vector, owasp_llm, mitre_atlas)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (payload.system_id, payload.title, payload.description, payload.severity,
         payload.attack_vector, payload.owasp_llm, payload.mitre_atlas),
    )
    return {"id": new_id}


@app.get("/api/risks")
def api_risks(conn=Depends(get_conn)):
    return repo.list_risks(conn)


@app.get("/api/risks/{risk_id}")
def api_risk(risk_id: int, conn=Depends(get_conn)):
    risk = repo.get_risk(conn, risk_id)
    if risk is None:
        raise HTTPException(status_code=404, detail="risk not found")
    risk["controls"] = [dict(c) for c in repo.controls_for_risk(conn, risk_id)]
    return risk


@app.post("/api/risks", status_code=201)
def api_create_risk(payload: RiskIn, conn=Depends(get_conn)):
    if repo.get_system(conn, payload.system_id) is None:
        raise HTTPException(status_code=404, detail="system not found")
    new_id = db.execute(
        conn,
        """INSERT INTO risks
               (system_id, finding_id, title, description, likelihood, impact,
                rmf_function, owasp_llm, mitre_atlas)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (payload.system_id, payload.finding_id, payload.title, payload.description,
         payload.likelihood, payload.impact, payload.rmf_function, payload.owasp_llm, payload.mitre_atlas),
    )
    return repo.get_risk(conn, new_id)


@app.post("/api/risks/{risk_id}/controls", status_code=201)
def api_map_control(risk_id: int, payload: RiskControlIn, conn=Depends(get_conn)):
    if repo.get_risk(conn, risk_id) is None:
        raise HTTPException(status_code=404, detail="risk not found")
    control = db.query_one(conn, "SELECT id FROM controls WHERE id = ?", (payload.control_id,))
    if control is None:
        raise HTTPException(status_code=404, detail="control not found")
    db.execute(
        conn,
        "INSERT OR REPLACE INTO risk_controls (risk_id, control_id, status) VALUES (?, ?, ?)",
        (risk_id, payload.control_id, payload.status),
    )
    return repo.get_risk(conn, risk_id)


@app.get("/api/controls")
def api_controls(conn=Depends(get_conn)):
    return [dict(r) for r in repo.list_controls(conn)]


@app.get("/api/metrics")
def api_metrics(conn=Depends(get_conn)):
    return repo.dashboard_metrics(conn)


# --------------------------------------------------------------------------
# Dashboard (HTML)
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, conn=Depends(get_conn)):
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"metrics": repo.dashboard_metrics(conn), "owasp": frameworks.OWASP_LLM_TOP_10},
    )


@app.get("/systems", response_class=HTMLResponse)
def page_systems(request: Request, conn=Depends(get_conn)):
    return templates.TemplateResponse(request, "systems.html", {"systems": repo.list_systems(conn)})


@app.get("/findings", response_class=HTMLResponse)
def page_findings(request: Request, conn=Depends(get_conn)):
    rows = repo.list_findings(conn)
    retests = {f["id"]: repo.latest_retest_result(conn, f["id"]) for f in rows}
    return templates.TemplateResponse(
        request, "findings.html",
        {"findings": rows, "retests": retests, "owasp": frameworks.OWASP_LLM_TOP_10, "atlas": frameworks.MITRE_ATLAS},
    )


@app.get("/risks", response_class=HTMLResponse)
def page_risks(request: Request, conn=Depends(get_conn)):
    return templates.TemplateResponse(request, "risks.html", {"risks": repo.list_risks(conn)})


@app.get("/controls", response_class=HTMLResponse)
def page_controls(request: Request, conn=Depends(get_conn)):
    return templates.TemplateResponse(
        request, "controls.html",
        {"controls": repo.list_controls(conn), "rmf": frameworks.NIST_AI_RMF_FUNCTIONS,
         "owasp": frameworks.OWASP_LLM_TOP_10},
    )
