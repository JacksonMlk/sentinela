from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Client, AnalysisReport
from app.templates_helper import get_templates

router = APIRouter()
templates = get_templates()


def get_latest_report(client_id: int, db: Session) -> AnalysisReport | None:
    return (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status.in_(["completed", "partial"]))
        .order_by(AnalysisReport.completed_at.desc())
        .first()
    )


def _with_idx(items: list, filter_fn=None) -> list:
    """Attach _orig_idx (position in full list) to each item, optionally filtering."""
    result = []
    for i, item in enumerate(items or []):
        if filter_fn is None or filter_fn(item):
            result.append(dict(item, _orig_idx=i))
    return result


@router.get("/{client_id}")
async def finops_dashboard(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)

    raw_d = (report.raw_data if report else None) or {}
    fin   = ((report.rightsizing_recommendations if report else None) or {})
    chs   = fin.get("cost_health_score", 0) or 0
    mm    = fin.get("maturity_model") or {}
    mm_pct = int((mm.get("overall_score") or 0) * 10)
    finops_score = round(chs * 0.6 + mm_pct * 0.4)
    finops_label = (
        "Excelente" if finops_score >= 80 else
        "Bom"       if finops_score >= 60 else
        "Regular"   if finops_score >= 40 else
        "Fraco"     if finops_score >= 20 else
        "Crítico"
    )
    return templates.TemplateResponse(
        "finops/dashboard.html",
        {
            "request": request, "client": client, "report": report,
            "raw_d": raw_d,
            "finops_score_js": finops_score,
            "finops_label_js": finops_label,
            "finops_chs_js":   chs,
            "finops_mmp_js":   mm_pct,
        },
    )


@router.get("/{client_id}/quick-wins")
async def finops_quick_wins(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    quick_wins = []
    tracking = {}
    if report and report.quick_wins:
        quick_wins = _with_idx(report.quick_wins, lambda qw: qw.get("area") != "security")
        tracking = (report.item_tracking or {}).get("quick_wins", {})

    return templates.TemplateResponse(
        "finops/quick_wins.html",
        {"request": request, "client": client, "report": report, "quick_wins": quick_wins, "tracking": tracking},
    )


@router.get("/{client_id}/projects")
async def finops_projects(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    projects = []
    tracking = {}
    if report and report.projects:
        projects = _with_idx(report.projects, lambda p: p.get("area") != "security")
        tracking = (report.item_tracking or {}).get("projects", {})

    return templates.TemplateResponse(
        "finops/projects.html",
        {"request": request, "client": client, "report": report, "projects": projects, "tracking": tracking},
    )


def _normalize_unused(unused: dict) -> dict:
    """Garantir campos obrigatórios em cada lista de unused_resources."""
    if not unused:
        return {}
    for v in unused.get("unattached_volumes", []):
        v.setdefault("estimated_monthly_cost", 0)
        v.setdefault("created", "")
        v.setdefault("type", "gp2")
        v.setdefault("size_gb", 0)
        v.setdefault("region", "")
    for e in unused.get("unused_eips", []):
        e.setdefault("estimated_monthly_cost", 0)
        e.setdefault("ip", "")
        e.setdefault("allocation_id", "")
        e.setdefault("region", "")
    for s in unused.get("old_snapshots", []):
        s.setdefault("estimated_monthly_cost", 0)
        s.setdefault("created", "")
        s.setdefault("size_gb", 0)
        s.setdefault("description", "")
        s.setdefault("region", "")
    for lb in unused.get("idle_load_balancers", []):
        lb.setdefault("estimated_monthly_cost", 0)
        lb.setdefault("type", "N/A")
        lb.setdefault("name", lb.get("lb_arn", "").split("/")[-1] or "N/A")
        lb.setdefault("region", "")
    for i in unused.get("stopped_instances", []):
        i.setdefault("name", "")
        i.setdefault("instance_type", "")
        i.setdefault("region", "")
        i.setdefault("launch_time", "")
    return unused


@router.get("/{client_id}/unused-resources")
async def finops_unused(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    unused = _normalize_unused(dict(report.unused_resources) if report and report.unused_resources else {})

    return templates.TemplateResponse(
        "finops/unused_resources.html",
        {"request": request, "client": client, "report": report, "unused": unused},
    )


@router.get("/{client_id}/correlations")
async def finops_correlations(request: Request, client_id: int, db: Session = Depends(get_db)):
    from app.aws_analyzer import detect_correlations
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    correlations = detect_correlations(report) if report else []

    return templates.TemplateResponse(
        "finops/correlations.html",
        {"request": request, "client": client, "report": report, "correlations": correlations},
    )
