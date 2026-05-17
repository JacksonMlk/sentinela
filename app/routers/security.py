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
async def security_dashboard(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)

    raw_d = (report.raw_data if report else None) or {}
    return templates.TemplateResponse(
        "security/dashboard.html",
        {"request": request, "client": client, "report": report, "raw_d": raw_d},
    )


@router.get("/{client_id}/quick-wins")
async def security_quick_wins(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    quick_wins = []
    tracking = {}
    if report and report.quick_wins:
        quick_wins = _with_idx(report.quick_wins, lambda qw: qw.get("area") == "security")
        tracking = (report.item_tracking or {}).get("quick_wins", {})

    return templates.TemplateResponse(
        "security/quick_wins.html",
        {"request": request, "client": client, "report": report, "quick_wins": quick_wins, "tracking": tracking},
    )


@router.get("/{client_id}/projects")
async def security_projects(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)
    projects = []
    tracking = {}
    if report and report.projects:
        projects = _with_idx(report.projects, lambda p: p.get("area") == "security")
        tracking = (report.item_tracking or {}).get("projects", {})

    return templates.TemplateResponse(
        "security/projects.html",
        {"request": request, "client": client, "report": report, "projects": projects, "tracking": tracking},
    )


@router.get("/{client_id}/findings")
async def security_findings(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = get_latest_report(client_id, db)

    findings = {}
    if report:
        findings = {
            "iam": report.iam_findings or {},
            "s3": report.s3_findings or {},
            "network": report.network_findings or {},
            "encryption": report.encryption_findings or {},
            "compliance": report.compliance_findings or {},
        }

    return templates.TemplateResponse(
        "security/findings.html",
        {"request": request, "client": client, "report": report, "findings": findings},
    )
