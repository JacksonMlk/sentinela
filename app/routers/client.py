"""
Client portal - token-based read-only access to FinOps and Security data.
Access via: /portal  (login form)
      or:  /portal/{token}  (direct link)
"""
from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Client, AnalysisReport
from app.templates_helper import get_templates

router = APIRouter()
templates = get_templates()


# ---------------------------------------------------------------------------
# LOGIN ROUTES
# ---------------------------------------------------------------------------

@router.get("/")
async def portal_login_page(request: Request, error: str = None):
    """Show the token login form."""
    return templates.TemplateResponse(
        "portal_login.html", {"request": request, "error": error}
    )


@router.post("/login")
async def portal_login(request: Request, token: str = Form(...), db: Session = Depends(get_db)):
    """Validate the submitted token and redirect to the portal."""
    client = db.query(Client).filter(
        Client.access_token == token.strip(),
        Client.is_active == True,
    ).first()
    if not client:
        return templates.TemplateResponse(
            "portal_login.html",
            {"request": request, "error": True},
            status_code=401,
        )
    return RedirectResponse(url=f"/portal/{token.strip()}", status_code=303)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def get_client_by_token(token: str, db: Session) -> Client:
    client = db.query(Client).filter(
        Client.access_token == token,
        Client.is_active == True,
    ).first()
    if not client:
        raise HTTPException(status_code=404, detail="Invalid or expired access token")
    return client


def get_latest_report(client_id: int, db: Session) -> AnalysisReport | None:
    return (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status.in_(["completed", "partial"]))
        .order_by(AnalysisReport.completed_at.desc())
        .first()
    )


def _visible(client: Client, section: str) -> bool:
    """Return True if the section is visible to the client (default: visible)."""
    settings = client.visibility_settings or {}
    return settings.get(section, True)


# ---------------------------------------------------------------------------
# PORTAL ROUTES
# ---------------------------------------------------------------------------

@router.get("/{token}")
async def portal_home(request: Request, token: str, db: Session = Depends(get_db)):
    client = get_client_by_token(token, db)
    report = get_latest_report(client.id, db)
    running = db.query(AnalysisReport).filter(
        AnalysisReport.client_id == client.id,
        AnalysisReport.status.in_(["pending", "running"])
    ).first()

    return templates.TemplateResponse(
        "client/home.html",
        {"request": request, "client": client, "report": report, "running": running, "token": token},
    )


@router.get("/{token}/finops")
async def portal_finops(request: Request, token: str, db: Session = Depends(get_db)):
    client = get_client_by_token(token, db)
    if not _visible(client, "finops_dashboard"):
        return RedirectResponse(url=f"/portal/{token}", status_code=303)
    report = get_latest_report(client.id, db)

    return templates.TemplateResponse(
        "client/finops.html",
        {"request": request, "client": client, "report": report, "token": token},
    )


@router.get("/{token}/security")
async def portal_security(request: Request, token: str, db: Session = Depends(get_db)):
    client = get_client_by_token(token, db)
    if not _visible(client, "security_dashboard"):
        return RedirectResponse(url=f"/portal/{token}", status_code=303)
    report = get_latest_report(client.id, db)

    return templates.TemplateResponse(
        "client/security.html",
        {"request": request, "client": client, "report": report, "token": token},
    )


@router.get("/{token}/quick-wins")
async def portal_quick_wins(request: Request, token: str, db: Session = Depends(get_db)):
    client = get_client_by_token(token, db)
    if not _visible(client, "finops_quick_wins") and not _visible(client, "security_quick_wins"):
        return RedirectResponse(url=f"/portal/{token}", status_code=303)
    report = get_latest_report(client.id, db)

    all_qw = report.quick_wins if report else []
    quick_wins = [qw for qw in all_qw if not qw.get("hidden")]

    return templates.TemplateResponse(
        "client/quick_wins.html",
        {"request": request, "client": client, "report": report, "quick_wins": quick_wins, "token": token},
    )


@router.get("/{token}/projects")
async def portal_projects(request: Request, token: str, db: Session = Depends(get_db)):
    client = get_client_by_token(token, db)
    if not _visible(client, "finops_projects") and not _visible(client, "security_projects"):
        return RedirectResponse(url=f"/portal/{token}", status_code=303)
    report = get_latest_report(client.id, db)

    all_proj = report.projects if report else []
    projects = [p for p in all_proj if not p.get("hidden")]

    return templates.TemplateResponse(
        "client/projects.html",
        {"request": request, "client": client, "report": report, "projects": projects, "token": token},
    )
