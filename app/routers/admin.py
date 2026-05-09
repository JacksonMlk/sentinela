import threading
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Client, AnalysisReport
from app import aws_analyzer, claude_analyzer
from app.aws_analyzer import AnalysisCancelledError

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# AUTHENTICATION ROUTES
# ---------------------------------------------------------------------------

@router.get("/login")
async def login_page(request: Request, error: str = ""):
    if request.session.get("admin_authenticated"):
        return RedirectResponse(url="/admin", status_code=302)
    return templates.TemplateResponse("admin/login.html", {"request": request, "error": error})


@router.post("/login")
async def do_login(request: Request, password: str = Form(...)):
    from app.config import get_settings
    cfg = get_settings()
    if password == cfg.admin_secret_token:
        request.session["admin_authenticated"] = True
        return RedirectResponse(url="/admin", status_code=303)
    return RedirectResponse(url="/admin/login?error=invalid", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/admin/login", status_code=302)

# ---------------------------------------------------------------------------
# IN-MEMORY STATE  (lives as long as the server process)
# ---------------------------------------------------------------------------

# report_id -> {"thread": Thread, "event": threading.Event}
_active_analyses: dict = {}

# report_id -> list of {"time": str, "status": str, "message": str}
_progress_logs: dict = {}


def _log(report_id: int, status: str, message: str) -> None:
    """Append a progress entry and echo it to stdout."""
    entry = {
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "status": status,   # running | done | error | warn | info
        "message": message,
    }
    _progress_logs.setdefault(report_id, []).append(entry)
    icons = {"running": "⟳", "done": "✓", "error": "✗", "warn": "⚠", "info": "·"}
    icon = icons.get(status, "·")
    print(f"  [{entry['time']}] {icon} Report#{report_id}: {message}", flush=True)


# ---------------------------------------------------------------------------
# BACKGROUND ANALYSIS JOB
# ---------------------------------------------------------------------------

def run_analysis_job(report_id: int, client_id: int, role_arns: list, regions: str,
                     db_url: str, cancel_event: threading.Event,
                     account_mode: str = "organization"):
    """Run in a daemon thread: collect AWS data, call Gemini, save results."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {})
    LocalSession = sessionmaker(bind=engine)
    db = LocalSession()

    try:
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if not report:
            return
        report.status = "running"
        db.commit()

        n_accounts = len(role_arns)
        _log(report_id, "info",
             f"Iniciando análise | modo: {account_mode} | contas: {n_accounts} | regiões: {regions}")

        # ── Step 1: Collect AWS data ──────────────────────────────────────────
        _log(report_id, "running", "Conectando à(s) conta(s) AWS via STS AssumeRole...")
        if account_mode == "standalone" and n_accounts > 1:
            raw_data = aws_analyzer.run_multi_account_analysis(
                role_arns, regions, cancel_event=cancel_event  # role_arns = list of dicts here
            )
        else:
            primary = role_arns[0]
            primary_arn = primary["arn"] if isinstance(primary, dict) else primary
            raw_data = aws_analyzer.run_full_analysis(
                primary_arn, regions, cancel_event=cancel_event
            )

        account_id = raw_data.get("account_id", "?")
        monthly = raw_data.get("cost_and_usage", {}).get("monthly_totals", [])
        last_cost = monthly[-1].get("cost", 0) if monthly else 0
        vol_count = len(raw_data.get("unused_resources", {}).get("unattached_volumes", []))
        eip_count = len(raw_data.get("unused_resources", {}).get("unused_eips", []))

        # Log por conta no modo standalone para expor erros individuais
        for acc in raw_data.get("accounts_data", []):
            acc_id = acc.get("account_id", "?")
            acc_fatal = acc.get("error")
            if acc_fatal:
                _log(report_id, "error", f"  Conta {acc_id}: FALHA — {str(acc_fatal)[:160]}")
                continue
            cau = acc.get("cost_and_usage", {})
            cau_err = cau.get("_collection_error") or cau.get("error")
            if cau_err:
                _log(report_id, "warn", f"  Conta {acc_id}: erro CE — {str(cau_err)[:120]}")
            else:
                acc_monthly = cau.get("monthly_totals", [])
                acc_cost = acc_monthly[-1].get("cost", 0) if acc_monthly else 0
                _log(report_id, "info", f"  Conta {acc_id}: ${acc_cost:.0f}/mês")

        _log(report_id, "done",
             f"Dados AWS coletados | conta: {account_id} | custo: ${last_cost:.0f}/mês | "
             f"{vol_count} volumes soltos, {eip_count} EIPs livres")

        # Persist all raw/structured fields immediately so a later AI failure
        # still leaves the report with useful data.
        report.raw_data = raw_data
        report.cost_by_service = _extract_cost_by_service(raw_data)
        report.cost_trend = raw_data.get("cost_and_usage", {}).get("monthly_totals", [])
        report.unused_resources = raw_data.get("unused_resources", {})
        report.ri_recommendations = raw_data.get("ri_recommendations", {})
        report.iam_findings = raw_data.get("iam_findings", {})
        report.s3_findings = {
            "costs": raw_data.get("s3_costs", {}),
            "security": raw_data.get("s3_security", {}),
        }
        report.network_findings = raw_data.get("network_security", {})
        report.encryption_findings = raw_data.get("encryption_findings", {})
        report.compliance_findings = raw_data.get("compliance_findings", {})
        report.monthly_cost = last_cost

        client = db.query(Client).filter(Client.id == client_id).first()
        if client:
            client.aws_account_id = account_id
        db.commit()

        # ── Step 2: FinOps AI ─────────────────────────────────────────────────
        if cancel_event.is_set():
            raise AnalysisCancelledError("Análise cancelada pelo usuário.")

        _log(report_id, "running", "Analisando FinOps com Gemini AI (pode levar 1–2 min)...")
        ai_errors = []
        finops_result: dict = {}
        security_result: dict = {}

        try:
            finops_result = claude_analyzer.analyze_finops(raw_data)
            savings = finops_result.get("total_potential_savings", 0)
            score = finops_result.get("cost_health_score", "?")
            _log(report_id, "done",
                 f"FinOps concluído | score: {score}/100 | economia potencial: ${savings:.0f}/mês")

            report.finops_summary = finops_result.get("executive_summary", "")
            report.potential_savings = savings
            if report.monthly_cost and report.monthly_cost > 0:
                report.savings_percentage = round((savings / report.monthly_cost) * 100, 1)
            report.rightsizing_recommendations = finops_result
            _account_id = raw_data.get("account_id") or ""
            report.quick_wins = [
                {**qw, "account_id": qw.get("account_id") or _account_id}
                for qw in finops_result.get("quick_wins", [])
            ]
            report.projects = finops_result.get("projects", [])
            report.service_suggestions = finops_result.get("service_suggestions", [])
            db.commit()
        except AnalysisCancelledError:
            raise
        except Exception as exc:
            _log(report_id, "error", f"Falha na análise FinOps: {exc}")
            ai_errors.append(f"FinOps AI: {exc}")

        # ── Step 3: Security AI ───────────────────────────────────────────────
        if cancel_event.is_set():
            raise AnalysisCancelledError("Análise cancelada pelo usuário.")

        _log(report_id, "running", "Analisando Segurança com Gemini AI (pode levar 1–2 min)...")
        try:
            security_result = claude_analyzer.analyze_security(raw_data)
            critical = security_result.get("critical_findings_count", 0)
            high = security_result.get("high_findings_count", 0)
            sec_score = security_result.get("security_score", "?")
            _log(report_id, "done",
                 f"Segurança concluída | score: {sec_score}/100 | {critical} críticos, {high} altos")

            report.security_summary = security_result.get("executive_summary", "")
            report.security_score = security_result.get("security_score")
            report.security_label = security_result.get("security_label")
            report.critical_findings = critical
            report.high_findings = high
            report.medium_findings = security_result.get("medium_findings_count", 0)
            report.low_findings = security_result.get("low_findings_count", 0)
            _account_id = raw_data.get("account_id") or ""
            sec_wins = [
                {**qw, "area": "security", "account_id": qw.get("account_id") or _account_id}
                for qw in security_result.get("quick_wins", [])
            ]
            sec_projs = [{**p, "area": "security"} for p in security_result.get("projects", [])]
            report.quick_wins = (report.quick_wins or []) + sec_wins
            report.projects = (report.projects or []) + sec_projs
            db.commit()
        except AnalysisCancelledError:
            raise
        except Exception as exc:
            _log(report_id, "error", f"Falha na análise de Segurança: {exc}")
            ai_errors.append(f"Security AI: {exc}")

        # ── Step 4: Combined summary ──────────────────────────────────────────
        if finops_result and security_result and not cancel_event.is_set():
            _log(report_id, "running", "Gerando análise cruzada FinOps + Segurança...")
            try:
                combined = claude_analyzer.generate_combined_analysis(finops_result, security_result, raw_data)
                report.combined_analysis = combined
                db.commit()
                _log(report_id, "done", "Análise cruzada concluída.")
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                _log(report_id, "warn", f"Análise cruzada falhou (não crítico): {exc}")
                ai_errors.append(f"Combined AI: {exc}")

        # ── Finalize ─────────────────────────────────────────────────────────
        if ai_errors:
            report.status = "partial"
            report.error_message = (
                "Dados AWS coletados com sucesso. Análise IA parcial — "
                + "; ".join(ai_errors)
            )
            _log(report_id, "warn",
                 f"Análise finalizada como PARCIAL ({len(ai_errors)} etapa(s) de AI falharam).")
        else:
            report.status = "completed"
            _log(report_id, "done", "Análise concluída com sucesso!")

        report.completed_at = datetime.utcnow()
        db.commit()

    except AnalysisCancelledError:
        _log(report_id, "warn", "Análise pausada.")
        # The cancel_report endpoint already set the correct status in DB.
        # Only update here if the thread was somehow cancelled without going through
        # that endpoint (e.g., server shutdown with daemon=True).
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report and report.status == "running":
            report.status = "partial" if report.raw_data else "cancelled"
            report.error_message = "Pausado pelo usuário."
            report.completed_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        _log(report_id, "error", f"Erro fatal na análise: {e}")
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report:
            report.status = "failed"
            report.error_message = str(e)
            db.commit()

    finally:
        _active_analyses.pop(report_id, None)
        db.close()


def _extract_cost_by_service(raw_data: dict) -> list:
    """Flatten cost-by-service from the last month."""
    results = raw_data.get("cost_and_usage", {}).get("by_service", [])
    if not results:
        return []
    last_month = results[-1] if results else {}
    groups = last_month.get("Groups", [])
    services = []
    for g in groups:
        services.append({
            "service": g["Keys"][0],
            "cost": float(g["Metrics"]["BlendedCost"]["Amount"]),
        })
    return sorted(services, key=lambda x: x["cost"], reverse=True)[:15]


def _start_analysis(report_id: int, client_id: int, role_arns: list,
                    regions: str, db_url: str, account_mode: str = "organization") -> None:
    """Create a daemon thread for the full analysis job and register it."""
    cancel_event = threading.Event()
    t = threading.Thread(
        target=run_analysis_job,
        args=(report_id, client_id, role_arns, regions, db_url, cancel_event, account_mode),
        daemon=True,
        name=f"analysis-{report_id}",
    )
    _active_analyses[report_id] = {"thread": t, "event": cancel_event}
    t.start()


# ---------------------------------------------------------------------------
# AI-ONLY JOB  (used by "Continue" — skips AWS collection, reuses raw_data)
# ---------------------------------------------------------------------------

def run_ai_only_job(report_id: int, db_url: str, cancel_event: threading.Event):
    """Re-run only the Gemini AI steps using the existing report's raw_data."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {})
    LocalSession = sessionmaker(bind=engine)
    db = LocalSession()

    try:
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if not report or not report.raw_data:
            return

        raw_data = report.raw_data
        report.status = "running"
        report.error_message = None
        db.commit()

        _log(report_id, "info", "Retomando análise — dados AWS já disponíveis, executando somente AI...")

        ai_errors = []
        finops_result: dict = {}
        security_result: dict = {}

        # ── FinOps AI ─────────────────────────────────────────────────────────
        if cancel_event.is_set():
            raise AnalysisCancelledError("Pausado pelo usuário.")

        finops_done = bool(report.rightsizing_recommendations and report.finops_summary)
        if finops_done:
            finops_result = report.rightsizing_recommendations
            _log(report_id, "info", "✓ FinOps AI já concluído — reutilizando resultado salvo.")
        else:
            _log(report_id, "running", "Analisando FinOps com Claude AI (pode levar 1–2 min)...")
            try:
                finops_result = claude_analyzer.analyze_finops(raw_data)
                savings = finops_result.get("total_potential_savings", 0)
                score = finops_result.get("cost_health_score", "?")
                _log(report_id, "done", f"FinOps concluído | score: {score}/100 | economia: ${savings:.0f}/mês")
                report.finops_summary = finops_result.get("executive_summary", "")
                report.potential_savings = savings
                if report.monthly_cost and report.monthly_cost > 0:
                    report.savings_percentage = round((savings / report.monthly_cost) * 100, 1)
                report.rightsizing_recommendations = finops_result
                _account_id = raw_data.get("account_id") or ""
                report.quick_wins = [
                    {**qw, "account_id": qw.get("account_id") or _account_id}
                    for qw in finops_result.get("quick_wins", [])
                ]
                report.projects = finops_result.get("projects", [])
                report.service_suggestions = finops_result.get("service_suggestions", [])
                db.commit()
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                _log(report_id, "error", f"Falha na análise FinOps: {exc}")
                ai_errors.append(f"FinOps AI: {exc}")

        # ── Security AI ───────────────────────────────────────────────────────
        if cancel_event.is_set():
            raise AnalysisCancelledError("Pausado pelo usuário.")

        security_done = bool(report.security_summary)
        if security_done:
            # Reconstruct a minimal security_result from saved report fields
            existing_wins = [qw for qw in (report.quick_wins or []) if qw.get("area") == "security"]
            existing_projs = [p for p in (report.projects or []) if p.get("area") == "security"]
            security_result = {
                "security_score": report.security_score or 0,
                "security_label": report.security_label or "",
                "critical_findings_count": report.critical_findings or 0,
                "high_findings_count": report.high_findings or 0,
                "medium_findings_count": report.medium_findings or 0,
                "low_findings_count": report.low_findings or 0,
                "executive_summary": report.security_summary or "",
                "quick_wins": existing_wins,
                "projects": existing_projs,
                "findings": [],
            }
            _log(report_id, "info", "✓ Segurança AI já concluída — reutilizando resultado salvo.")
        else:
            _log(report_id, "running", "Analisando Segurança com Claude AI (pode levar 1–2 min)...")
            try:
                security_result = claude_analyzer.analyze_security(raw_data)
                critical = security_result.get("critical_findings_count", 0)
                high = security_result.get("high_findings_count", 0)
                sec_score = security_result.get("security_score", "?")
                _log(report_id, "done",
                     f"Segurança concluída | score: {sec_score}/100 | {critical} críticos, {high} altos")
                report.security_summary = security_result.get("executive_summary", "")
                report.security_score = security_result.get("security_score")
                report.security_label = security_result.get("security_label")
                report.critical_findings = critical
                report.high_findings = high
                report.medium_findings = security_result.get("medium_findings_count", 0)
                report.low_findings = security_result.get("low_findings_count", 0)
                _account_id = raw_data.get("account_id") or ""
                sec_wins = [
                    {**qw, "area": "security", "account_id": qw.get("account_id") or _account_id}
                    for qw in security_result.get("quick_wins", [])
                ]
                sec_projs = [{**p, "area": "security"} for p in security_result.get("projects", [])]
                report.quick_wins = (report.quick_wins or []) + sec_wins
                report.projects = (report.projects or []) + sec_projs
                db.commit()
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                _log(report_id, "error", f"Falha na análise de Segurança: {exc}")
                ai_errors.append(f"Security AI: {exc}")

        # ── Combined ──────────────────────────────────────────────────────────
        if cancel_event.is_set():
            raise AnalysisCancelledError("Pausado pelo usuário.")

        combined_done = bool(report.combined_analysis)
        if combined_done:
            _log(report_id, "info", "✓ Análise cruzada já concluída — reutilizando resultado salvo.")
        elif finops_result and security_result:
            _log(report_id, "running", "Gerando análise cruzada FinOps + Segurança...")
            try:
                combined = claude_analyzer.generate_combined_analysis(finops_result, security_result, raw_data)
                report.combined_analysis = combined
                db.commit()
                _log(report_id, "done", "Análise cruzada concluída.")
            except AnalysisCancelledError:
                raise
            except Exception as exc:
                _log(report_id, "warn", f"Análise cruzada falhou (não crítico): {exc}")
                ai_errors.append(f"Combined AI: {exc}")

        # ── Finalize ──────────────────────────────────────────────────────────
        if ai_errors:
            report.status = "partial"
            report.error_message = (
                "Dados AWS coletados com sucesso. Análise IA parcial — " + "; ".join(ai_errors)
            )
            _log(report_id, "warn", f"Análise finalizada como PARCIAL.")
        else:
            report.status = "completed"
            _log(report_id, "done", "Análise concluída com sucesso!")

        report.completed_at = datetime.utcnow()
        db.commit()

    except AnalysisCancelledError:
        _log(report_id, "warn", "Pausado durante análise AI. Dados AWS preservados.")
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report and report.status == "running":
            report.status = "partial"
            report.error_message = "Pausado pelo usuário durante análise IA."
            report.completed_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        _log(report_id, "error", f"Erro fatal: {e}")
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report:
            report.status = "failed"
            report.error_message = str(e)
            db.commit()

    finally:
        _active_analyses.pop(report_id, None)
        db.close()


def _start_ai_only(report_id: int, db_url: str) -> None:
    """Create a daemon thread for the AI-only job and register it."""
    cancel_event = threading.Event()
    t = threading.Thread(
        target=run_ai_only_job,
        args=(report_id, db_url, cancel_event),
        daemon=True,
        name=f"analysis-ai-{report_id}",
    )
    _active_analyses[report_id] = {"thread": t, "event": cancel_event}
    t.start()


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@router.get("/")
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    from datetime import datetime as dt, timedelta as td

    clients = db.query(Client).order_by(Client.created_at.desc()).all()
    client_map = {c.id: c for c in clients}

    # Latest completed/partial report per client
    latest_per_client: dict = {}
    for r in (
        db.query(AnalysisReport)
        .filter(AnalysisReport.status.in_(["completed", "partial"]))
        .order_by(AnalysisReport.started_at.desc())
        .all()
    ):
        if r.client_id not in latest_per_client:
            latest_per_client[r.client_id] = r

    # Build per-client status cards for the portfolio view
    client_status: list = []
    alerts: list = []

    for client in clients:
        r = latest_per_client.get(client.id)

        # Extract trend info from rightsizing_recommendations (full finops result JSON)
        trend_direction = None
        trend_status = None
        trend_pct = None
        run_rate = None
        cost_score = None
        cost_label = None
        if r and r.rightsizing_recommendations and isinstance(r.rightsizing_recommendations, dict):
            finops = r.rightsizing_recommendations
            cost_score = finops.get("cost_health_score")
            cost_label = finops.get("cost_health_label")
            ct = finops.get("cost_trend", {}) or {}
            trend_direction = ct.get("trend_direction") or ct.get("status")
            trend_status = ct.get("status")
            trend_pct = ct.get("variacao_mom_pct") or ct.get("avg_mom_change_pct")
            run_rate = ct.get("current_month_run_rate_usd")

        days_since = None
        if r and r.started_at:
            days_since = (dt.utcnow() - r.started_at).days

        entry = {
            "client": client,
            "report": r,
            "cost_score": cost_score,
            "cost_label": cost_label,
            "security_score": r.security_score if r else None,
            "security_label": r.security_label if r else None,
            "monthly_cost": r.monthly_cost if r else None,
            "run_rate": run_rate,
            "potential_savings": r.potential_savings if r else None,
            "critical_findings": r.critical_findings if r else None,
            "trend_direction": trend_direction,
            "trend_status": trend_status,
            "trend_pct": trend_pct,
            "days_since": days_since,
            "has_analysis": r is not None,
        }
        client_status.append(entry)

        # Build alerts for clients needing attention
        if r:
            if (r.critical_findings or 0) > 0:
                alerts.append({
                    "client": client,
                    "type": "security",
                    "message": f"{r.critical_findings} finding(s) crítico(s) de segurança",
                    "level": "critical",
                })
            if trend_status == "alerta":
                alerts.append({
                    "client": client,
                    "type": "cost",
                    "message": f"Custo crescendo {trend_pct:.1f}% ao mês — tendência de alerta",
                    "level": "warning",
                })
            if r.status == "failed":
                alerts.append({
                    "client": client,
                    "type": "analysis",
                    "message": "Última análise falhou — reexecutar necessário",
                    "level": "error",
                })
            if days_since is not None and days_since > 30:
                alerts.append({
                    "client": client,
                    "type": "stale",
                    "message": f"Última análise há {days_since} dias — dados desatualizados",
                    "level": "info",
                })

    # Running analyses
    running_reports = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.status == "running")
        .all()
    )
    running_with_client = [
        {"report": r, "client": client_map.get(r.client_id)}
        for r in running_reports
    ]

    # Recent activity (last 10 completed)
    recent_reports = (
        db.query(AnalysisReport)
        .order_by(AnalysisReport.started_at.desc())
        .limit(8)
        .all()
    )

    stats = {
        "total_clients":       len(clients),
        "active_clients":      sum(1 for c in clients if c.is_active),
        "clients_with_data":   len(latest_per_client),
        "running_reports":     len(running_reports),
        "total_reports":       db.query(AnalysisReport).count(),
        "clients_with_critical": sum(1 for r in latest_per_client.values() if (r.critical_findings or 0) > 0),
        "total_savings":       sum(r.potential_savings or 0 for r in latest_per_client.values()),
        "alerts_count":        len(alerts),
    }

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "clients": clients,
            "client_status": client_status,
            "running_with_client": running_with_client,
            "recent_reports": recent_reports,
            "client_map": client_map,
            "alerts": alerts,
            "stats": stats,
        },
    )


def _zip_arns_regions(arns: list, regions: list) -> list:
    """Combina listas paralelas de ARNs e regiões em lista de dicts."""
    result = []
    for i, arn in enumerate(arns):
        arn = arn.strip()
        if not arn:
            continue
        reg = regions[i].strip() if i < len(regions) else "us-east-1"
        result.append({"arn": arn, "regions": reg or "us-east-1"})
    return result


@router.get("/clients/new")
async def new_client_form(request: Request):
    return templates.TemplateResponse("admin/client_form.html", {"request": request, "client": None})


@router.post("/clients/new")
async def create_client(
    request: Request,
    name: str = Form(...),
    company: str = Form(...),
    email: str = Form(...),
    account_mode: str = Form(default="organization"),
    aws_role_arn: str = Form(default=""),
    aws_role_arns: list = Form(default=[]),
    aws_role_regions: list = Form(default=[]),
    aws_regions: str = Form(default="us-east-1"),
    db: Session = Depends(get_db),
):
    if account_mode == "standalone":
        entries = _zip_arns_regions(aws_role_arns, aws_role_regions)
        if not entries and aws_role_arn.strip():
            entries = [{"arn": aws_role_arn.strip(), "regions": "us-east-1"}]
        primary_arn = entries[0]["arn"] if entries else ""
        role_arns_json = entries
    else:
        primary_arn = aws_role_arn.strip()
        role_arns_json = None

    client = Client(
        name=name,
        company=company,
        email=email,
        account_mode=account_mode,
        aws_role_arn=primary_arn,
        aws_role_arns=role_arns_json,
        aws_regions=aws_regions.strip(),
        access_token=Client.generate_token(),
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return RedirectResponse(url=f"/admin/clients/{client.id}", status_code=303)


@router.get("/clients/{client_id}")
async def client_detail(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    reports = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id)
        .order_by(AnalysisReport.started_at.desc())
        .all()
    )

    latest_report = reports[0] if reports else None

    # Build comparison data: for each report, attach delta vs previous report with data
    reports_with_comparison = []
    data_reports = [r for r in reversed(reports) if r.monthly_cost is not None]
    for r in reports:
        comp = {"report": r, "prev": None, "cost_delta": None, "savings_delta": None, "score_delta": None, "critical_delta": None}
        idx = next((i for i, dr in enumerate(data_reports) if dr.id == r.id), None)
        if idx is not None and idx > 0:
            prev = data_reports[idx - 1]
            comp["prev"] = prev
            if r.monthly_cost is not None and prev.monthly_cost is not None:
                comp["cost_delta"] = r.monthly_cost - prev.monthly_cost
            if r.potential_savings is not None and prev.potential_savings is not None:
                comp["savings_delta"] = r.potential_savings - prev.potential_savings
            prev_score = max(0, 100 - (prev.critical_findings or 0) * 20 - (prev.high_findings or 0) * 10 - (prev.medium_findings or 0) * 5)
            curr_score = max(0, 100 - (r.critical_findings or 0) * 20 - (r.high_findings or 0) * 10 - (r.medium_findings or 0) * 5)
            if r.critical_findings is not None and prev.critical_findings is not None:
                comp["score_delta"] = curr_score - prev_score
                comp["critical_delta"] = (r.critical_findings or 0) - (prev.critical_findings or 0)
        reports_with_comparison.append(comp)

    return templates.TemplateResponse(
        "admin/client_detail.html",
        {
            "request": request,
            "client": client,
            "reports": reports,
            "latest_report": latest_report,
            "reports_with_comparison": reports_with_comparison,
        },
    )


@router.get("/clients/{client_id}/edit")
async def edit_client_form(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return templates.TemplateResponse("admin/client_form.html", {"request": request, "client": client})


@router.post("/clients/{client_id}/edit")
async def update_client(
    client_id: int,
    name: str = Form(...),
    company: str = Form(...),
    email: str = Form(...),
    account_mode: str = Form(default="organization"),
    aws_role_arn: str = Form(default=""),
    aws_role_arns: list = Form(default=[]),
    aws_role_regions: list = Form(default=[]),
    aws_regions: str = Form(default="us-east-1"),
    db: Session = Depends(get_db),
):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    client.name = name
    client.company = company
    client.email = email
    client.account_mode = account_mode
    client.aws_regions = aws_regions.strip()

    if account_mode == "standalone":
        entries = _zip_arns_regions(aws_role_arns, aws_role_regions)
        if not entries and aws_role_arn.strip():
            entries = [{"arn": aws_role_arn.strip(), "regions": "us-east-1"}]
        client.aws_role_arns = entries
        client.aws_role_arn = entries[0]["arn"] if entries else ""
    else:
        client.aws_role_arn = aws_role_arn.strip()
        client.aws_role_arns = None

    db.commit()
    return RedirectResponse(url=f"/admin/clients/{client_id}", status_code=303)


@router.post("/clients/{client_id}/toggle")
async def toggle_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    client.is_active = not client.is_active
    db.commit()
    return RedirectResponse(url=f"/admin/clients/{client_id}", status_code=303)


@router.post("/clients/{client_id}/regenerate-token")
async def regenerate_token(client_id: int, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    client.access_token = Client.generate_token()
    db.commit()
    return RedirectResponse(url=f"/admin/clients/{client_id}", status_code=303)


@router.post("/clients/{client_id}/analyze")
async def trigger_analysis(
    client_id: int,
    db: Session = Depends(get_db),
):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    running = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status == "running")
        .first()
    )
    if running:
        return RedirectResponse(url=f"/admin/clients/{client_id}?error=already_running", status_code=303)

    report = AnalysisReport(client_id=client_id, report_type="full", status="pending")
    db.add(report)
    db.commit()
    db.refresh(report)

    from app.config import get_settings
    settings = get_settings()

    _start_analysis(report.id, client_id, client.analysis_accounts,
                    client.aws_regions, settings.database_url, client.account_mode)

    return RedirectResponse(url=f"/admin/clients/{client_id}?analyzing={report.id}", status_code=303)


@router.post("/clients/{client_id}/retry")
async def retry_analysis(
    client_id: int,
    db: Session = Depends(get_db),
):
    """Create a new analysis run (retry after failure/partial/cancelled)."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    running = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status == "running")
        .first()
    )
    if running:
        return RedirectResponse(url=f"/admin/clients/{client_id}?error=already_running", status_code=303)

    report = AnalysisReport(client_id=client_id, report_type="full", status="pending")
    db.add(report)
    db.commit()
    db.refresh(report)

    from app.config import get_settings
    settings = get_settings()

    _start_analysis(report.id, client_id, client.analysis_accounts,
                    client.aws_regions, settings.database_url, client.account_mode)

    return RedirectResponse(url=f"/admin/clients/{client_id}?analyzing={report.id}", status_code=303)


@router.get("/reports/{report_id}/status")
async def report_status(report_id: int, db: Session = Depends(get_db)):
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse({
        "status": report.status,
        "error": report.error_message,
        "completed_at": str(report.completed_at) if report.completed_at else None,
        "progress_log": _progress_logs.get(report_id, []),
    })


@router.post("/reports/{report_id}/cancel")
async def cancel_report(report_id: int, db: Session = Depends(get_db)):
    """
    Pause / cancel an analysis immediately:
    1. Sets the threading.Event so the worker stops at the next checkpoint.
    2. Updates the DB status right away so the UI reflects it without waiting.
       - 'partial'   if AWS data was already collected (user can view it)
       - 'cancelled' if nothing was collected yet (nothing to show)
    """
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status not in ("running", "pending"):
        return JSONResponse({"ok": False, "reason": "not running"})

    # Signal the worker thread to stop at the next checkpoint
    analysis = _active_analyses.get(report_id)
    if analysis:
        analysis["event"].set()

    # Decide final status based on what's already been saved
    if report.raw_data:
        report.status = "partial"
        report.error_message = "Pausado pelo usuário. Dados AWS coletados com sucesso — análise IA não executada."
    else:
        report.status = "cancelled"
        report.error_message = "Pausado pelo usuário antes da coleta de dados AWS."

    report.completed_at = datetime.utcnow()
    db.commit()

    _log(report_id, "warn", f"Pausado pelo usuário — status final: {report.status}.")
    return JSONResponse({"ok": True, "new_status": report.status})


@router.post("/clients/{client_id}/continue/{report_id}")
async def continue_analysis(
    client_id: int,
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Continue AI steps on an existing partial/paused report that already has raw_data.
    If no raw_data exists, falls back to a full retry.
    """
    report = db.query(AnalysisReport).filter(
        AnalysisReport.id == report_id,
        AnalysisReport.client_id == client_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # No raw_data means we need a full re-analysis
    if not report.raw_data:
        return RedirectResponse(url=f"/admin/clients/{client_id}/retry", status_code=303)

    running = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status == "running")
        .first()
    )
    if running:
        return RedirectResponse(url=f"/admin/clients/{client_id}?error=already_running", status_code=303)

    from app.config import get_settings
    settings = get_settings()

    _start_ai_only(report_id, settings.database_url)

    return RedirectResponse(url=f"/admin/clients/{client_id}?analyzing={report_id}", status_code=303)


@router.get("/reports/{report_id}/download-assessment")
async def download_assessment(report_id: int, db: Session = Depends(get_db)):
    """Generate and download a professional AWS Assessment DOCX for the given report."""
    from app.report_generator import generate_assessment_docx

    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status not in ("completed", "partial"):
        raise HTTPException(status_code=400, detail="Report must be completed or partial to download")

    client = db.query(Client).filter(Client.id == report.client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    buf = generate_assessment_docx(report, client)
    safe_name = client.company.replace(" ", "_").replace("/", "-")
    date_str  = datetime.utcnow().strftime("%Y%m%d")
    filename  = f"Assessment_{safe_name}_{date_str}.docx"

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# ITEM TRACKING, EDITING & DELETION
# ---------------------------------------------------------------------------

@router.post("/reports/{report_id}/track")
async def update_item_tracking(report_id: int, request: Request, db: Session = Depends(get_db)):
    """Update completion status of a quick win or project item."""
    data = await request.json()
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    item_type = data.get("type")
    if item_type not in ("quick_wins", "projects"):
        raise HTTPException(status_code=400, detail="Invalid type")
    index = str(data.get("index", ""))
    status = data.get("status", "pending")

    tracking = dict(report.item_tracking or {})
    tracking[item_type] = dict(tracking.get(item_type, {}))
    tracking[item_type][index] = {"status": status, "updated_at": datetime.utcnow().isoformat()}
    report.item_tracking = tracking
    db.commit()
    return JSONResponse({"ok": True, "status": status})


@router.post("/reports/{report_id}/items/update")
async def update_report_item(report_id: int, request: Request, db: Session = Depends(get_db)):
    """Update fields of a quick win or project item."""
    data = await request.json()
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    item_type = data.get("type")
    index = int(data.get("index", -1))
    updates = data.get("updates", {})
    allowed = {"title", "description", "estimated_savings_monthly", "effort_hours", "effort_weeks", "risk", "severity", "hidden"}

    if item_type not in ("quick_wins", "projects"):
        raise HTTPException(status_code=400, detail="Invalid type")

    items = list(getattr(report, item_type) or [])
    if not (0 <= index < len(items)):
        raise HTTPException(status_code=404, detail="Item not found")

    item = dict(items[index])
    item.update({k: v for k, v in updates.items() if k in allowed})
    items[index] = item
    setattr(report, item_type, items)
    db.commit()
    return JSONResponse({"ok": True})


@router.post("/reports/{report_id}/items/delete")
async def delete_report_item(report_id: int, request: Request, db: Session = Depends(get_db)):
    """Delete a quick win or project item, shifting tracking keys."""
    data = await request.json()
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    item_type = data.get("type")
    index = int(data.get("index", -1))

    if item_type not in ("quick_wins", "projects"):
        raise HTTPException(status_code=400, detail="Invalid type")

    items = list(getattr(report, item_type) or [])
    if not (0 <= index < len(items)):
        raise HTTPException(status_code=404, detail="Item not found")

    items.pop(index)
    setattr(report, item_type, items)

    # Shift tracking keys > index down by 1
    tracking = dict(report.item_tracking or {})
    if item_type in tracking:
        old = dict(tracking[item_type])
        new_t = {}
        for k, v in old.items():
            k_int = int(k)
            if k_int < index:
                new_t[str(k_int)] = v
            elif k_int > index:
                new_t[str(k_int - 1)] = v
        tracking[item_type] = new_t
    report.item_tracking = tracking
    db.commit()
    return JSONResponse({"ok": True})


@router.get("/reports/{report_id}/print")
async def print_report(report_id: int, request: Request, db: Session = Depends(get_db)):
    """Render a print-optimized HTML page for PDF export via browser print."""
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status not in ("completed", "partial"):
        raise HTTPException(status_code=400, detail="Report not ready for export")
    client = db.query(Client).filter(Client.id == report.client_id).first()
    return templates.TemplateResponse(
        "admin/report_print.html",
        {"request": request, "client": client, "report": report}
    )


@router.get("/reports/{report_id}/monthly-pdf")
async def monthly_pdf(report_id: int, db: Session = Depends(get_db)):
    """Generate a professional monthly PDF report using WeasyPrint."""
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="WeasyPrint não instalado. Execute: pip install weasyprint",
        )

    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report or report.status not in ("completed", "partial"):
        raise HTTPException(status_code=404, detail="Relatório não encontrado ou incompleto")

    client = db.query(Client).filter(Client.id == report.client_id).first()

    # Build month-over-month comparison from raw data
    monthly_totals = (report.raw_data or {}).get("cost_and_usage", {}).get("monthly_totals", [])
    prev_month_cost = monthly_totals[-2]["cost"] if len(monthly_totals) >= 2 else None
    curr_month_cost = monthly_totals[-1]["cost"] if monthly_totals else (report.monthly_cost or 0)
    # Support both "period" (single-account) and "month" (multi-account merge) key names
    _prev = monthly_totals[-2] if len(monthly_totals) >= 2 else {}
    prev_month_period = _prev.get("period") or _prev.get("month")

    month_delta = None
    month_delta_pct = None
    if prev_month_cost and curr_month_cost and prev_month_cost > 0:
        month_delta = curr_month_cost - prev_month_cost
        month_delta_pct = (month_delta / prev_month_cost) * 100

    forecast = (report.raw_data or {}).get("cost_and_usage", {}).get("forecast_next_month")
    top_services = sorted(
        report.cost_by_service or [],
        key=lambda x: float(x.get("cost", 0) or 0),
        reverse=True,
    )[:5]

    prowler = report.prowler_findings or {}
    prowler_total = sum(len(v) for v in prowler.values() if isinstance(v, list))

    context = {
        "client": client,
        "report": report,
        "curr_month_cost": curr_month_cost,
        "prev_month_cost": prev_month_cost,
        "prev_month_period": prev_month_period,
        "month_delta": month_delta,
        "month_delta_pct": month_delta_pct,
        "monthly_totals": monthly_totals[-6:],
        "top_services": top_services,
        "forecast": forecast,
        "prowler": prowler,
        "prowler_total": prowler_total,
        "today": datetime.utcnow(),
    }

    html_str = templates.env.get_template("admin/monthly_report.html").render(context)
    pdf_bytes = WeasyprintHTML(string=html_str).write_pdf()

    import io
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    safe_name = client.company.lower().replace(" ", "-").replace("/", "-")
    filename = f"relatorio-mensal-{safe_name}-{datetime.utcnow().strftime('%Y-%m')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# CLOUDTRAIL UNAUTHORIZED RESOURCE AUDIT
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/cloudtrail-audit")
async def cloudtrail_audit(
    request: Request,
    client_id: int,
    days: int = 7,
    db: Session = Depends(get_db),
):
    """
    On-demand CloudTrail query: find resources created by non-operator principals
    in the last 1–30 days across all configured regions for this client.
    """
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    days = min(max(int(days), 1), 30)
    events: list[dict] = []
    error: str | None = None

    try:
        from app.aws_analyzer import collect_cloudtrail_unauthorized_resources
        regions = [r.strip() for r in (client.aws_regions or "us-east-1").split(",") if r.strip()]
        events = collect_cloudtrail_unauthorized_resources(
            role_arn=client.primary_role_arn,
            regions=regions,
            days=days,
        )
    except Exception as exc:
        error = str(exc)

    # Summary stats for the template
    unique_users = {e["username"] for e in events if e.get("username")}
    by_type: dict[str, int] = {}
    for e in events:
        ev = e.get("event_name", "Unknown")
        by_type[ev] = by_type.get(ev, 0) + 1
    top_events = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]

    return templates.TemplateResponse(
        "admin/cloudtrail_audit.html",
        {
            "request": request,
            "client": client,
            "events": events,
            "days": days,
            "error": error,
            "unique_users": unique_users,
            "top_events": top_events,
        },
    )


# ---------------------------------------------------------------------------
# PROWLER SECURITY POSTURE SCAN
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/prowler-scan")
async def trigger_prowler_scan(client_id: int, db: Session = Depends(get_db)):
    """Trigger a Prowler security scan for a client (runs in background thread)."""
    from app.prowler_runner import prowler_available, run_prowler_background, get_prowler_state

    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    if not prowler_available():
        raise HTTPException(
            status_code=400,
            detail="Prowler não encontrado. Instale com: pip install prowler",
        )

    state = get_prowler_state(client_id)
    if state and state.get("status") == "running":
        return JSONResponse({"ok": False, "message": "Scan já em andamento"})

    # Find or create a report to attach prowler results to
    report = (
        db.query(AnalysisReport)
        .filter(
            AnalysisReport.client_id == client_id,
            AnalysisReport.status.in_(["completed", "partial"]),
        )
        .order_by(AnalysisReport.completed_at.desc())
        .first()
    )
    if not report:
        raise HTTPException(status_code=400, detail="Nenhum relatório disponível para este cliente")

    regions = [r.strip() for r in (client.aws_regions or "us-east-1").split(",") if r.strip()]

    from app.database import SessionLocal
    run_prowler_background(
        client_id=client_id,
        report_id=report.id,
        role_arn=client.primary_role_arn,
        regions=regions,
        db_session_factory=SessionLocal,
    )

    return JSONResponse({"ok": True, "message": "Scan iniciado em background", "report_id": report.id})


@router.get("/clients/{client_id}/prowler-status")
async def prowler_status(client_id: int):
    """Poll Prowler scan status for a client."""
    from app.prowler_runner import get_prowler_state
    state = get_prowler_state(client_id)
    if not state:
        return JSONResponse({"status": "idle"})
    return JSONResponse(state)


@router.get("/clients/{client_id}/prowler-results")
async def prowler_results(client_id: int, request: Request, db: Session = Depends(get_db)):
    """View Prowler scan results for a client."""
    from app.prowler_runner import prowler_available, get_prowler_state

    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    report = (
        db.query(AnalysisReport)
        .filter(
            AnalysisReport.client_id == client_id,
            AnalysisReport.status.in_(["completed", "partial"]),
        )
        .order_by(AnalysisReport.completed_at.desc())
        .first()
    )

    findings = report.prowler_findings if report else None
    prowler_st = report.prowler_status if report else None
    state = get_prowler_state(client_id)

    total = 0
    if isinstance(findings, dict):
        total = sum(len(v) for v in findings.values() if isinstance(v, list))

    return templates.TemplateResponse(
        "admin/prowler_results.html",
        {
            "request": request,
            "client": client,
            "report": report,
            "findings": findings or {},
            "prowler_status": prowler_st,
            "state": state,
            "total": total,
            "prowler_available": prowler_available(),
        },
    )


# ---------------------------------------------------------------------------
# PORTAL VISIBILITY SETTINGS
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/visibility")
async def update_visibility(client_id: int, request: Request, db: Session = Depends(get_db)):
    """Update portal section visibility for a client."""
    data = await request.json()
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    allowed = {
        "finops_dashboard", "finops_quick_wins", "finops_projects",
        "finops_unused", "finops_correlations",
        "security_dashboard", "security_quick_wins", "security_projects", "security_findings"
    }
    settings = {k: bool(v) for k, v in data.items() if k in allowed}
    client.visibility_settings = settings
    db.commit()
    return JSONResponse({"ok": True})


@router.post("/clients/{client_id}/delete")
async def delete_client(client_id: int, db: Session = Depends(get_db)):
    """Delete a client and all their analysis reports."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Refuse if an analysis is running
    running = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.client_id == client_id, AnalysisReport.status == "running")
        .first()
    )
    if running:
        return RedirectResponse(
            url=f"/admin/clients/{client_id}?error=cannot_delete_running", status_code=303
        )

    db.query(AnalysisReport).filter(AnalysisReport.client_id == client_id).delete()
    db.delete(client)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)


# ---------------------------------------------------------------------------
# SCHEDULED ANALYSIS
# ---------------------------------------------------------------------------

@router.post("/clients/{client_id}/schedule")
async def set_schedule(
    client_id: int,
    enabled: bool = Form(False),
    interval_days: int = Form(7),
    db: Session = Depends(get_db),
):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    client.schedule_enabled = enabled
    client.schedule_interval_days = interval_days
    if enabled:
        client.schedule_next_run = datetime.utcnow() + timedelta(days=interval_days)
    else:
        client.schedule_next_run = None
    db.commit()
    return RedirectResponse(url=f"/admin/clients/{client_id}", status_code=303)


def _scheduler_tick() -> None:
    """Check all clients for due scheduled analyses and trigger them."""
    from app.database import SessionLocal
    from app.config import get_settings

    settings = get_settings()
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        due = db.query(Client).filter(
            Client.schedule_enabled == True,
            Client.is_active == True,
            Client.schedule_next_run != None,
            Client.schedule_next_run <= now,
        ).all()

        for client in due:
            running = db.query(AnalysisReport).filter(
                AnalysisReport.client_id == client.id,
                AnalysisReport.status.in_(["pending", "running"]),
            ).first()
            if running:
                continue

            report = AnalysisReport(client_id=client.id, report_type="full", status="pending")
            db.add(report)
            db.flush()

            client.schedule_last_run = now
            client.schedule_next_run = now + timedelta(days=client.schedule_interval_days or 7)
            db.commit()
            db.refresh(report)

            _start_analysis(report.id, client.id, client.analysis_accounts,
                            client.aws_regions, settings.database_url, client.account_mode)
    except Exception:
        pass
    finally:
        db.close()


def start_scheduler() -> None:
    """Start the background scheduler daemon thread."""
    def _loop():
        while True:
            try:
                _scheduler_tick()
            except Exception:
                pass
            time.sleep(900)  # check every 15 minutes

    t = threading.Thread(target=_loop, daemon=True, name="analysis-scheduler")
    t.start()
