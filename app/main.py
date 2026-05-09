import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import text, inspect as sql_inspect

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

from app.database import engine, Base
from app.routers import admin, finops, security, client as client_router
from app.config import get_settings
from app.routers.admin import start_scheduler

settings = get_settings()

# Paths under /admin that don't require a session (login flow + static assets)
_ADMIN_PUBLIC = ("/admin/login", "/admin/logout", "/admin/auth/")

_REPORT_COLUMNS = [
    # (column_name, sql_type_sqlite, sql_type_pg)
    ("combined_analysis",    "TEXT",    "JSON"),
    ("security_score",       "INTEGER", "INTEGER"),
    ("security_label",       "TEXT",    "TEXT"),
    ("item_tracking",        "TEXT",    "JSON"),
    ("prowler_findings",     "TEXT",    "JSON"),
    ("prowler_status",       "TEXT",    "TEXT"),
    ("prowler_started_at",   "TEXT",    "TIMESTAMP"),
    ("prowler_completed_at", "TEXT",    "TIMESTAMP"),
]

_CLIENT_COLUMNS = [
    ("schedule_enabled",       "INTEGER", "BOOLEAN"),
    ("schedule_interval_days", "INTEGER", "INTEGER"),
    ("schedule_next_run",      "TEXT",    "TIMESTAMP"),
    ("schedule_last_run",      "TEXT",    "TIMESTAMP"),
    ("visibility_settings",    "TEXT",    "JSON"),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    # Add columns introduced after initial schema — safe for existing DBs.
    is_sqlite = "sqlite" in str(engine.url)
    try:
        inspector = sql_inspect(engine)
        with engine.begin() as conn:
            existing_reports = {c["name"] for c in inspector.get_columns("analysis_reports")}
            for col_name, sqlite_type, pg_type in _REPORT_COLUMNS:
                if col_name not in existing_reports:
                    col_type = sqlite_type if is_sqlite else pg_type
                    conn.execute(text(f"ALTER TABLE analysis_reports ADD COLUMN {col_name} {col_type}"))

            existing_clients = {c["name"] for c in inspector.get_columns("clients")}
            for col_name, sqlite_type, pg_type in _CLIENT_COLUMNS:
                if col_name not in existing_clients:
                    col_type = sqlite_type if is_sqlite else pg_type
                    conn.execute(text(f"ALTER TABLE clients ADD COLUMN {col_name} {col_type}"))
    except Exception:
        pass  # Table may not exist yet on first run; create_all handles it

    start_scheduler()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Multi-tenant AWS FinOps & Security Analysis Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(admin.router, prefix="/admin")
app.include_router(finops.router, prefix="/finops")
app.include_router(security.router, prefix="/security")
app.include_router(client_router.router, prefix="/portal")


@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    """Redirect unauthenticated requests to /admin/login."""
    path = request.url.path
    if path.startswith("/admin") and not any(path.startswith(p) for p in _ADMIN_PUBLIC):
        if not request.session.get("admin_authenticated"):
            return RedirectResponse(url="/admin/login", status_code=302)
    return await call_next(request)


# SessionMiddleware must be registered AFTER the auth middleware so Starlette
# inserts it as the outermost layer (runs first), making request.session
# available when admin_auth_middleware executes.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    max_age=3600 * 8,  # 8-hour session
    https_only=False,   # set True in prod (HTTPS only)
    same_site="lax",
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return RedirectResponse(url="/admin")


