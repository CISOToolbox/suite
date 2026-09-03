from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from pathlib import Path

from src.database import async_session, engine
from src.models import Base
from src.kpi_scheduler import compute_auto_kpis_once, start_kpi_scheduler
from src.seeds.kpi_catalog import seed_kpi_catalog
from src.connectors import graph as graph_connector
from src.connectors import aws as aws_connector
from src.connectors import proofpoint_psat as psat_connector
from src.connectors_common import ConnectorBinding, make_router as make_connectors_router
from src.routes.ai import router as ai_router
from src.routes.awareness import router as awareness_router
from src.routes.auth import router as auth_router
from src.routes.backups import router as backups_router, start_backup_scheduler
from src.routes.connectors_admin import router as connectors_admin_router
from src.routes.dashboard import router as dashboard_router
from src.routes.kpis import router as kpis_router
from src.routes.measure_groups import router as measure_groups_router
from src.routes.measures import router as measures_router
from src.routes.evidences import router as evidences_router
from src.routes.internal import router as internal_router
from src.routes.modules import router as modules_router
from src.routes.notifications import router as notifications_router
from src.routes.projects import router as projects_router
from src.routes.restore import router as restore_router
from src.routes.settings import router as settings_router
from src.routes.directory import router as directory_router
from src.routes.users import router as users_router
from src.version_common import version_payload

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pilot")

app = FastAPI(title="CISO Toolbox Pilot", version="0.1.0")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Même politique de cache que le proxy de la suite (nginx $cache_policy) :
        # sans Cache-Control, un déploiement standalone (sans proxy) laisse le
        # navigateur au cache heuristique — vieux JS sur nouveau backend, la
        # classe de panne la plus déroutante qui soit (formats d'API croisés).
        # Ne touche pas aux routes qui posent déjà leur propre politique.
        if "cache-control" not in response.headers:
            ct = response.headers.get("content-type", "")
            if ct.startswith(("image/", "font/")):
                response.headers["Cache-Control"] = "public, max-age=3600"
            else:
                response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


app.add_middleware(SecurityHeadersMiddleware)
# Generic write journal (FEAT-30 P1.6): every mutating /api request is
# journaled; routes with richer in-handler entries are excluded.
from src.audit import install_write_journal_middleware
install_write_journal_middleware(app, exclude=[("*", r"/api/backups(/.*)?"), ("*", r"/api/restore(/.*)?"), ("PUT", r"/api/settings"), ("DELETE", r"/api/kpis/[^/]+"), ("POST", r"/api/measures/sync")])

APP_URL = os.environ.get("APP_URL", "http://localhost:8090")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(auth_router)
# Service-token only, and 404'd at the edge by nginx — see routes/internal.py.
app.include_router(internal_router)
app.include_router(users_router)
app.include_router(directory_router)
app.include_router(modules_router)
app.include_router(notifications_router)
app.include_router(dashboard_router)
app.include_router(measures_router)
app.include_router(measure_groups_router)
app.include_router(restore_router)
app.include_router(evidences_router)
app.include_router(kpis_router)
app.include_router(awareness_router)
app.include_router(projects_router)
app.include_router(settings_router)
app.include_router(backups_router)

# Connector framework — see docs/CHANTIER_CONNECTEURS.md.
# Pilot declares itself as a consumer of the M365 connector (used by
# the KPI scheduler). The shared router exposes:
#   GET/PUT /api/connectors/{m365}, POST /api/connectors/m365/{test,run},
#   PUT /api/internal/connectors/m365 (Pilot push for future managed clients).
_CONNECTOR_SCHEMAS = Path(__file__).parent / "connector_schemas"
_CONNECTORS_MAP = {
    "m365": ConnectorBinding(
        schema_path=_CONNECTOR_SCHEMAS / "m365.json",
        test=graph_connector.test_credentials,
        run=compute_auto_kpis_once,
    ),
    "aws": ConnectorBinding(
        schema_path=_CONNECTOR_SCHEMAS / "aws.json",
        test=aws_connector.test_credentials,
        run=compute_auto_kpis_once,
    ),
    "proofpoint_psat": ConnectorBinding(
        schema_path=_CONNECTOR_SCHEMAS / "proofpoint_psat.json",
        test=psat_connector.test_credentials,
        run=psat_connector.run_sync,
    ),
}
# Stash the binding map on app.state so the aggregator route can read
# Pilot's own connectors without HTTP loopback.
app.state.connectors = _CONNECTORS_MAP
app.include_router(make_connectors_router(_CONNECTORS_MAP))
app.include_router(connectors_admin_router)
app.include_router(ai_router)


@app.get("/api/health")
async def health():
    return {"status": "ok"}



@app.get("/api/version")
async def version():
    """Version identity (FEAT-29): public, used for backup
    compatibility checks before restore."""
    async with async_session() as db:
        return await version_payload("pilot", Base.metadata, db)

@app.on_event("startup")
async def on_startup():
    # Fail closed unless AUTH_MODE=none is explicit (see auth.assert_auth_posture).
    from src.auth import assert_auth_posture, SERVICE_TOKEN
    assert_auth_posture()
    if not SERVICE_TOKEN:
        logger.warning("SERVICE_TOKEN is empty — inter-module calls will fail")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Pilot database tables created")

    # Idempotent KPI catalogue seed. Safe to run on every boot — only
    # the definition shape is refreshed; user-tuned target/threshold/active
    # are preserved (see seeds/kpi_catalog.py docstring).
    try:
        async with async_session() as session:
            counts = await seed_kpi_catalog(session)
        logger.info("KPI catalogue seed counts: %s", counts)
    except Exception:  # pragma: no cover — never block startup on seed failure
        logger.exception("KPI catalogue seed failed (continuing startup)")

    start_backup_scheduler()
    logger.info("Backup scheduler started")

    start_kpi_scheduler()
    logger.info("KPI auto-compute scheduler started")

    from src.deadline_digest import start_deadline_digest_scheduler
    start_deadline_digest_scheduler()
    logger.info("Deadline digest scheduler started")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
