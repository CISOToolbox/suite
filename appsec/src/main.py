from __future__ import annotations

import logging
import os

logging.basicConfig(level=logging.INFO)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.database import async_session, engine
from src.models import Base

APP_URL = os.getenv("APP_URL", "http://localhost:8080")
MODULE_NAME = os.getenv("MODULE_NAME", "appsec")

app = FastAPI(title="CISO Toolbox — AppSec", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(Exception)
async def _global_error_handler(request, exc):
    logging.getLogger(f"{MODULE_NAME}-backend").error("Unhandled error: %s", exc, exc_info=True)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.anthropic.com https://api.openai.com https://services.nvd.nist.gov; font-src 'self'; frame-ancestors 'none'"
        response.headers["Content-Security-Policy"] = csp
        return response


app.add_middleware(SecurityHeadersMiddleware)
# Generic write journal (FEAT-30 P1.6): every mutating /api request is
# journaled; routes already covered by in-handler log_action are excluded.
from src.audit_common import install_write_journal_middleware
install_write_journal_middleware(app, exclude=[
    ("POST", r"/api/applications"),
    ("PATCH", r"/api/applications/[^/]+"),
    ("DELETE", r"/api/applications/[^/]+"),
    ("POST", r"/api/applications/[^/]+/scan"),
    ("PATCH", r"/api/findings/[^/]+"),
    ("POST", r"/api/findings/bulk-triage"),
    ("POST", r"/api/ignore-rules"),
    ("PATCH", r"/api/ignore-rules/[^/]+"),
    ("DELETE", r"/api/ignore-rules/[^/]+"),
    ("PUT", r"/api/audit-log/retention"),
    ("POST", r"/api/scans/reset(/[^/]+)?"),
])
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    # Explicit allow-list aligned with the 7 other modules (AUTH-07): the
    # wildcard also whitelisted X-Service-Token for the allowed origin.
    allow_headers=["Content-Type", "Authorization"],
)

from src.routes import auth, applications, findings, scans, sbom, measures, users, ai, audit, ignore_rules
from src.version_common import version_payload

app.include_router(auth.router)
app.include_router(applications.router)
app.include_router(findings.router)
app.include_router(scans.router)
app.include_router(sbom.router)
app.include_router(measures.router)
app.include_router(users.router)
app.include_router(ai.router)
app.include_router(audit.router)
app.include_router(ignore_rules.router)
from src.routes import notifications as notifications_routes
app.include_router(notifications_routes.router)

try:
    from src.routes import internal
    app.include_router(internal.router)
except ImportError:
    pass

try:
    from src.routes import directory_proxy
    app.include_router(directory_proxy.router)
except ImportError:
    pass


@app.get("/api/health")
async def health():
    return {"status": "ok", "module": MODULE_NAME}



@app.get("/api/version")
async def version():
    """Version identity (FEAT-29): public, used for backup
    compatibility checks before restore."""
    async with async_session() as db:
        return await version_payload("appsec", Base.metadata, db)

@app.on_event("startup")
async def on_startup():
    # Fail closed unless AUTH_MODE=none is explicit (see auth_common.assert_auth_posture).
    from src.auth import assert_auth_posture
    assert_auth_posture()
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(f"{MODULE_NAME}-backend")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    # Mark orphaned pending/running jobs as failed (from previous crash)
    from src.database import async_session
    from sqlalchemy import update
    from src.models import ScanJob
    async with async_session() as db:
        await db.execute(
            update(ScanJob)
            .where(ScanJob.status.in_(["pending", "running"]))
            .values(status="failed", error="Server restarted before scan completed")
        )
        await db.commit()
    logger.info("Orphaned scan jobs cleaned up")

    from src.scheduler import start_scheduler
    start_scheduler()
    logger.info("Scheduler started")

    # FEAT-35 — SMTP pushed by Pilot survives restarts via app_settings;
    # weekly findings recap scheduler.
    try:
        from src.routes.internal import _hydrate_smtp_from_db
        await _hydrate_smtp_from_db()
    except ImportError:
        pass
    from src.findings_notify import start_findings_notify_scheduler
    start_findings_notify_scheduler()
    logger.info("Findings notification scheduler started")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
