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
MODULE_NAME = os.getenv("MODULE_NAME", "watch")

app = FastAPI(title="CISO Toolbox — Watch", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)


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
        # connect-src allows the feed sources we ingest in later phases (NVD, OSV,
        # CISA, EPSS, CERT-FR…) so the optional frontend "preview" can call them
        # client-side if we ever need it. Server-side ingestion does not need CSP.
        csp = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' https://api.anthropic.com https://api.openai.com "
            "https://services.nvd.nist.gov https://api.osv.dev https://api.first.org "
            "https://www.cisa.gov https://www.cert.ssi.gouv.fr; "
            "font-src 'self'; frame-ancestors 'none'"
        )
        response.headers["Content-Security-Policy"] = csp
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
# journaled; routes already covered by in-handler log_action are excluded.
from src.audit_common import install_write_journal_middleware
install_write_journal_middleware(app, exclude=[
    ("PATCH", r"/api/alerts/[^/]+/status"),
    ("POST", r"/api/alerts/bulk-status"),
    ("POST", r"/api/alerts/[^/]+/analyze"),
    ("POST", r"/api/feeds/[^/]+/run"),
    ("POST", r"/api/scopes"),
    ("PATCH", r"/api/scopes/[^/]+"),
    ("DELETE", r"/api/scopes/[^/]+"),
    ("POST", r"/api/scopes/[^/]+/recipients"),
    ("DELETE", r"/api/scopes/[^/]+/recipients/[^/]+"),
    ("POST", r"/api/scopes/[^/]+/targets"),
    ("PATCH", r"/api/scopes/[^/]+/targets/[^/]+"),
    ("DELETE", r"/api/scopes/[^/]+/targets/[^/]+"),
    ("PUT", r"/api/audit-log/retention"),
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

# Standard suite routers (mandatory). Module-specific routers (scopes,
# targets, alerts, digest…) are added in later phases.
from src.routes import auth, users, ai, audit, scopes, targets, alerts, digest, dashboard
from src.version_common import version_payload

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(ai.router)
app.include_router(audit.router)
app.include_router(scopes.router)
app.include_router(targets.router)
app.include_router(alerts.router)
app.include_router(digest.router)
app.include_router(dashboard.router)

# Suite-integration routers (only present when deployed alongside Pilot).
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
        return await version_payload("watch", Base.metadata, db)

@app.on_event("startup")
async def on_startup():
    # Fail closed unless AUTH_MODE=none is explicit (see auth_common.assert_auth_posture).
    from src.auth import assert_auth_posture
    assert_auth_posture()
    logger = logging.getLogger(f"{MODULE_NAME}-backend")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    # Prime SMTP config from app_settings so digests can send right after
    # a rebuild — without waiting for Pilot to re-push.
    from src.routes.internal import _hydrate_smtp_from_db
    await _hydrate_smtp_from_db()

    # Phase 3: scheduler runs real feed ingestion (NVD, OSV, KEV, CERT-FR).
    from src.scheduler import start_scheduler
    start_scheduler()
    logger.info("Scheduler started (phase 3 — feed ingestion active)")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
