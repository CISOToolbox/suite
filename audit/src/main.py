from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from src.database import async_session, engine
from src.models import Base
from src.routes.ai import router as ai_router
from src.routes.auth import router as auth_router
from src.routes.directory_proxy import router as directory_router
from src.routes.internal import router as internal_router
from src.routes.measures import router as measures_router
from src.routes.projects import router as projects_router
from src.routes.users import router as users_router
from src.version_common import version_payload

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("audit-backend")

app = FastAPI(title="Audit Backend", version="0.1.0")


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
install_write_journal_middleware(app, exclude=[("PUT", r"/api/projects/[^/]+"), ("DELETE", r"/api/projects/[^/]+"), ("POST", r"/api/projects/import"), ("DELETE", r"/api/projects/[^/]+/measures/[^/]+")])

APP_URL = os.environ.get("APP_URL", "http://localhost:8089")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(measures_router)
app.include_router(ai_router)
app.include_router(users_router)
app.include_router(directory_router)
app.include_router(internal_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "module": "audit"}



@app.get("/api/version")
async def version():
    """Version identity (FEAT-29): public, used for backup
    compatibility checks before restore."""
    async with async_session() as db:
        return await version_payload("audit", Base.metadata, db)

@app.on_event("startup")
async def on_startup():
    # Fail closed unless AUTH_MODE=none is explicit (see auth_common.assert_auth_posture).
    from src.auth import assert_auth_posture
    assert_auth_posture()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
