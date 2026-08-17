"""Perf regression (H2): access /internal/stats resolves the latest closed
review per application in ONE grouped query, not a SELECT per app.

The endpoint (polled by Pilot every 30s) looped over every Application and ran
a per-app "latest closed review" query (N+1). It now groups with MAX(closed_at)
once. This test locks the apps-needing-review count the rewrite must preserve:
one up-to-date app, one overdue, one never reviewed → 2 needing review.
"""
import datetime
import os
import uuid
from types import SimpleNamespace

import pytest

os.environ.setdefault("SERVICE_TOKEN", "test-service-token")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB as _JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from src.models import Application, Base, Project, Review
from src.routes.internal import internal_stats

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

_engine = create_async_engine(
    "sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
)
_Session = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

pytestmark = pytest.mark.asyncio


async def test_apps_needing_review_count_after_n1_fix():
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        pid = uuid.uuid4()
        today = datetime.date.today().isoformat()
        async with _Session() as db:
            db.add(Project(id=pid, name="MedSecure"))
            db.add_all([
                Application(project_id=pid, id="APP-1", nom="Up to date", frequence_revue="mensuelle"),
                Application(project_id=pid, id="APP-2", nom="Overdue", frequence_revue="mensuelle"),
                Application(project_id=pid, id="APP-3", nom="Never reviewed", frequence_revue="mensuelle"),
            ])
            db.add_all([
                # APP-1: closed today → within the monthly window (not needing).
                Review(project_id=pid, id="R1", application_id="APP-1", status="cloturee", closed_at=today),
                # APP-1 also has an older closed review — MAX must pick today's.
                Review(project_id=pid, id="R0", application_id="APP-1", status="cloturee", closed_at="2019-01-01"),
                # APP-2: only an old closed review → overdue.
                Review(project_id=pid, id="R2", application_id="APP-2", status="cloturee", closed_at="2020-01-01"),
                # APP-3: an in-progress (not closed) review → still never reviewed.
                Review(project_id=pid, id="R3", application_id="APP-3", status="en_cours", closed_at=""),
            ])
            await db.commit()

            req = SimpleNamespace(headers={"X-Service-Token": "test-service-token"})
            out = await internal_stats(req, db)

        texts = " | ".join(a.get("text", "") for a in out.get("alerts", []))
        assert "2 application(s) sans revue" in texts, texts
    finally:
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
