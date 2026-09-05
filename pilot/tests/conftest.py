"""Shared fixtures for Pilot tests.

Uses an in-memory SQLite database so tests run without PostgreSQL.
Overrides auth dependencies to bypass JWT checks.
Patches the database engine and disables startup side-effects.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import patch

# Force AUTH_MODE=none before any app import so on_startup won't reject missing JWT_SECRET
os.environ["AUTH_MODE"] = "none"
os.environ["JWT_SECRET"] = ""
os.environ["SERVICE_TOKEN"] = "test-service-token"
# Use SQLite for tests (set before database.py is imported)
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from src.models import Base, User


# ---------------------------------------------------------------------------
# In-memory async SQLite engine (no PostgreSQL required)
# ---------------------------------------------------------------------------
# Use StaticPool + check_same_thread=False so all async sessions share the
# same in-memory database within a single test.
test_engine = create_async_engine(
    "sqlite+aiosqlite://",
    echo=False,
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
)


# SQLite ignores FKs (hence the DDL's ON DELETE CASCADE) until the pragma
# is armed per connection — the cascade tests were missing the very behavior
# they verify, and failed on a DDL that was actually correct.
@sa_event.listens_for(test_engine.sync_engine, "connect")
def _enable_sqlite_fks(dbapi_conn, _record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


def _strip_pg_server_defaults():
    """Remove PostgreSQL-only server_defaults (gen_random_uuid, NOW, jsonb
    casts) from all columns so SQLite's CREATE TABLE doesn't choke."""
    for table in Base.metadata.tables.values():
        for col in table.columns:
            if col.server_default is not None:
                sd_text = str(col.server_default.arg) if hasattr(col.server_default, "arg") else ""
                # Keep simple string defaults, remove PG functions
                if any(kw in sd_text.lower() for kw in ("gen_random_uuid", "now(", "::jsonb")):
                    col.server_default = None


def _substitute_pg_types_for_sqlite():
    """SQLite has no JSONB — swap it for the dialect-agnostic JSON type
    so `Base.metadata.create_all` against an in-memory SQLite engine
    doesn't fail with `Compiler can't render element of type JSONB`.

    Done at module import time, BEFORE any engine touches the metadata.
    The substitution stays in place for the whole test session; tests
    don't exercise PG-specific JSONB semantics (operator `?`, GIN
    indexes, etc.) so this is safe."""
    from sqlalchemy import JSON
    from sqlalchemy.dialects.postgresql import JSONB as _JSONB
    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, _JSONB):
                col.type = JSON()


_strip_pg_server_defaults()
_substitute_pg_types_for_sqlite()


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Create all tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# Fake user for auth bypass
# ---------------------------------------------------------------------------
_fake_user_id = uuid.uuid4()

_fake_user = User(
    id=_fake_user_id,
    email="test@cisotoolbox.org",
    name="Test User",
    provider="local",
    provider_id="test",
    role="admin",
    modules=[],
    permissions={},
    ai_enabled="false",
)


def _fake_get_current_user():
    """Return a fake admin user, bypassing JWT auth."""
    return _fake_user


def _fake_require_admin():
    """No-op: allow admin actions in tests."""
    return None


# ---------------------------------------------------------------------------
# Override app dependencies and provide async test client.
# The app's on_startup tries to create_all via the real PG engine and
# starts a backup scheduler. We patch both away.
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def client():
    from src.database import get_db
    from src.auth import get_current_user, require_admin
    from src.main import app

    async def override_get_db():
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = _fake_get_current_user
    app.dependency_overrides[require_admin] = _fake_require_admin

    # Patch engine in src.main (imported at module level) so on_startup's
    # create_all uses our SQLite engine instead of the PG one.
    # Also stub the backup scheduler.
    with (
        patch("src.main.engine", test_engine),
        patch("src.routes.backups.start_backup_scheduler", return_value=None),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def db():
    """Provide a raw database session for setup/assertions."""
    async with TestSessionLocal() as session:
        yield session
