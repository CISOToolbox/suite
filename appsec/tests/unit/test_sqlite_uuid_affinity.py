"""An id whose hex reads as a number survives the SQLite test database.

A column declared ``UUID`` has NUMERIC affinity on SQLite: the hex of
``…5678e123`` was stored as a float, ``…56789012`` as a number too, and
reading the row back raised inside ``uuid.UUID``. Random ids made this an
intermittent failure of whichever test drew one (see ``conftest.py``)."""
import os
import sys
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.models import User  # noqa: E402


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "12345678-1234-4234-8234-12345678e123",   # digits and one "e": a float
    "12345678-1234-4234-8234-123456789012",   # digits only: too long for an integer, a float
    "00000000-0000-4000-8000-000000000000",   # leading zeros: an integer
])
async def test_a_numeric_looking_id_reads_back(value):
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(User.__table__.create)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    uid = uuid.UUID(value)
    async with maker() as db:
        db.add(User(id=uid, email="ciso@medsecure.example"))
        await db.commit()
    async with maker() as db:
        row = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    await engine.dispose()
    assert row.id == uid
