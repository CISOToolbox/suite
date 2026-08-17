"""Perf regression (H6b): the dashboard caches each module's fan-out briefly.

The health+stats+activity fetch per module is the expensive part of the
dashboard and identical for every user/tab polling within the window. A
per-module TTL cache collapses concurrent/overlapping polls to one fan-out per
module, while still filtering per user. These tests lock the cache-hit and the
per-user-filtering behaviour.
"""
from unittest.mock import patch

import pytest
from sqlalchemy import select

from src.models import ModuleRegistry
from src.routes import dashboard

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clear_module_cache():
    dashboard._MODULE_CACHE.clear()
    yield
    dashboard._MODULE_CACHE.clear()


def _make_counting_fetch(counter):
    async def _fetch(client, m, headers):
        counter[m.id] = counter.get(m.id, 0) + 1
        return {
            "card": {"id": m.id, "name": m.name, "url": "/", "status": "active", "stats": None},
            "activity": [],
        }
    return _fetch


async def _seed_two_modules(db):
    db.add_all([
        ModuleRegistry(id="risk", name="Risk", internal_url="http://risk:8080",
                       external_url="/risk/", status="active"),
        ModuleRegistry(id="vendor", name="Vendor", internal_url="http://vendor:8080",
                       external_url="/vendor/", status="active"),
    ])
    await db.commit()


async def test_second_poll_within_ttl_is_a_cache_hit(db):
    # The cache logic is _collect_cards; get_dashboard's later JSONB query needs
    # Postgres, so we exercise the fan-out/cache unit directly.
    await _seed_two_modules(db)
    wanted = (await db.execute(select(ModuleRegistry))).scalars().all()
    counter: dict = {}

    with patch("src.routes.dashboard._fetch_module", _make_counting_fetch(counter)):
        cards1, _ = await dashboard._collect_cards(wanted, {}, db)
        assert counter == {"risk": 1, "vendor": 1}          # first poll fetches both
        assert {c["id"] for c in cards1} == {"risk", "vendor"}

        cards2, _ = await dashboard._collect_cards(wanted, {}, db)
        assert counter == {"risk": 1, "vendor": 1}          # second poll: no new fetch
        assert {c["id"] for c in cards2} == {"risk", "vendor"}


async def test_user_only_sees_and_fetches_its_modules(db):
    await _seed_two_modules(db)
    all_mods = (await db.execute(select(ModuleRegistry))).scalars().all()
    wanted = [m for m in all_mods if m.id == "risk"]           # a limited user's set
    counter: dict = {}

    with patch("src.routes.dashboard._fetch_module", _make_counting_fetch(counter)):
        cards, _ = await dashboard._collect_cards(wanted, {}, db)

    assert counter == {"risk": 1}                              # vendor never fetched
    assert {c["id"] for c in cards} == {"risk"}
