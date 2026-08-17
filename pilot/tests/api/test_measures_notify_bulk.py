"""Perf regression (M4): POST /api/measures/notify-bulk upserts/deletes many
measures in one request.

A project rename in Vendor used to fire one /notify POST (and a fresh httpx
client) per measure — 500 measures → 500 connections + 500 commits on Pilot.
The bulk endpoint takes the whole batch at once. This test locks its
add/update(merge)/delete semantics and its auth.
"""
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from src.models import MeasureCache

pytestmark = pytest.mark.asyncio
TOKEN = {"X-Service-Token": "test-service-token"}


async def test_notify_bulk_add_update_delete(client, db):
    db.add_all([
        MeasureCache(module="vendor", source_id="A", entity_id="p", entity_name="old",
                     data={"source_id": "A", "title": "keep", "x": 1},
                     synced_at=datetime.now(timezone.utc)),
        MeasureCache(module="vendor", source_id="DEL", entity_id="p", entity_name="d",
                     data={"source_id": "DEL"}, synced_at=datetime.now(timezone.utc)),
    ])
    await db.commit()

    resp = await client.post("/api/measures/notify-bulk", headers=TOKEN, json={"entries": [
        {"module": "vendor", "source_id": "A", "entity_name": "newA", "x": 2},       # update (merge)
        {"module": "vendor", "source_id": "B", "entity_name": "newB", "title": "t"},  # add
        {"module": "vendor", "source_id": "DEL", "deleted": True},                    # delete
    ]})

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "added": 1, "updated": 1, "removed": 1}

    db.expire_all()
    rows = (await db.execute(
        select(MeasureCache).where(MeasureCache.module == "vendor")
    )).scalars().all()
    by = {r.source_id: r for r in rows}
    assert "DEL" not in by                       # deleted
    assert "B" in by                             # added
    # update is a MERGE, not a replace: the pre-existing title survives.
    assert by["A"].data["x"] == 2
    assert by["A"].data["title"] == "keep"
    assert by["A"].entity_name == "newA"


async def test_notify_bulk_rejects_bad_token(client):
    resp = await client.post("/api/measures/notify-bulk",
                             headers={"X-Service-Token": "wrong"}, json={"entries": []})
    assert resp.status_code == 403


async def test_notify_bulk_rejects_bad_shape(client):
    resp = await client.post("/api/measures/notify-bulk", headers=TOKEN, json={"entries": "nope"})
    assert resp.status_code == 400


def test_vendor_rename_uses_the_bulk_notifier():
    # projects.py must batch via notify_pilot_measures_bulk and no longer spawn
    # a per-measure notify_pilot_measure (the ...s_bulk( name is distinct).
    src = (Path(__file__).resolve().parents[3] / "vendor" / "src" / "routes" / "projects.py").read_text()
    assert "notify_pilot_measures_bulk" in src
    assert "ensure_future(notify_pilot_measure(" not in src
