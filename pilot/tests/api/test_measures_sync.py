"""Perf regression: POST /api/measures/sync must keep add/update/remove
semantics after the concurrent-fetch + bulk-load rewrite.

The old handler fetched each module serially with a fresh httpx client and ran
a SELECT per incoming measure. It now fetches all modules concurrently over one
client and bulk-loads each module's existing rows into a dict (reused for the
stale purge). This test locks the observable behaviour the rewrite preserves.
"""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from src.models import MeasureCache, ModuleRegistry

pytestmark = pytest.mark.asyncio


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    @property
    def is_success(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._payload


class _FakeClient:
    """Stand-in for httpx.AsyncClient: routes .get() by URL fragment."""

    def __init__(self, by_fragment):
        self._by_fragment = by_fragment

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        for frag, payload in self._by_fragment.items():
            if frag in url:
                return _FakeResp(payload)
        return _FakeResp(None, status=404)


async def test_sync_add_update_remove(client, db):
    db.add_all([
        ModuleRegistry(id="risk", name="Risk", internal_url="http://risk-app:8080",
                       external_url="/risk/", status="active"),
        ModuleRegistry(id="vendor", name="Vendor", internal_url="http://vendor-app:8080",
                       external_url="/vendor/", status="active"),
    ])
    db.add_all([
        MeasureCache(module="risk", source_id="A", entity_id="e", entity_name="old",
                     data={"source_id": "A", "x": 1}, synced_at=datetime.now(timezone.utc)),
        MeasureCache(module="risk", source_id="STALE", entity_id="e", entity_name="stale",
                     data={"source_id": "STALE"}, synced_at=datetime.now(timezone.utc)),
    ])
    await db.commit()

    responses = {
        "risk-app": [
            {"source_id": "A", "entity_name": "newA", "x": 2},   # update
            {"source_id": "B", "entity_name": "newB"},           # add
        ],
        "vendor-app": [
            {"source_id": "V1", "entity_name": "v"},             # add
        ],
    }
    with patch("src.routes.measures.httpx.AsyncClient", lambda *a, **k: _FakeClient(responses)):
        resp = await client.post("/api/measures/sync")

    assert resp.status_code == 200
    report = resp.json()
    assert report["risk"] == {"added": 1, "updated": 1, "removed": 1}
    assert report["vendor"] == {"added": 1, "updated": 0, "removed": 0}

    db.expire_all()  # drop identity-map copies mutated in the request session
    rows = (await db.execute(select(MeasureCache))).scalars().all()
    by_key = {(r.module, r.source_id): r for r in rows}
    assert ("risk", "STALE") not in by_key            # purged
    assert by_key[("risk", "A")].data["x"] == 2       # updated in place
    assert by_key[("risk", "A")].entity_name == "newA"
    assert ("risk", "B") in by_key                    # added
    assert ("vendor", "V1") in by_key                 # added
