"""API tests for /api/measure-groups (FEAT-11 meta-measures).

Members are seeded as module="pilot" cache rows so propagation only touches
the cache (no external write-back in tests); one test uses an unregistered
module to assert the propagation error surfaces instead of failing silently.
"""
from __future__ import annotations

import pytest

from src.models import MeasureCache

pytestmark = pytest.mark.anyio


async def _seed(db, n=2, module="pilot", status="planned"):
    rows = []
    for i in range(n):
        mc = MeasureCache(module=module, source_id=f"MES-{i+1:03d}",
                          entity_id="", entity_name="",
                          data={"title": f"Mesure {i+1}", "status": status,
                                "assignee": "", "due_date": ""})
        db.add(mc)
        rows.append(mc)
    await db.commit()
    for mc in rows:
        await db.refresh(mc)
    return rows


async def test_create_group_and_canonical_defaults(client, db):
    a, b = await _seed(db)
    resp = await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)], "title": "Groupe test"})
    assert resp.status_code == 201
    g = resp.json()
    assert g["title"] == "Groupe test"
    assert g["status"] == "planned"
    assert len(g["members"]) == 2
    assert g["propagation_errors"] == []


async def test_group_needs_two_measures(client, db):
    (a,) = await _seed(db, n=1)
    resp = await client.post("/api/measure-groups", json={"measure_ids": [str(a.id)]})
    assert resp.status_code == 422


async def test_one_group_per_measure_invariant(client, db):
    a, b, c = await _seed(db, n=3)
    r1 = await client.post("/api/measure-groups", json={"measure_ids": [str(a.id), str(b.id)]})
    assert r1.status_code == 201
    r2 = await client.post("/api/measure-groups", json={"measure_ids": [str(a.id), str(c.id)]})
    assert r2.status_code == 409


async def test_patch_propagates_to_members(client, db):
    a, b = await _seed(db)
    g = (await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})).json()
    resp = await client.patch(f"/api/measure-groups/{g['id']}", json={
        "status": "in_progress", "responsible": "CISO"})
    assert resp.status_code == 200
    out = resp.json()
    assert out["status"] == "in_progress"
    for mm in out["members"]:
        assert mm["status"] == "in_progress"
        assert mm["assignee"] == "CISO"


async def test_unregistered_module_surfaces_propagation_error(client, db):
    a, b = await _seed(db, module="ghostmod", status="backlog")
    resp = await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})
    assert resp.status_code == 201
    g = resp.json()
    r2 = await client.patch(f"/api/measure-groups/{g['id']}", json={"status": "completed"})
    errs = r2.json()["propagation_errors"]
    assert len(errs) == 2 and all("not registered" in e["error"] for e in errs)


async def test_detach_below_two_dissolves(client, db):
    a, b = await _seed(db)
    g = (await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})).json()
    resp = await client.delete(f"/api/measure-groups/{g['id']}/members/{str(a.id)}")
    assert resp.status_code == 200
    assert resp.json()["dissolved"] is True
    assert (await client.get("/api/measure-groups")).json() == []


async def test_dissolve_frees_members(client, db):
    a, b = await _seed(db)
    g = (await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})).json()
    assert (await client.delete(f"/api/measure-groups/{g['id']}")).status_code == 204
    r = await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})
    assert r.status_code == 201


async def test_failed_writeback_keeps_cache_divergent_and_resync_retries(client, db):
    """A transient write-back failure must NOT update the cache: with an
    optimistically-updated cache the next propagation skipped the member as
    'already equal' and the divergence became unrepairable (found live —
    stale-tab blob revert scenario). Resync forces the re-push."""
    a, b = await _seed(db, module="ghostmod")  # unregistered → write-back fails
    g = (await client.post("/api/measure-groups", json={
        "measure_ids": [str(a.id), str(b.id)]})).json()
    r = await client.patch(f"/api/measure-groups/{g['id']}", json={"status": "completed"})
    assert len(r.json()["propagation_errors"]) == 2
    # Cache must still hold the OLD value (divergence stays visible/retryable)
    for mm in r.json()["members"]:
        assert mm["status"] == "planned"
    # Resync retries even though canonical == last attempt (force bypass)
    r2 = await client.post(f"/api/measure-groups/{g['id']}/resync")
    assert len(r2.json()["propagation_errors"]) == 2
