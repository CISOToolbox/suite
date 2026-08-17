"""Integration tests for /api/measures endpoints."""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.anyio


async def _proj(client) -> str:
    """Pilot-native measures must attach to a remediation project."""
    r = await client.post("/api/projects", json={"name": "Test project"})
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]



async def test_create_measure_happy_path(client):
    pid = await _proj(client)
    resp = await client.post("/api/measures", json={
        "title": "Enable MFA on all admin accounts",
        "status": "planned",
        "assignee": "security-team",
        "due_date": "2026-06-01",
        "project_id": pid,
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Enable MFA on all admin accounts"
    assert data["status"] == "planned"
    assert data["module"] == "pilot"
    assert data["source_id"].startswith("MES-")
    assert data["assignee"] == "security-team"
    assert "id" in data


async def test_create_measure_minimal(client):
    """Only title is required."""
    pid = await _proj(client)
    resp = await client.post("/api/measures", json={"title": "Rotate API keys", "project_id": pid})
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Rotate API keys"
    assert data["status"] == "planned"  # default


async def test_create_measure_missing_title(client):
    pid = await _proj(client)
    resp = await client.post("/api/measures", json={"status": "planned", "project_id": pid})
    assert resp.status_code == 422  # Pydantic validation error


async def test_create_measure_invalid_status(client):
    pid = await _proj(client)
    resp = await client.post("/api/measures", json={
        "title": "Test", "status": "done",
        "project_id": pid,
    })
    assert resp.status_code == 422


async def test_list_measures_empty(client):
    resp = await client.get("/api/measures")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_measures_returns_created(client):
    pid = await _proj(client)
    await client.post("/api/measures", json={"title": "M1", "project_id": pid})
    await client.post("/api/measures", json={"title": "M2", "status": "completed", "project_id": pid})
    resp = await client.get("/api/measures")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2


async def test_list_measures_filter_by_status(client):
    pid = await _proj(client)
    await client.post("/api/measures", json={"title": "A", "status": "planned", "project_id": pid})
    await client.post("/api/measures", json={"title": "B", "status": "completed", "project_id": pid})
    resp = await client.get("/api/measures", params={"status": "completed"})
    items = resp.json()
    assert len(items) == 1
    assert items[0]["title"] == "B"


async def test_list_measures_filter_by_module(client):
    pid = await _proj(client)
    await client.post("/api/measures", json={"title": "Pilot measure", "project_id": pid})
    resp = await client.get("/api/measures", params={"module": "pilot"})
    items = resp.json()
    assert len(items) == 1
    resp2 = await client.get("/api/measures", params={"module": "risk"})
    assert resp2.json() == []


async def test_patch_measure_status(client):
    pid = await _proj(client)
    create_resp = await client.post("/api/measures", json={"title": "Patch", "project_id": pid})
    mid = create_resp.json()["id"]
    resp = await client.patch(f"/api/measures/{mid}", json={"status": "in_progress"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    # Verify updated
    items = await client.get("/api/measures", params={"status": "in_progress"})
    assert any(m["id"] == mid for m in items.json())


async def test_patch_measure_assignee(client):
    pid = await _proj(client)
    create_resp = await client.post("/api/measures", json={"title": "Assign test", "project_id": pid})
    mid = create_resp.json()["id"]
    resp = await client.patch(f"/api/measures/{mid}", json={"assignee": "alice"})
    assert resp.status_code == 200

    items = await client.get("/api/measures")
    measure = next(m for m in items.json() if m["id"] == mid)
    assert measure["assignee"] == "alice"


async def test_patch_measure_due_date(client):
    pid = await _proj(client)
    create_resp = await client.post("/api/measures", json={"title": "Due test", "project_id": pid})
    mid = create_resp.json()["id"]
    resp = await client.patch(f"/api/measures/{mid}", json={"due_date": "2026-12-31"})
    assert resp.status_code == 200

    items = await client.get("/api/measures")
    measure = next(m for m in items.json() if m["id"] == mid)
    assert measure["due_date"] == "2026-12-31"


async def test_patch_measure_title(client):
    pid = await _proj(client)
    create_resp = await client.post("/api/measures", json={"title": "Old", "project_id": pid})
    mid = create_resp.json()["id"]
    await client.patch(f"/api/measures/{mid}", json={"title": "New"})

    items = await client.get("/api/measures")
    measure = next(m for m in items.json() if m["id"] == mid)
    assert measure["title"] == "New"


async def test_patch_measure_not_found(client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.patch(f"/api/measures/{fake_id}", json={"status": "completed"})
    assert resp.status_code == 404


async def test_delete_pilot_measure(client):
    pid = await _proj(client)
    create_resp = await client.post("/api/measures", json={"title": "To delete", "project_id": pid})
    mid = create_resp.json()["id"]
    resp = await client.delete(f"/api/measures/{mid}")
    assert resp.status_code == 204

    # Verify gone
    items = await client.get("/api/measures")
    assert not any(m["id"] == mid for m in items.json())


async def test_delete_module_measure_propagates(client, db):
    """Deleting a module measure is allowed: Pilot writes the deletion back
    to the source module, then purges its cache (policy change — the old
    behaviour was a 403). The module being unregistered in tests, only the
    cache purge is observable."""
    from src.models import MeasureCache
    from datetime import datetime, timezone

    mc = MeasureCache(
        module="risk",
        source_id="RISK-001",
        entity_id="ent-1",
        entity_name="MedSecure Risk Analysis",
        data={"title": "From risk module", "status": "planned"},
        synced_at=datetime.now(timezone.utc),
    )
    db.add(mc)
    await db.commit()
    await db.refresh(mc)

    resp = await client.delete(f"/api/measures/{mc.id}")
    assert resp.status_code == 204


async def test_delete_measure_not_found(client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"/api/measures/{fake_id}")
    assert resp.status_code == 404


async def test_notify_valid_token(client):
    resp = await client.post(
        "/api/measures/notify",
        json={
            "module": "compliance",
            "source_id": "COMP-42",
            "entity_id": "e1",
            "entity_name": "ISO 27001 Audit",
            "title": "Implement logging",
            "status": "in_progress",
        },
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    # Verify the measure was cached
    items = await client.get("/api/measures", params={"module": "compliance"})
    assert len(items.json()) == 1
    assert items.json()[0]["source_id"] == "COMP-42"


async def test_notify_updates_existing(client):
    """Second notify with same module+source_id updates instead of creating."""
    headers = {"X-Service-Token": "test-service-token"}
    await client.post("/api/measures/notify", json={
        "module": "vendor", "source_id": "VND-1",
        "title": "Original", "status": "planned",
    }, headers=headers)

    await client.post("/api/measures/notify", json={
        "module": "vendor", "source_id": "VND-1",
        "title": "Updated", "status": "completed",
    }, headers=headers)

    items = await client.get("/api/measures", params={"module": "vendor"})
    assert len(items.json()) == 1
    assert items.json()[0]["status"] == "completed"


async def test_notify_invalid_token(client):
    resp = await client.post(
        "/api/measures/notify",
        json={"module": "risk", "source_id": "R-1"},
        headers={"X-Service-Token": "wrong-token"},
    )
    assert resp.status_code == 403


async def test_notify_missing_token(client):
    resp = await client.post(
        "/api/measures/notify",
        json={"module": "risk", "source_id": "R-1"},
    )
    assert resp.status_code == 403


async def test_notify_missing_fields(client):
    resp = await client.post(
        "/api/measures/notify",
        json={"module": "risk"},  # missing source_id
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 400


async def test_notify_missing_module(client):
    resp = await client.post(
        "/api/measures/notify",
        json={"source_id": "X-1"},  # missing module
        headers={"X-Service-Token": "test-service-token"},
    )
    assert resp.status_code == 400


async def test_sync_requires_admin(client):
    """POST /api/measures/sync requires admin role.
    Our fixture mocks require_admin as no-op, so it should succeed."""
    resp = await client.post("/api/measures/sync")
    assert resp.status_code == 200
    # With no modules registered, the report is empty
    assert resp.json() == {}


# ═══════════════════════════════════════════════════════════════════════
# Phase 6b — notify merge behavior + vendor_name propagation
# ═══════════════════════════════════════════════════════════════════════

async def test_notify_merge_preserves_existing_data(client):
    """A partial notify must merge into existing cache data rather than
    replace it, so fields not sent (entity_name, description, vendor_name)
    stay intact across updates.
    Regression: pre-fix, mc.data = body wiped fields on every notify."""
    token = "test-service-token"
    # First notify: full create payload (as if from /sync)
    resp = await client.post(
        "/api/measures/notify",
        headers={"X-Service-Token": token},
        json={
            "module": "vendor",
            "source_id": "VM-MERGE-001",
            "title": "Vendor measure 1",
            "description": "Full description",
            "entity_name": "MedSecure / ACME Corp",
            "vendor_id": "V-001",
            "vendor_name": "ACME Corp",
            "status": "planned",
            "assignee": "alice",
            "due_date": "2026-06-01",
        },
    )
    assert resp.status_code == 200

    # Second notify: partial patch (only status change, like after a
    # frontend edit that only touched one field)
    resp = await client.post(
        "/api/measures/notify",
        headers={"X-Service-Token": token},
        json={
            "module": "vendor",
            "source_id": "VM-MERGE-001",
            "status": "in_progress",
        },
    )
    assert resp.status_code == 200

    # Cache should still carry the fields that weren't in the partial patch
    items = (await client.get("/api/measures")).json()
    row = next(m for m in items if m["source_id"] == "VM-MERGE-001")
    assert row["status"] == "in_progress"             # updated
    assert row["title"] == "Vendor measure 1"         # preserved
    assert row["description"] == "Full description"   # preserved
    assert row["entity_name"] == "MedSecure / ACME Corp"  # preserved
    assert row["vendor_name"] == "ACME Corp"          # preserved
    assert row["vendor_id"] == "V-001"                # preserved
    assert row["assignee"] == "alice"                 # preserved


async def test_list_exposes_vendor_fields(client):
    """/api/measures list must expose vendor_id + vendor_name so the
    Pilot frontend can show the supplier in the Entité column."""
    resp = await client.post(
        "/api/measures/notify",
        headers={"X-Service-Token": "test-service-token"},
        json={
            "module": "vendor",
            "source_id": "VM-LIST-001",
            "title": "Audit vendor",
            "vendor_id": "V-042",
            "vendor_name": "Globex",
            "entity_name": "MedSecure / Globex",
        },
    )
    assert resp.status_code == 200

    items = (await client.get("/api/measures")).json()
    row = next(m for m in items if m["source_id"] == "VM-LIST-001")
    # Fields added in Phase 6b
    assert "vendor_id" in row
    assert "vendor_name" in row
    assert row["vendor_id"] == "V-042"
    assert row["vendor_name"] == "Globex"


async def test_notify_without_vendor_fields_defaults_to_empty(client):
    """Non-vendor modules (compliance, access) don't send vendor_*.
    The list response should still expose the keys with empty strings
    so frontend renderers don't have to null-check."""
    resp = await client.post(
        "/api/measures/notify",
        headers={"X-Service-Token": "test-service-token"},
        json={
            "module": "compliance",
            "source_id": "CM-LIST-001",
            "title": "Compliance measure",
            "entity_name": "MedSecure",
        },
    )
    assert resp.status_code == 200

    items = (await client.get("/api/measures")).json()
    row = next(m for m in items if m["source_id"] == "CM-LIST-001")
    assert row["vendor_id"] == ""
    assert row["vendor_name"] == ""
    # But entity_name must still be there (societe for compliance)
    assert row["entity_name"] == "MedSecure"
