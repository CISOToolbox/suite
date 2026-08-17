"""Integration tests for /api/projects endpoints."""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.anyio


async def _proj(client) -> str:
    """Pilot-native measures must attach to a remediation project."""
    r = await client.post("/api/projects", json={"name": "Seed project"})
    return r.json()["id"]



async def test_list_projects_empty(client):
    resp = await client.get("/api/projects")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_create_project_happy_path(client):
    resp = await client.post("/api/projects", json={
        "name": "MedSecure ISMS Rollout",
        "priority": "high",
        "description": "Deploy ISMS across all business units",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "MedSecure ISMS Rollout"
    assert data["priority"] == "high"
    assert data["description"] == "Deploy ISMS across all business units"
    assert data["status"] == "planned"  # default
    assert "id" in data
    assert data["measures_total"] == 0
    assert data["progress"] == 0


async def test_create_project_minimal(client):
    resp = await client.post("/api/projects", json={"name": "Quick project"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Quick project"
    assert data["priority"] == "medium"  # default


async def test_create_project_missing_name(client):
    resp = await client.post("/api/projects", json={"priority": "high"})
    assert resp.status_code == 422  # Pydantic validation


async def test_create_project_empty_name(client):
    resp = await client.post("/api/projects", json={"name": "   "})
    assert resp.status_code == 400  # route-level validation


async def test_create_project_with_tags(client):
    resp = await client.post("/api/projects", json={
        "name": "Tagged", "tags": ["iso27001", "urgent"],
    })
    assert resp.status_code == 201
    assert resp.json()["tags"] == ["iso27001", "urgent"]


async def test_create_project_with_dates(client):
    resp = await client.post("/api/projects", json={
        "name": "Dated",
        "start_date": "2026-01-01",
        "due_date": "2026-12-31",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["start_date"] == "2026-01-01"
    assert data["due_date"] == "2026-12-31"


async def test_list_projects_returns_created(client):
    await client.post("/api/projects", json={"name": "P1"})
    await client.post("/api/projects", json={"name": "P2"})
    resp = await client.get("/api/projects")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


async def test_get_project_by_id(client):
    create_resp = await client.post("/api/projects", json={"name": "Detail"})
    pid = create_resp.json()["id"]
    resp = await client.get(f"/api/projects/{pid}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "Detail"


async def test_get_project_not_found(client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/api/projects/{fake_id}")
    assert resp.status_code == 404


async def test_update_project(client):
    create_resp = await client.post("/api/projects", json={"name": "Before"})
    pid = create_resp.json()["id"]
    resp = await client.put(f"/api/projects/{pid}", json={
        "name": "After", "priority": "critical",
    })
    assert resp.status_code == 200
    assert resp.json()["name"] == "After"
    assert resp.json()["priority"] == "critical"


async def test_update_project_completed_sets_date(client):
    """Setting status to 'completed' auto-fills completed_date."""
    create_resp = await client.post("/api/projects", json={"name": "Finish me"})
    pid = create_resp.json()["id"]
    resp = await client.put(f"/api/projects/{pid}", json={"status": "completed"})
    assert resp.status_code == 200
    assert resp.json()["completed_date"] != ""


async def test_assign_measures_to_project(client):
    pid = await _proj(client)
    # Create a project
    proj_resp = await client.post("/api/projects", json={"name": "With measures"})
    pid = proj_resp.json()["id"]

    # Create two measures
    m1 = await client.post("/api/measures", json={"title": "M1", "status": "planned", "project_id": pid})
    m2 = await client.post("/api/measures", json={"title": "M2", "status": "completed", "project_id": pid})
    m1_id = m1.json()["id"]
    m2_id = m2.json()["id"]

    # Assign measures
    resp = await client.post(f"/api/projects/{pid}/measures", json={
        "measure_ids": [m1_id, m2_id],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["measures_total"] == 2
    assert data["measures_completed"] == 1
    assert data["progress"] == 50


async def test_assign_measures_idempotent(client):
    pid = await _proj(client)
    """Assigning the same measure twice does not duplicate it."""
    proj_resp = await client.post("/api/projects", json={"name": "Idempotent"})
    pid = proj_resp.json()["id"]
    m = await client.post("/api/measures", json={"title": "Only once", "project_id": pid})
    mid = m.json()["id"]

    await client.post(f"/api/projects/{pid}/measures", json={"measure_ids": [mid]})
    resp = await client.post(f"/api/projects/{pid}/measures", json={"measure_ids": [mid]})
    assert resp.json()["measures_total"] == 1


async def test_assign_invalid_measure_id_skipped(client):
    """Non-existent measure IDs are silently skipped."""
    proj_resp = await client.post("/api/projects", json={"name": "Skip bad"})
    pid = proj_resp.json()["id"]
    resp = await client.post(f"/api/projects/{pid}/measures", json={
        "measure_ids": ["00000000-0000-0000-0000-000000000000"],
    })
    assert resp.status_code == 200
    assert resp.json()["measures_total"] == 0


async def test_assign_malformed_uuid_skipped(client):
    """Malformed UUIDs are silently skipped."""
    proj_resp = await client.post("/api/projects", json={"name": "Bad UUID"})
    pid = proj_resp.json()["id"]
    resp = await client.post(f"/api/projects/{pid}/measures", json={
        "measure_ids": ["not-a-uuid"],
    })
    assert resp.status_code == 200
    assert resp.json()["measures_total"] == 0


async def test_unassign_measure(client):
    pid = await _proj(client)
    proj_resp = await client.post("/api/projects", json={"name": "Unassign"})
    pid = proj_resp.json()["id"]
    m = await client.post("/api/measures", json={"title": "Remove me", "project_id": pid})
    mid = m.json()["id"]
    await client.post(f"/api/projects/{pid}/measures", json={"measure_ids": [mid]})

    resp = await client.delete(f"/api/projects/{pid}/measures/{mid}")
    assert resp.status_code == 200

    proj = await client.get(f"/api/projects/{pid}")
    assert proj.json()["measures_total"] == 0


async def test_delete_project(client):
    create_resp = await client.post("/api/projects", json={"name": "Delete me"})
    pid = create_resp.json()["id"]
    resp = await client.delete(f"/api/projects/{pid}")
    assert resp.status_code == 204

    # Verify gone
    get_resp = await client.get(f"/api/projects/{pid}")
    assert get_resp.status_code == 404


async def test_delete_project_cascade_removes_links(client):
    pid = await _proj(client)
    """Deleting a project also removes its project_measures links."""
    proj_resp = await client.post("/api/projects", json={"name": "Cascade"})
    pid = proj_resp.json()["id"]
    m = await client.post("/api/measures", json={"title": "Linked", "project_id": pid})
    mid = m.json()["id"]
    await client.post(f"/api/projects/{pid}/measures", json={"measure_ids": [mid]})

    resp = await client.delete(f"/api/projects/{pid}")
    assert resp.status_code == 204

    # The measure itself still exists (only the link is removed)
    items = await client.get("/api/measures")
    assert any(m["id"] == mid for m in items.json())


async def test_delete_project_not_found(client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"/api/projects/{fake_id}")
    assert resp.status_code == 404
