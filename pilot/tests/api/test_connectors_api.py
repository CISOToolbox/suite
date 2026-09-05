"""API tests for the connectors framework + Pilot aggregator.

The unit tests (``tests/unit/test_connectors_common.py``) cover the
data-manipulation helpers in isolation. These tests exercise the HTTP
surface — specifically the **authorization matrix** that motivated the
chantier security review:

* Browser admin user must be able to read/write connectors locally.
* Service-token caller (Pilot back-to-back) must be able to read.
* Service-token caller must be able to write via the ``/internal``
  bypass route.
* Anyone missing both credentials gets 401/403.

Secrets are masked at the framework level (validated in unit tests),
so the API tests focus purely on access control."""
from __future__ import annotations

from unittest.mock import patch

import pytest


pytestmark = pytest.mark.asyncio


SERVICE_TOKEN_HEADER = {"X-Service-Token": "test-service-token"}


# ── Module-side framework routes ──────────────────────────────────


async def test_get_connectors_with_admin_user(client):
    """The default ``client`` fixture installs an admin override —
    list should succeed and contain m365."""
    r = await client.get("/api/connectors")
    assert r.status_code == 200
    body = r.json()
    assert "managed" in body
    ids = [c["id"] for c in body["connectors"]]
    assert "m365" in ids


async def test_get_connectors_with_service_token(client):
    """Drop admin override, present a service token — must still pass."""
    from src.auth import get_current_user, require_admin
    from src.main import app
    # Remove user-auth overrides for this test so the dual-auth helper
    # has to walk the service-token branch.
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(require_admin, None)
    try:
        r = await client.get("/api/connectors", headers=SERVICE_TOKEN_HEADER)
        assert r.status_code == 200
        assert "m365" in [c["id"] for c in r.json()["connectors"]]
    finally:
        app.dependency_overrides.update(saved)


# NB: the "anonymous → 401" case is not testable here because the test
# harness sets AUTH_MODE=none (see tests/conftest.py), which intentionally
# disables auth across the whole app. The 401 gate is verified manually
# against a running stack (AUTH_MODE=pilot) — every connector route
# returned 401 without a session in the step 5 smoke check.


async def test_get_secret_field_is_masked(client, db):
    """Even with admin auth, a configured secret must come back as the
    placeholder ``"configured"``, never as the stored value."""
    from src.models import AppSettings
    db.add(AppSettings(key="connector_m365_client_secret", value="ULTRA-SECRET"))
    await db.commit()

    r = await client.get("/api/connectors/m365")
    assert r.status_code == 200
    body = r.json()
    assert body["client_secret"] == "configured"
    assert "ULTRA-SECRET" not in r.text  # no leak anywhere in the payload


# ── Internal push route ───────────────────────────────────────────


async def test_internal_put_requires_service_token(client):
    r = await client.put("/api/internal/connectors/m365", json={"tenant_id": "x"})
    assert r.status_code == 403


async def test_internal_put_with_valid_token_writes(client, db):
    from src.models import AppSettings
    r = await client.put(
        "/api/internal/connectors/m365",
        headers=SERVICE_TOKEN_HEADER,
        json={"tenant_id": "pushed-by-pilot", "client_id": "cid", "client_secret": "csec"},
    )
    assert r.status_code == 200
    # Read back via DB — confirms the write landed
    from sqlalchemy import select
    rows = (await db.execute(select(AppSettings))).scalars().all()
    keys = {r.key: r.value for r in rows}
    assert keys["connector_m365_tenant_id"] == "pushed-by-pilot"
    assert keys["connector_m365_client_secret"] == "csec"


async def test_internal_put_with_bad_token_returns_403(client):
    r = await client.put(
        "/api/internal/connectors/m365",
        headers={"X-Service-Token": "wrong"},
        json={"tenant_id": "x"},
    )
    assert r.status_code == 403


# ── Managed mode behaviour ────────────────────────────────────────


async def test_put_user_blocked_in_managed_mode(client):
    """When CONNECTORS_MANAGED_BY_PILOT is on, the user-facing PUT must
    return 403 — the only way to write is via the /internal route from
    Pilot."""
    with patch("src.connectors_common.MANAGED", True):
        r = await client.put(
            "/api/connectors/m365",
            json={"tenant_id": "x"},
        )
        assert r.status_code == 403
        assert "managed" in r.json()["detail"].lower()


async def test_internal_put_still_works_in_managed_mode(client):
    """Service-token push is the escape hatch — must always work,
    regardless of the managed flag."""
    with patch("src.connectors_common.MANAGED", True):
        r = await client.put(
            "/api/internal/connectors/m365",
            headers=SERVICE_TOKEN_HEADER,
            json={"tenant_id": "from-pilot"},
        )
        assert r.status_code == 200


async def test_managed_flag_surfaces_in_list_response(client):
    with patch("src.connectors_common.MANAGED", True):
        r = await client.get("/api/connectors")
        assert r.status_code == 200
        assert r.json()["managed"] is True


# ── Aggregator routes ─────────────────────────────────────────────


async def test_aggregate_lists_local_connector(client):
    """Pilot aggregator should include its own M365 binding even with
    no remote modules to query (the test setup has no module_registry
    entries)."""
    r = await client.get("/api/admin/connectors")
    assert r.status_code == 200
    body = r.json()
    m365 = next((c for c in body["connectors"] if c["id"] == "m365"), None)
    assert m365 is not None
    assert "pilot" in m365["consumers"]


async def test_aggregate_put_writes_pilot_local(client, db):
    from sqlalchemy import select
    from src.models import AppSettings

    r = await client.put(
        "/api/admin/connectors/m365",
        json={"tenant_id": "via-agg", "client_id": "cid", "client_secret": "csec"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["report"]["pilot"] == "ok"

    rows = (await db.execute(select(AppSettings))).scalars().all()
    assert any(r.key == "connector_m365_tenant_id" and r.value == "via-agg" for r in rows)


async def test_aggregate_get_unknown_returns_404(client):
    r = await client.get("/api/admin/connectors/does-not-exist")
    assert r.status_code == 404
