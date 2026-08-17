"""Unit tests for the centralised connector framework.

Targets the helpers in ``src/connectors_common.py``:

* ``_mask`` — secret fields become the ``"configured"`` placeholder,
  empty secret fields stay empty.
* ``_apply_update`` — sending ``"configured"`` for a secret preserves
  the stored value (placeholder echo), unknown fields are ignored,
  empty string clears a non-secret value.
* ``_list_configured_connectors`` (in ``routes/settings.py``) —
  groups ``connector_<id>_<field>`` AppSettings rows by id.

These are the invariants Pilot pushes/displays on, so a regression here
would either leak a secret or silently nuke a user's config. They're
cheap to test in-process — no HTTP, no DB beyond the in-memory SQLite
already wired in ``conftest.py``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.connectors_common import (
    PLACEHOLDER,
    _apply_update,
    _is_configured,
    _mask,
)
from src.models import AppSettings


@pytest.fixture
def m365_schema() -> dict:
    """Load the on-disk schema used in production so the tests catch
    drift between the spec and the framework helpers."""
    path = Path(__file__).parent.parent.parent / "src" / "connector_schemas" / "m365.json"
    return json.loads(path.read_text())


# ── _mask ──────────────────────────────────────────────────────────


def test_mask_secret_with_value_returns_placeholder(m365_schema):
    raw = {
        "tenant_id": "tenant-guid",
        "client_id": "client-guid",
        "client_secret": "supersecret",
    }
    masked = _mask(m365_schema, raw)
    assert masked["client_secret"] == PLACEHOLDER
    assert masked["tenant_id"] == "tenant-guid"
    assert masked["client_id"] == "client-guid"


def test_mask_empty_secret_stays_empty(m365_schema):
    raw = {"tenant_id": "x", "client_id": "y", "client_secret": ""}
    masked = _mask(m365_schema, raw)
    assert masked["client_secret"] == ""


def test_mask_only_returns_schema_fields(m365_schema):
    raw = {"tenant_id": "x", "client_id": "y", "client_secret": "z", "extra": "ignored"}
    masked = _mask(m365_schema, raw)
    assert set(masked.keys()) == {"tenant_id", "client_id", "client_secret"}


# ── _is_configured ─────────────────────────────────────────────────


def test_is_configured_true_when_all_required_set(m365_schema):
    assert _is_configured(m365_schema, {
        "tenant_id": "x", "client_id": "y", "client_secret": "z"
    }) is True


def test_is_configured_false_when_any_required_missing(m365_schema):
    assert _is_configured(m365_schema, {
        "tenant_id": "x", "client_id": "", "client_secret": "z"
    }) is False
    assert _is_configured(m365_schema, {}) is False


# ── _apply_update ──────────────────────────────────────────────────


async def test_apply_update_writes_fields(db, m365_schema):
    await _apply_update("m365", m365_schema, {
        "tenant_id": "tenant-1",
        "client_id": "client-1",
        "client_secret": "secret-1",
    }, db)
    await db.commit()
    keys = {r.key: r.value for r in (await db.execute(
        __import__("sqlalchemy").select(AppSettings)
    )).scalars().all()}
    assert keys["connector_m365_tenant_id"] == "tenant-1"
    assert keys["connector_m365_client_id"] == "client-1"
    assert keys["connector_m365_client_secret"] == "secret-1"


async def test_apply_update_preserves_placeholder_for_secret(db, m365_schema):
    # Seed an existing secret
    db.add(AppSettings(key="connector_m365_client_secret", value="real-secret"))
    await db.commit()

    # Send the placeholder back — should be a no-op for the secret
    await _apply_update("m365", m365_schema, {
        "tenant_id": "tenant-2",
        "client_secret": PLACEHOLDER,
    }, db)
    await db.commit()

    keys = {r.key: r.value for r in (await db.execute(
        __import__("sqlalchemy").select(AppSettings)
    )).scalars().all()}
    assert keys["connector_m365_client_secret"] == "real-secret"
    assert keys["connector_m365_tenant_id"] == "tenant-2"


async def test_apply_update_ignores_unknown_fields(db, m365_schema):
    await _apply_update("m365", m365_schema, {
        "tenant_id": "tenant-3",
        "rogue_field": "should be ignored",
    }, db)
    await db.commit()

    keys = {r.key: r.value for r in (await db.execute(
        __import__("sqlalchemy").select(AppSettings)
    )).scalars().all()}
    assert "connector_m365_rogue_field" not in keys
    assert keys["connector_m365_tenant_id"] == "tenant-3"


async def test_apply_update_rejects_non_string(db, m365_schema):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        await _apply_update("m365", m365_schema, {"tenant_id": 42}, db)
    assert ei.value.status_code == 400


async def test_apply_update_partial_does_not_touch_other_fields(db, m365_schema):
    db.add(AppSettings(key="connector_m365_tenant_id", value="keep-me"))
    db.add(AppSettings(key="connector_m365_client_id", value="also-keep"))
    await db.commit()

    # Update only the secret
    await _apply_update("m365", m365_schema, {"client_secret": "new-secret"}, db)
    await db.commit()

    keys = {r.key: r.value for r in (await db.execute(
        __import__("sqlalchemy").select(AppSettings)
    )).scalars().all()}
    assert keys["connector_m365_tenant_id"] == "keep-me"
    assert keys["connector_m365_client_id"] == "also-keep"
    assert keys["connector_m365_client_secret"] == "new-secret"


# ── _list_configured_connectors (settings.py helper) ───────────────


async def test_list_configured_connectors_groups_by_id(db):
    from src.routes.settings import _list_configured_connectors

    for k, v in [
        ("connector_m365_tenant_id", "t"),
        ("connector_m365_client_id", "c"),
        ("connector_m365_client_secret", "s"),
        # unrelated app setting — must be skipped
        ("ai_key_anthropic", "ANTHROPIC-KEY"),
        # empty connector field — must be skipped
        ("connector_m365_optional", ""),
    ]:
        db.add(AppSettings(key=k, value=v))
    await db.commit()

    out = await _list_configured_connectors(db)
    assert set(out.keys()) == {"m365"}
    assert out["m365"] == {"tenant_id": "t", "client_id": "c", "client_secret": "s"}


async def test_list_configured_connectors_empty_when_nothing(db):
    from src.routes.settings import _list_configured_connectors
    out = await _list_configured_connectors(db)
    assert out == {}
