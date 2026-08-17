"""Unit tests for the v2 multi-instance flavor of the connectors
framework. The Pilot module itself only registers a singleton (M365),
so these tests use an in-process ``FakeBackend`` to exercise the
multi-instance code paths without needing the Access bridge live."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.connectors_common import (
    PLACEHOLDER,
    ConnectorBinding,
    MultiInstanceBackend,
    make_router,
)


pytestmark = pytest.mark.asyncio


SCHEMA = {
    "id": "fake",
    "name": {"fr": "Fake", "en": "Fake"},
    "cardinality": "many",
    "fields": [
        {"id": "host", "label": {"fr": "Host", "en": "Host"}, "required": True, "secret": False},
        {"id": "token", "label": {"fr": "Token", "en": "Token"}, "required": True, "secret": True},
    ],
    "capabilities": ["test", "run"],
}


class FakeBackend(MultiInstanceBackend):
    def __init__(self):
        # in-memory store: instance_id → {field_id: value}
        self.store: dict[str, dict[str, Any]] = {}

    async def list_instances(self, db):
        return [
            {
                "id": iid,
                "label": rec.get("label", ""),
                "configured": all(rec.get(f["id"]) for f in SCHEMA["fields"] if f.get("required")),
                "host": rec.get("host", ""),
                "token": PLACEHOLDER if rec.get("token") else "",
            }
            for iid, rec in self.store.items()
        ]

    async def get_instance(self, instance_id, db):
        rec = self.store.get(instance_id)
        if rec is None:
            return None
        return {
            "id": instance_id,
            "label": rec.get("label", ""),
            "configured": bool(rec.get("host") and rec.get("token")),
            "host": rec.get("host", ""),
            "token": PLACEHOLDER if rec.get("token") else "",
        }

    async def create_instance(self, body, db):
        iid = body.get("id") or f"inst-{len(self.store) + 1}"
        self.store[iid] = {k: body.get(k, "") for k in ("label", "host", "token")}
        return {"id": iid, **self.store[iid]}

    async def update_instance(self, instance_id, body, db):
        if instance_id not in self.store:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="not found")
        rec = self.store[instance_id]
        for k, v in body.items():
            if k == "token" and v == PLACEHOLDER:
                continue
            rec[k] = v

    async def delete_instance(self, instance_id, db):
        self.store.pop(instance_id, None)

    async def test_instance(self, instance_id, db):
        rec = self.store.get(instance_id)
        if rec is None:
            return False, "not found"
        return bool(rec.get("host") and rec.get("token")), "ok"

    async def run_instance(self, instance_id, db):
        return {"ran": instance_id, "store_size": len(self.store)}


@pytest.fixture
def fake_app():
    """Build a tiny FastAPI app with just the multi-instance router."""
    from src.auth import get_current_user, require_admin
    from src.database import get_db

    backend = FakeBackend()
    binding = ConnectorBinding(schema_dict=SCHEMA, backend=backend)

    app = FastAPI()
    app.include_router(make_router({"fake": binding}))

    # Stub auth — every request is admin
    async def _fake_user():
        return type("U", (), {"role": "admin"})()
    app.dependency_overrides[get_current_user] = _fake_user
    app.dependency_overrides[require_admin] = lambda: None
    # Stub DB — we don't touch it
    app.dependency_overrides[get_db] = lambda: None  # type: ignore[arg-type,return-value]
    return app, backend


async def test_list_empty(fake_app):
    app, _ = fake_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/connectors")
        assert r.status_code == 200
        items = r.json()["connectors"]
        assert len(items) == 1
        assert items[0]["cardinality"] == "many"
        assert items[0]["instances"] == []


async def test_create_then_list(fake_app):
    app, backend = fake_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/api/connectors/fake/instances",
            json={"label": "prod", "host": "h1.example.com", "token": "secret-1"},
        )
        assert r.status_code == 200
        iid = r.json()["id"]
        assert iid in backend.store

        r = await c.get(f"/api/connectors/fake/instances/{iid}")
        assert r.status_code == 200
        body = r.json()
        assert body["host"] == "h1.example.com"
        assert body["token"] == PLACEHOLDER  # secret masked
        assert body["configured"] is True


async def test_update_preserves_secret_placeholder(fake_app):
    app, backend = fake_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/api/connectors/fake/instances",
            json={"label": "prod", "host": "h1", "token": "real-secret"},
        )
        iid = r.json()["id"]

        # Send placeholder back — secret must NOT change
        r = await c.put(
            f"/api/connectors/fake/instances/{iid}",
            json={"host": "h2", "token": PLACEHOLDER},
        )
        assert r.status_code == 200
        assert backend.store[iid]["host"] == "h2"
        assert backend.store[iid]["token"] == "real-secret"


async def test_singleton_routes_reject_on_many(fake_app):
    """Calling a singleton route on a many connector must return 400."""
    app, _ = fake_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.put("/api/connectors/fake", json={"host": "x"})
        assert r.status_code == 400
        assert "multi-instance" in r.json()["detail"]

        r = await c.post("/api/connectors/fake/test")
        assert r.status_code == 400


async def test_delete_instance(fake_app):
    app, backend = fake_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/api/connectors/fake/instances",
            json={"label": "tmp", "host": "h", "token": "t"},
        )
        iid = r.json()["id"]
        assert iid in backend.store

        r = await c.delete(f"/api/connectors/fake/instances/{iid}")
        assert r.status_code == 200
        assert iid not in backend.store
