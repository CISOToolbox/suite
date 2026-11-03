"""Regression: syncing perimeters from Asset needs a role in Asset.

`POST /api/projects/{id}/applications/sync-asset` reads every Asset project
through Asset's internal export, with the service token, which Asset serves
without any ACL. Any Access editor could pull them. The route now asks Pilot
for the caller's role in Asset (`sibling_module_role`, fail-closed) and
refuses with 403, before any call to Asset, when there is none.
"""
import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import applications  # noqa: E402


class _Asset:
    """Stands in for httpx.AsyncClient; Asset has no project."""

    def __init__(self):
        self.calls = []

    def __call__(self, **_):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url, headers=None):
        self.calls.append(url)
        return SimpleNamespace(status_code=200, is_success=True, json=lambda: [],
                               raise_for_status=lambda: None)


@pytest.fixture
def sync(monkeypatch):
    asset = _Asset()
    monkeypatch.setattr(applications.httpx, "AsyncClient", asset)
    monkeypatch.setenv("ASSET_URL", "http://asset:8000")
    monkeypatch.setenv("SERVICE_TOKEN", "svc-token")

    async def _project(*_a, **_k):
        return SimpleNamespace(id=uuid.uuid4(), updated_at=None)

    monkeypatch.setattr(applications, "get_project_or_404", _project)

    def _run(asset_role):
        async def _role(_user, module):
            assert module == "asset"
            return asset_role
        monkeypatch.setattr(applications, "sibling_module_role", _role, raising=False)
        user = SimpleNamespace(id=uuid.uuid4(), email="marc.petit@medsecure.example",
                               role="user", _module_role="manager")
        result = asyncio.run(applications.sync_from_asset(uuid.uuid4(), user, None))
        return result, asset.calls
    return _run


def test_without_asset_role_asset_is_not_called(sync):
    with pytest.raises(HTTPException) as exc:
        sync("")
    assert exc.value.status_code == 403


def test_with_asset_role_the_sync_runs(sync):
    result, calls = sync("viewer")
    assert calls == ["http://asset:8000/api/internal/export"]
    assert result["imported"] == 0
