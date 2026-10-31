"""A restore session the module cannot read is reported, not swallowed.

When the agent has the restored instance ready but the module fails to read
it (typically a point in time before a database password change), the
status route used to fail with a 502 that the screen retried silently, so
the session looked stuck in "preparing". It now answers "unreadable" — but
only when the module itself failed: an unreachable or unknown module is a
different problem and stays an error.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from src.routes import restore


class _Module:
    """Stands in for the module's HTTP API behind httpx."""

    def __init__(self, status=None, body="", error=None):
        self.status, self.body, self.error = status, body, error

    def client(self, *a, **kw):
        module = self

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, headers=None):
                if module.error:
                    raise module.error
                return httpx.Response(module.status, text=module.body,
                                      request=httpx.Request("GET", url))
        return Client()


@pytest.fixture
def ready(monkeypatch):
    async def agent(method, path, body=None):
        return {"module": "risk", "status": "ready", "time": "2026-10-26 17:00:00+00"}

    async def module_url(db, module):
        return "http://risk-app:8080"

    monkeypatch.setattr(restore, "require_admin", lambda user: None)
    monkeypatch.setattr(restore, "_agent", agent)
    monkeypatch.setattr(restore, "_module_url", module_url)

    def run(module_double):
        monkeypatch.setattr(restore.httpx, "AsyncClient", module_double.client)
        return asyncio.run(restore.session_status("risk", user=SimpleNamespace(id=1), db=None))
    return run


def test_a_module_failing_to_read_the_instance_is_reported_as_unreadable(ready):
    # What a module without an exception handler really answers.
    out = ready(_Module(500, "Internal Server Error"))
    assert out["status"] == "unreadable"
    assert "500" in out["error"] and out["time"] == "2026-10-26 17:00:00+00"


def test_an_unknown_module_endpoint_stays_an_error(ready):
    with pytest.raises(HTTPException) as e:
        ready(_Module(404, "Not Found"))
    assert e.value.status_code == 502


def test_an_unreachable_module_stays_an_error(ready):
    with pytest.raises(httpx.ConnectError):
        ready(_Module(error=httpx.ConnectError("All connection attempts failed")))


def test_a_preparing_session_is_passed_through(monkeypatch):
    async def agent(method, path, body=None):
        return {"module": "risk", "status": "preparing"}

    async def module_url(db, module):  # pragma: no cover — must not be reached
        raise AssertionError("the module is only asked once the agent is ready")

    monkeypatch.setattr(restore, "require_admin", lambda user: None)
    monkeypatch.setattr(restore, "_agent", agent)
    monkeypatch.setattr(restore, "_module_url", module_url)
    out = asyncio.run(restore.session_status("risk", user=SimpleNamespace(id=1), db=None))
    assert out["status"] == "preparing"
