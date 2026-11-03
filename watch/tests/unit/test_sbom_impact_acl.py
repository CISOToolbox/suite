"""Regression: the SBOM impact of an alert stays behind AppSec's access.

`GET /alerts/{id}/sbom-impact` asks AppSec with the service token, which
AppSec serves without any ACL, and relays its applications, packages,
versions and findings. Any Watch account that could see the alert got them.
The call is now made only for a caller who holds a role in AppSec (asked to
Pilot, fail-closed: the Watch session carries Watch's role only); anyone else
gets an empty answer flagged `forbidden`, and AppSec is not called.
"""
import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest

os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import appsec_client  # noqa: E402
from src.routes import alerts  # noqa: E402

_SCOPE = uuid.uuid4()
_ALERT = SimpleNamespace(id=uuid.uuid4(), source="nvd", external_id="CVE-2026-1234",
                         affected_json=[{"purl": "pkg:npm/lodash", "version_range": "<4.17.21"}])
_IMPACT = {"configured": True, "matched_findings": [{"application_id": "app-1"}],
           "matched_sbom": [{"package_name": "lodash"}], "applications": ["Patient portal"]}


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalar_one(self):
        return self._value


class _DB:
    """Loads the alert, then counts its matches in the caller's scopes."""

    def __init__(self):
        self._answers = [_ALERT, 1]

    async def execute(self, _stmt):
        return _Result(self._answers.pop(0))


@pytest.fixture
def impact(monkeypatch):
    calls = []

    async def _scopes(_db, _user):
        return {_SCOPE}

    async def _sbom(cve_id, affected):
        calls.append(cve_id)
        return dict(_IMPACT)

    monkeypatch.setattr(alerts, "_user_scope_ids", _scopes)
    monkeypatch.setattr(appsec_client, "is_configured", lambda: True)
    monkeypatch.setattr(appsec_client, "sbom_impact", _sbom)

    def _run(appsec_role):
        async def _role(_user, module):
            assert module == "appsec"
            return appsec_role
        monkeypatch.setattr(alerts, "sibling_module_role", _role, raising=False)
        user = SimpleNamespace(id=uuid.uuid4(), email="u@medsecure.example", role="user", _module_role="viewer")
        return asyncio.run(alerts.alert_sbom_impact(_ALERT.id, user, _DB())), calls
    return _run


def test_without_appsec_role_nothing_is_relayed(impact):
    out, calls = impact("")
    assert calls == []
    assert out["forbidden"] is True
    assert out["matched_findings"] == [] and out["matched_sbom"] == [] and out["applications"] == []


@pytest.mark.parametrize("role", ["viewer", "triager", "admin"])
def test_with_appsec_role_the_impact_is_shown(impact, role):
    out, calls = impact(role)
    assert calls == ["CVE-2026-1234"]
    assert out["applications"] == ["Patient portal"]
    assert not out.get("forbidden")
