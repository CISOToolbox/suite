"""Unit tests for the AppSec S2S client.

We focus on the graceful-degradation paths because the success path is
just `httpx.AsyncClient.post(...)` — covered indirectly by the live
docker-compose smoke test.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestIsConfigured:
    def test_missing_url(self, monkeypatch):
        monkeypatch.setattr("appsec_client.APPSEC_URL", "")
        monkeypatch.setattr("appsec_client.SERVICE_TOKEN", "secret")
        from appsec_client import is_configured
        assert not is_configured()

    def test_missing_token(self, monkeypatch):
        monkeypatch.setattr("appsec_client.APPSEC_URL", "http://appsec:8080")
        monkeypatch.setattr("appsec_client.SERVICE_TOKEN", "")
        from appsec_client import is_configured
        assert not is_configured()

    def test_both_set(self, monkeypatch):
        monkeypatch.setattr("appsec_client.APPSEC_URL", "http://appsec:8080")
        monkeypatch.setattr("appsec_client.SERVICE_TOKEN", "secret")
        from appsec_client import is_configured
        assert is_configured()


class TestSbomImpactDegradation:
    def test_unconfigured_returns_empty(self, monkeypatch):
        monkeypatch.setattr("appsec_client.APPSEC_URL", "")
        from appsec_client import sbom_impact
        data = _run(sbom_impact("CVE-2025-1", [{"product": "openssl"}]))
        assert data["configured"] is False
        assert data["matched_findings"] == []
        assert data["matched_sbom"] == []

    def test_transport_error_returns_unreachable(self, monkeypatch):
        monkeypatch.setattr("appsec_client.APPSEC_URL", "http://invalid-host-127001:1")
        monkeypatch.setattr("appsec_client.SERVICE_TOKEN", "secret")
        monkeypatch.setattr("appsec_client.TIMEOUT_S", 1.0)
        from appsec_client import sbom_impact
        data = _run(sbom_impact("CVE-2025-1", []))
        assert data.get("configured") is True
        assert data.get("error") == "appsec_unreachable"
        assert data["matched_findings"] == []
