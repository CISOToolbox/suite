"""Lock the docker_images validator that prevents `trivy image` argument
injection (an image ref starting with '-' would be parsed as a flag)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import schemas  # noqa: E402
from src.schemas import ApplicationCreate, ApplicationUpdate  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_resolver(monkeypatch):
    """Stub the registry resolution so these tests never touch DNS.

    The validator resolves the registry host and fails closed on an
    unresolvable name — correct behaviour, but it made the suite depend on a
    live network, and the RFC 2606 host below does not resolve anywhere by
    design. Internal targets are covered by their own test.
    """
    monkeypatch.setattr(schemas, "resolve_safe_target", lambda host, **kw: "203.0.113.10")


class TestDockerImageValidation:
    def test_valid_refs_accepted(self):
        imgs = ["nginx:alpine", "ghcr.io/org/app:v1.2.3",
                "registry.example.com:5000/team/svc@sha256:" + "a" * 64]
        app = ApplicationCreate(name="x", docker_images=imgs)
        assert app.docker_images == imgs

    def test_internal_registry_rejected(self, monkeypatch):
        def _blocked(host, **kw):
            raise ValueError(f"{host} resolves to an internal address")
        monkeypatch.setattr(schemas, "resolve_safe_target", _blocked)
        for bad in ["169.254.169.254/x", "10.0.0.5:5000/team/svc:1"]:
            with pytest.raises(ValueError):
                ApplicationCreate(name="x", docker_images=[bad])

    def test_docker_hub_refs_skip_resolution(self, monkeypatch):
        # No registry component => Docker Hub, nothing to resolve.
        def _boom(host, **kw):
            raise AssertionError(f"should not resolve {host!r}")
        monkeypatch.setattr(schemas, "resolve_safe_target", _boom)
        app = ApplicationCreate(name="x", docker_images=["nginx:alpine", "grafana/grafana:11"])
        assert app.docker_images == ["nginx:alpine", "grafana/grafana:11"]

    def test_leading_dash_rejected(self):
        # The argument-injection vector.
        for bad in ["--config=/etc/passwd", "-x", "--cache-dir=/tmp"]:
            with pytest.raises(ValueError):
                ApplicationCreate(name="x", docker_images=[bad])

    def test_whitespace_and_null_rejected(self):
        for bad in ["nginx alpine", "nginx\timage", "nginx\x00"]:
            with pytest.raises(ValueError):
                ApplicationCreate(name="x", docker_images=[bad])

    def test_blank_entries_dropped(self):
        app = ApplicationCreate(name="x", docker_images=["nginx:alpine", "", "  "])
        assert app.docker_images == ["nginx:alpine"]

    def test_update_schema_also_validated(self):
        with pytest.raises(ValueError):
            ApplicationUpdate(docker_images=["-flag"])
        assert ApplicationUpdate(docker_images=None).docker_images is None
        assert ApplicationUpdate(docker_images=["ok:1"]).docker_images == ["ok:1"]
