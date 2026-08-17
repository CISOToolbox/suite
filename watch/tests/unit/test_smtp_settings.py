"""Unit tests for _smtp_settings() — config resolution priority."""
import os
import sys
from unittest.mock import patch

import pytest


def _reset_pushed():
    """Reset the in-memory pushed-config dict between tests."""
    import src.routes.internal as ri
    ri._smtp_config.clear()


def test_env_fallback_when_no_push(monkeypatch):
    _reset_pushed()
    monkeypatch.setenv("SMTP_HOST", "env.example.com")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_USER", "envuser")
    monkeypatch.setenv("SMTP_PASSWORD", "envpass")
    monkeypatch.setenv("SMTP_FROM", "env-from@x.io")
    monkeypatch.setenv("SMTP_TLS", "false")

    from src.digest import _smtp_settings
    cfg = _smtp_settings()
    assert cfg["host"] == "env.example.com"
    assert cfg["port"] == 2525
    assert cfg["user"] == "envuser"
    assert cfg["password"] == "envpass"
    assert cfg["from_addr"] == "env-from@x.io"
    assert cfg["tls"] is False


def test_pushed_overrides_env(monkeypatch):
    _reset_pushed()
    monkeypatch.setenv("SMTP_HOST", "env.example.com")
    monkeypatch.setenv("SMTP_PORT", "2525")

    import src.routes.internal as ri
    ri._smtp_config.update({
        "host": "pushed.example.com",
        "port": "465",
        "user": "pushuser",
        "password": "pushpass",
        "from_addr": "push@x.io",
        "tls": "true",
    })

    from src.digest import _smtp_settings
    cfg = _smtp_settings()
    assert cfg["host"] == "pushed.example.com"
    assert cfg["port"] == 465
    assert cfg["user"] == "pushuser"
    assert cfg["password"] == "pushpass"


def test_no_host_returns_empty_host(monkeypatch):
    _reset_pushed()
    monkeypatch.delenv("SMTP_HOST", raising=False)
    from src.digest import _smtp_settings
    cfg = _smtp_settings()
    assert cfg["host"] == ""


def test_partial_push_falls_back_to_env_per_field(monkeypatch):
    """If push sets host but not port, port should come from env."""
    _reset_pushed()
    monkeypatch.setenv("SMTP_PORT", "1025")
    import src.routes.internal as ri
    ri._smtp_config.update({"host": "only-host.example.com"})

    from src.digest import _smtp_settings
    cfg = _smtp_settings()
    assert cfg["host"] == "only-host.example.com"
    assert cfg["port"] == 1025  # from env, since push didn't include port


def test_invalid_port_falls_back_to_587(monkeypatch):
    _reset_pushed()
    monkeypatch.setenv("SMTP_HOST", "env.example.com")
    monkeypatch.setenv("SMTP_PORT", "not-a-number")
    from src.digest import _smtp_settings
    cfg = _smtp_settings()
    assert cfg["port"] == 587
