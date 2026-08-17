"""Regression (H6): creating a central directory entry is admin-only.

POST /api/directory forwards an arbitrary body to Pilot's internal directory
(mass-assignment into shared personnel data). It used to be gated only on
get_current_user, so any module role — even a read-only viewer — could inject
personnel into the central directory. The fix adds require_admin(user).

GET /api/directory stays open to any authenticated module user on purpose: it
backs the owner/user pickers used across every module (measure owners, finding
assignees), so admin-gating it would break assignment for non-admin editors.
"""
import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from fastapi import HTTPException  # noqa: E402

from src.routes.directory_proxy import create_directory_entry  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
MODULES = ["access", "appsec", "asset", "compliance", "risk", "surface", "vendor", "watch"]


def _user(module_role):
    u = SimpleNamespace(id="u", email="u@medsecure.local", name="U", role="user")
    u._module_role = module_role
    return u


def test_viewer_cannot_create_directory_entry():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(create_directory_entry({"email": "x@y.z"}, user=_user("viewer"), db=None))
    assert exc.value.status_code == 403


def test_unauthenticated_rejected():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(create_directory_entry({"email": "x@y.z"}, user=None, db=None))
    assert exc.value.status_code == 401


def test_every_module_gates_post_but_not_get():
    for m in MODULES:
        src = (REPO / m / "src" / "routes" / "directory_proxy.py").read_text()
        post = src.split("async def create_directory_entry", 1)[1]
        assert "require_admin(user)" in post, f"{m}: POST /directory not admin-gated"
        get_block = src.split("async def get_directory", 1)[1].split("async def", 1)[0]
        assert "require_admin" not in get_block, f"{m}: GET /directory wrongly admin-gated (breaks pickers)"
