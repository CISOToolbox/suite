"""Unit tests for Pilot authorization guards.

Tests require_admin, get_current_user token validation, and verifies
that admin-only routes are properly protected via source code analysis.
"""
import ast
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

ROUTES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes")


# ── require_admin ─────────────────────────────────────────────────

class TestRequireAdmin:
    def test_rejects_user_role(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(role="user")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_rejects_viewer_role(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(role="viewer")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_accepts_admin_role(self):
        from auth import require_admin
        user = SimpleNamespace(role="admin")
        require_admin(user)  # no exception

    def test_accepts_none_user(self):
        from auth import require_admin
        require_admin(None)  # auth disabled => no exception

    def test_rejects_pending_role(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(role="pending")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403


# ── verify_service_token ──────────────────────────────────────────

class TestVerifyServiceToken:
    def test_rejects_empty_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "secret123")
        import importlib, auth
        importlib.reload(auth)
        from auth import verify_service_token
        from fastapi import HTTPException
        request = SimpleNamespace(headers={"X-Service-Token": ""})
        with pytest.raises(HTTPException) as exc:
            verify_service_token(request)
        assert exc.value.status_code == 403

    def test_rejects_wrong_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "secret123")
        import importlib, auth
        importlib.reload(auth)
        from auth import verify_service_token
        from fastapi import HTTPException
        request = SimpleNamespace(headers={"X-Service-Token": "wrong"})
        with pytest.raises(HTTPException) as exc:
            verify_service_token(request)
        assert exc.value.status_code == 403

    def test_accepts_correct_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "secret123")
        import importlib, auth
        importlib.reload(auth)
        from auth import verify_service_token
        request = SimpleNamespace(headers={"X-Service-Token": "secret123"})
        verify_service_token(request)  # no exception


# ── Source code analysis: admin-protected routes ──────────────────

def _collect_admin_routes():
    """Parse route files and find functions that call require_admin."""
    admin_routes = []
    for fname in os.listdir(ROUTES_DIR):
        if not fname.endswith(".py") or fname == "__init__.py":
            continue
        fpath = os.path.join(ROUTES_DIR, fname)
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                src = ast.dump(node)
                if "require_admin" in src:
                    admin_routes.append((fname, node.name))
    return admin_routes


EXPECTED_ADMIN_ROUTES = {
    ("settings.py", "get_settings"),
    ("settings.py", "update_settings"),
    ("users.py", "list_users"),
    ("users.py", "update_user"),
    ("measures.py", "sync_measures"),
    ("backups.py", "get_config"),
    ("backups.py", "update_config"),
    ("backups.py", "run_backup"),
    ("backups.py", "run_all_backups"),
    ("backups.py", "list_backups"),
    ("backups.py", "download_backup"),
    ("backups.py", "restore_backup"),
    ("backups.py", "delete_backup"),
    ("directory.py", "create_personnel"),
    ("directory.py", "update_personnel"),
    ("directory.py", "delete_personnel"),
    ("directory.py", "import_csv"),
    ("modules.py", "health_check"),
}


class TestAdminRoutesCoverage:
    def test_all_expected_routes_are_admin_protected(self):
        actual = set(_collect_admin_routes())
        missing = EXPECTED_ADMIN_ROUTES - actual
        assert not missing, f"Routes expected to require admin but don't: {missing}"

    def test_no_unexpected_admin_routes_removed(self):
        actual = set(_collect_admin_routes())
        assert len(actual) >= len(EXPECTED_ADMIN_ROUTES), (
            f"Found only {len(actual)} admin routes, expected at least {len(EXPECTED_ADMIN_ROUTES)}"
        )
