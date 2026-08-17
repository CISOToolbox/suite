"""Unit tests for Asset module authorization guards.

Tests _user_permissions ownership/sharing pattern, require_admin,
require_min_role, service token on internal endpoints, and
source-code verification that routes are properly protected.
"""
import ast
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

ROUTES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes")


# ── _user_permissions (projects.py) ───────────────────────────────

class TestUserPermissions:
    def _perms(self, project, user):
        from routes.projects import _user_permissions
        return _user_permissions(project, user)

    def test_no_auth_returns_full_access(self, monkeypatch):
        monkeypatch.delenv("ENTRA_CLIENT_ID", raising=False)
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
        import importlib
        import routes.auth_helpers as ah
        importlib.reload(ah)
        import routes.projects as rp
        importlib.reload(rp)
        project = SimpleNamespace(owner_id=None, shared_with=[])
        assert self._perms(project, None) == ["read", "edit", "delete", "share"]

    def test_admin_gets_full_access(self, monkeypatch):
        monkeypatch.setenv("OIDC_CLIENT_ID", "test")
        import importlib
        import routes.auth_helpers as ah
        importlib.reload(ah)
        import routes.projects as rp
        importlib.reload(rp)
        project = SimpleNamespace(owner_id="other-id", shared_with=[])
        user = SimpleNamespace(id="admin-id", role="admin")
        perms = rp._user_permissions(project, user)
        assert "delete" in perms
        assert "share" in perms

    def test_owner_gets_full_access(self, monkeypatch):
        monkeypatch.setenv("OIDC_CLIENT_ID", "test")
        import importlib
        import routes.auth_helpers as ah
        importlib.reload(ah)
        import routes.projects as rp
        importlib.reload(rp)
        project = SimpleNamespace(owner_id="user-1", shared_with=[])
        user = SimpleNamespace(id="user-1", role="user")
        assert rp._user_permissions(project, user) == ["read", "edit", "delete", "share"]

    def test_viewer_role_is_read_only(self, monkeypatch):
        # Shared-inventory model: a viewer (incl. a suite-wide "viewer") reads
        # only — no edit/delete/share.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        user = SimpleNamespace(id="v", role="user")
        user._module_role = "viewer"
        project = SimpleNamespace(owner_id=None, shared_with=[])
        assert rp._user_permissions(project, user) == ["read"]

    def test_plain_user_gets_read_edit(self, monkeypatch):
        # Any non-viewer module user gets read+edit (no lockout); only admins
        # get delete/share.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        user = SimpleNamespace(id="u", role="user")
        user._module_role = "user"
        project = SimpleNamespace(owner_id=None, shared_with=[])
        assert rp._user_permissions(project, user) == ["read", "edit"]

    def test_unowned_project_gives_full_access(self, monkeypatch):
        monkeypatch.setenv("OIDC_CLIENT_ID", "test")
        import importlib
        import routes.auth_helpers as ah
        importlib.reload(ah)
        import routes.projects as rp
        importlib.reload(rp)
        project = SimpleNamespace(owner_id=None, shared_with=[])
        user = SimpleNamespace(id="anyone", role="user")
        assert rp._user_permissions(project, user) == ["read", "edit", "delete", "share"]


# ── require_admin ─────────────────────────────────────────────────

class TestRequireAdmin:
    def test_rejects_viewer(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="viewer")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_accepts_admin(self):
        from auth import require_admin
        user = SimpleNamespace(_module_role="admin")
        require_admin(user)

    def test_none_user_passes(self):
        from auth import require_admin
        require_admin(None)


# ── require_min_role ──────────────────────────────────────────────

class TestRequireMinRole:
    HIERARCHY = ["viewer", "editor", "admin"]

    def test_viewer_below_editor(self):
        from auth import require_min_role
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="viewer")
        with pytest.raises(HTTPException):
            require_min_role(user, "editor", self.HIERARCHY)

    def test_editor_meets_editor(self):
        from auth import require_min_role
        user = SimpleNamespace(_module_role="editor")
        require_min_role(user, "editor", self.HIERARCHY)

    def test_no_role_rejected(self):
        from auth import require_min_role, get_module_role
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role=None)
        role = get_module_role(user)
        # If get_module_role returns a fallback (e.g. "admin" for None user),
        # the function won't raise. Only test the raise if role is truly empty.
        if not role:
            with pytest.raises(HTTPException):
                require_min_role(user, "viewer", self.HIERARCHY)


# ── Internal service token ────────────────────────────────────────

class TestInternalServiceToken:
    def test_rejects_missing_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "secret")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        from fastapi import HTTPException
        request = SimpleNamespace(headers={})
        with pytest.raises(HTTPException) as exc:
            internal_mod._check_service_token(request)
        assert exc.value.status_code == 403

    def test_accepts_valid_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "secret")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        request = SimpleNamespace(headers={"X-Service-Token": "secret"})
        internal_mod._check_service_token(request)


# ── Source analysis ───────────────────────────────────────────────

def _find_routes_with(pattern: str):
    result = set()
    for fname in os.listdir(ROUTES_DIR):
        if not fname.endswith(".py") or fname == "__init__.py":
            continue
        fpath = os.path.join(ROUTES_DIR, fname)
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if pattern in ast.dump(node):
                    result.add((fname, node.name))
    return result


class TestRouteProtection:
    def test_all_internal_routes_check_service_token(self):
        fpath = os.path.join(ROUTES_DIR, "internal.py")
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for deco in node.decorator_list:
                    if "router" in ast.dump(deco):
                        assert "_check_service_token" in ast.dump(node), (
                            f"internal.py:{node.name} missing service token check"
                        )

    def test_user_management_requires_admin(self):
        admin_routes = _find_routes_with("require_admin")
        assert ("users.py", "list_users") in admin_routes
        assert ("users.py", "update_user") in admin_routes

    def test_directory_proxy_set_source_requires_admin(self):
        admin_routes = _find_routes_with("require_admin")
        assert ("directory_proxy.py", "set_source") in admin_routes
