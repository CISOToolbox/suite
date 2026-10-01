"""Unit tests for Access module authorization guards.

Tests _user_permissions, require_admin,
require_min_role, service token on internal endpoints, and
an inventory of the running app proving every route is authenticated.
"""
import ast
import asyncio
import contextlib
import inspect
import os
import sys
import textwrap
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

MODULE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROUTES_DIR = os.path.join(MODULE_DIR, "src", "routes")


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
        # Authentication is switched on through the seam, never through the
        # environment and a reload, which depends on test order. With auth off
        # everyone gets every right, so the plain user on the same project is
        # the contrast that proves the admin gets them *because* admin.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        project = SimpleNamespace(owner_id="other-id", shared_with=[])
        admin = SimpleNamespace(id="admin-id", role="admin")
        plain = SimpleNamespace(id="user-id", role="user")
        assert rp._user_permissions(project, admin) == ["read", "edit", "delete", "share"]
        assert rp._user_permissions(project, plain) == ["read", "edit"]

    def test_owner_gets_no_extra_rights(self, monkeypatch):
        # Single shared project: ownership is not a role. The owner is a plain
        # user — read+edit, no delete/share.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        project = SimpleNamespace(owner_id="user-1", shared_with=[])
        user = SimpleNamespace(id="user-1", role="user")
        assert rp._user_permissions(project, user) == ["read", "edit"]

    def test_viewer_role_is_read_only(self, monkeypatch):
        # A viewer (incl. a suite-wide "viewer") can SEE the review data
        # (users / service accounts / perimeters) but not mutate it.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        user = SimpleNamespace(id="v", role="user")
        user._module_role = "viewer"
        project = SimpleNamespace(owner_id=None, shared_with=[])
        assert rp._user_permissions(project, user) == ["read"]

    def test_plain_user_gets_read_edit(self, monkeypatch):
        # Any non-viewer module user gets read+edit (the review workflow);
        # only admins get delete/share.
        import routes.projects as rp
        monkeypatch.setattr(rp, "auth_enabled", lambda: True)
        user = SimpleNamespace(id="u", role="user")
        user._module_role = "user"
        project = SimpleNamespace(owner_id=None, shared_with=[])
        assert rp._user_permissions(project, user) == ["read", "edit"]


# ── require_admin ─────────────────────────────────────────────────

class TestRequireAdmin:
    def test_rejects_non_admin(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="editor")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_accepts_admin(self):
        from auth import require_admin
        user = SimpleNamespace(_module_role="admin")
        require_admin(user)


# ── require_min_role ──────────────────────────────────────────────

class TestRequireMinRole:
    HIERARCHY = ["viewer", "editor", "admin"]

    def test_viewer_cannot_reach_editor(self):
        from auth import require_min_role
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="viewer")
        with pytest.raises(HTTPException) as exc:
            require_min_role(user, "editor", self.HIERARCHY)
        assert exc.value.status_code == 403

    def test_editor_can_reach_editor(self):
        from auth import require_min_role
        user = SimpleNamespace(_module_role="editor")
        require_min_role(user, "editor", self.HIERARCHY)  # no exception

    def test_admin_always_passes(self):
        from auth import require_min_role
        user = SimpleNamespace(_module_role="admin")
        require_min_role(user, "editor", self.HIERARCHY)  # no exception


# ── Internal service token ────────────────────────────────────────

class TestInternalServiceToken:
    def test_rejects_no_service_token_configured(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        from fastapi import HTTPException
        request = SimpleNamespace(headers={"X-Service-Token": "anything"})
        with pytest.raises(HTTPException) as exc:
            internal_mod._check_service_token(request)
        assert exc.value.status_code == 503

    def test_rejects_wrong_service_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "correct")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        from fastapi import HTTPException
        request = SimpleNamespace(headers={"X-Service-Token": "wrong"})
        with pytest.raises(HTTPException) as exc:
            internal_mod._check_service_token(request)
        assert exc.value.status_code == 403


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


# ── Runtime inventory of the routes ───────────────────────────────

# Routes that are public by design; every other route must authenticate.
PUBLIC_ROUTES = {
    ("POST", "/auth/login/token"), ("POST", "/auth/logout"), ("GET", "/auth/providers"),
    ("GET", "/api/plugins/available"), ("GET", "/api/health"), ("GET", "/api/version"),
}
# Everything mounted outside FastAPI's APIRoute: the docs and the static front.
NON_API_ROUTES = {
    ("Route", "/openapi.json"), ("Route", "/docs"),
    ("Route", "/docs/oauth2-redirect"), ("Route", "/redoc"), ("Mount", ""),
}


def _app():
    """The application as it runs. Imported from the module directory: the
    static mount resolves ``app/`` against the working directory."""
    if MODULE_DIR not in sys.path:
        sys.path.insert(0, MODULE_DIR)
    with contextlib.chdir(MODULE_DIR):
        from src.main import app
    return app


def _guards() -> set:
    """The guard functions themselves, compared by identity: a local function
    that merely borrows one of their names is not a guard."""
    from src import auth_common, connectors_common
    from src.routes import internal
    return {auth_common.get_current_user, auth_common.get_current_user_permissive,
            internal._check_service_token,
            connectors_common._check_service_token,
            connectors_common._require_admin_or_service}


def _dependency_calls(dependant) -> set:
    calls = set()
    for dep in dependant.dependencies:
        calls.add(dep.call)
        calls |= _dependency_calls(dep)
    return calls


def _called_objects(func) -> set:
    """The objects the endpoint calls by plain name, resolved through its
    closure and its module globals (a guard handed to a router factory is a
    closure variable)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    names = {n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    scope = inspect.getclosurevars(func)
    resolved = {**scope.globals, **scope.nonlocals}
    return {resolved[n] for n in names if n in resolved}


class TestRoutesAuthenticated:
    def test_every_route_is_authenticated(self):
        """Inventory of the running application, not of the source files: a
        route added by add_api_route, by @app.post or in any file is seen."""
        from fastapi.routing import APIRoute
        guards = _guards()
        routes = [(m, r) for r in _app().routes if isinstance(r, APIRoute)
                  for m in sorted(r.methods)]
        assert len(routes) > 40, "inventory too small: the check proves nothing"
        unguarded = []
        for method, route in routes:
            if (method, route.path) in PUBLIC_ROUTES:
                continue
            if guards & (_dependency_calls(route.dependant) | _called_objects(route.endpoint)):
                continue
            unguarded.append(f"{method} {route.path} "
                             f"({route.endpoint.__module__}.{route.endpoint.__name__})")
        assert not unguarded, "routes without authentication:\n" + "\n".join(unguarded)

    def test_no_route_outside_the_inventory(self):
        # A sub-application, a websocket or a bare Starlette route escapes the
        # APIRoute inventory: the set of such routes is pinned.
        from fastapi.routing import APIRoute
        others = {(type(r).__name__, getattr(r, "path", "")) for r in _app().routes
                  if not isinstance(r, APIRoute)}
        assert others == NON_API_ROUTES

    def test_public_routes_are_current(self):
        # An exception that no longer matches a route must not linger.
        from fastapi.routing import APIRoute
        declared = {(m, r.path) for r in _app().routes if isinstance(r, APIRoute)
                    for m in r.methods}
        assert PUBLIC_ROUTES <= declared


class TestConnectorGuards:
    """The connector guards are trusted by the inventory: they must reject."""

    def _request(self, token=None):
        return SimpleNamespace(headers={"X-Service-Token": token} if token else {})

    def test_service_token_rejects_wrong_or_missing(self, monkeypatch):
        from fastapi import HTTPException
        from src import connectors_common as cc
        monkeypatch.setattr(cc, "SERVICE_TOKEN", "secret")
        for token in (None, "wrong"):
            with pytest.raises(HTTPException) as exc:
                cc._check_service_token(self._request(token))
            assert exc.value.status_code == 403
        cc._check_service_token(self._request("secret"))

    def test_service_token_unset_fails_closed(self, monkeypatch):
        from fastapi import HTTPException
        from src import connectors_common as cc
        monkeypatch.setattr(cc, "SERVICE_TOKEN", "")
        with pytest.raises(HTTPException) as exc:
            cc._check_service_token(self._request("anything"))
        assert exc.value.status_code == 503

    def test_admin_or_service_rejects_anonymous_and_non_admin(self, monkeypatch):
        from fastapi import HTTPException
        from src import connectors_common as cc
        monkeypatch.setattr(cc, "SERVICE_TOKEN", "secret")

        async def anonymous(request, db):
            raise HTTPException(status_code=401)

        async def editor(request, db):
            return SimpleNamespace(_module_role="editor")

        for fake, status in ((anonymous, 401), (editor, 403)):
            monkeypatch.setattr(cc, "get_current_user", fake)
            with pytest.raises(HTTPException) as exc:
                asyncio.run(cc._require_admin_or_service(self._request(), None))
            assert exc.value.status_code == status
        asyncio.run(cc._require_admin_or_service(self._request("secret"), None))
