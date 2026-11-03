"""The interactive API docs stay off unless a deployment asks for them.

FastAPI serves /docs, /redoc and /openapi.json by default, without any
authentication: the whole route inventory, internal routes included. Every
module must pass docs_url, redoc_url and openapi_url explicitly, and they
must resolve to None when ENABLE_API_DOCS is unset.

The check reads each main.py instead of importing it (importing an app needs
that module's dependencies and database): it finds the FastAPI(...) call and
evaluates its three keyword arguments, with the top-level assignments they
refer to, under a controlled environment.
"""
import ast
import os
import pathlib
from unittest import mock

import pytest

SUITE = pathlib.Path(__file__).resolve().parents[1]
MODULES = ["pilot", "risk", "vendor", "compliance", "asset", "audit", "access", "surface", "appsec", "watch"]
DOC_KWARGS = ("docs_url", "redoc_url", "openapi_url")


def _app_call(tree: ast.Module) -> ast.Call:
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "app" for t in node.targets)
                and isinstance(node.value, ast.Call) and getattr(node.value.func, "id", None) == "FastAPI"):
            return node.value
    raise AssertionError("no top-level `app = FastAPI(...)`")


def _doc_urls(module: str, env: dict) -> dict:
    """{kwarg: value} as main.py would compute it under `env`; a kwarg left
    out reports FastAPI's own default, which serves the docs."""
    tree = ast.parse((SUITE / module / "src" / "main.py").read_text())
    call = _app_call(tree)
    given = {k.arg: k.value for k in call.keywords if k.arg in DOC_KWARGS}
    names = {n.id for v in given.values() for n in ast.walk(v) if isinstance(n, ast.Name)}
    ns: dict = {"os": os}
    with mock.patch.dict(os.environ, env, clear=True):
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), ns)
        return {k: (eval(compile(ast.Expression(given[k]), "main.py", "eval"), ns) if k in given else "<default>")
                for k in DOC_KWARGS}


@pytest.mark.parametrize("module", MODULES)
def test_api_docs_are_off_by_default(module):
    assert _doc_urls(module, {}) == dict.fromkeys(DOC_KWARGS), module
    assert _doc_urls(module, {"ENABLE_API_DOCS": "false"}) == dict.fromkeys(DOC_KWARGS), module


@pytest.mark.parametrize("module", MODULES)
def test_api_docs_can_be_enabled(module):
    urls = _doc_urls(module, {"ENABLE_API_DOCS": "true"})
    assert all(isinstance(v, str) and v.startswith("/") for v in urls.values()), (module, urls)


def test_compose_passes_the_switch_to_every_module():
    import yaml
    services = yaml.safe_load((SUITE / "docker-compose.yml").read_text())["services"]
    for m in MODULES:
        assert "ENABLE_API_DOCS" in services[f"{m}-app"].get("environment", []), m
