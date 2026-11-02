#!/usr/bin/env python3
"""Regression guard: a read-only module role cannot create a project.

Creating, importing or duplicating a project (an analysis in Risk) makes the
caller its owner, with every right on it. These routes used to check nothing
but authentication, so a viewer could create projects, import any file as a
project, or copy one shared with them read-only and edit the copy.

This file walks every route file of the project modules and fails on any
route handler (sync or async, any router, POST/PUT/PATCH) that gives a
project an owner — `Project(...)`/`Analysis(...)` built with `owner_id=`, or
`<obj>.owner_id = ...` — without first calling `require_edit_role(user)` (or
Audit's module-wide `_require("edit", user)`) as an unconditional statement
of its body. It covers the usual ways of writing a route and an owner
assignment, not every possible one: a project built in a helper function,
a route added with `add_api_route` or declared outside `src/routes/`, a
model reached through an alias, or a GET/DELETE route that creates a project
is not seen. Pure stdlib:

    python3 tests/test_project_creation_roles.py
    pytest tests/test_project_creation_roles.py
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Modules whose top-level object is a project (an analysis in Risk). Every
# route file of these modules is swept, so a new file is covered too.
MODULES = ("access", "asset", "audit", "compliance", "risk", "vendor")
MODELS = {"Project", "Analysis"}
HTTP_VERBS = {"post", "put", "patch"}


def _route_files() -> list[Path]:
    return sorted(p for m in MODULES for p in (REPO_ROOT / m / "src" / "routes").rglob("*.py"))


def _is_route(fn: ast.AST) -> bool:
    """Decorated with `<any router>.post/put/patch(...)`, or
    `<any router>.api_route(..., methods=[...])` naming one of them."""
    for dec in fn.decorator_list:
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
            continue
        if dec.func.attr in HTTP_VERBS:
            return True
        if dec.func.attr == "api_route":
            for k in dec.keywords:
                if k.arg == "methods" and any(
                        isinstance(e, ast.Constant) and str(e.value).lower() in HTTP_VERBS
                        for e in getattr(k.value, "elts", [])):
                    return True
    return False


def _model_name(func: ast.AST) -> str:
    """`Project` for both `Project(...)` and `models.Project(...)`."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _targets(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Assign):
        out = []
        for t in node.targets:
            out += t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]
        return out
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


def _owned_construction_line(fn: ast.AST) -> int | None:
    """Line where the handler gives a new project an owner: a
    `Project(...)`/`Analysis(...)` built with `owner_id=`, or an
    `<obj>.owner_id = ...` assignment."""
    lines = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and _model_name(node.func) in MODELS
                and any(k.arg in ("owner_id", None) for k in node.keywords)):
            # `owner_id=` or a `**mapping` that may carry it
            lines.append(node.lineno)
        elif any(isinstance(t, ast.Attribute) and t.attr == "owner_id" for t in _targets(node)):
            lines.append(node.lineno)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "setattr" and len(node.args) >= 2
              and isinstance(node.args[1], ast.Constant) and node.args[1].value == "owner_id"):
            lines.append(node.lineno)
    return min(lines) if lines else None


def _is_user(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "user"


def _gate_line(fn: ast.AST, rel: str) -> int | None:
    """Line of the first role gate on the handler's `user`, called
    unconditionally (a statement of the handler body itself, not nested in a
    branch). `_require("edit", user)` is Audit's own module-wide gate."""
    for stmt in fn.body:
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Name)):
            continue
        call = stmt.value
        args = list(call.args) + [k.value for k in call.keywords]
        if call.func.id == "require_edit_role" and len(args) == 1 and _is_user(args[0]):
            return stmt.lineno
        if (rel.startswith("audit/") and call.func.id == "_require" and len(args) == 2
                and isinstance(args[0], ast.Constant) and args[0].value == "edit"
                and _is_user(args[1])):
            return stmt.lineno
    return None


def _handlers():
    for path in _route_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(), filename=rel)
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_route(fn):
                built = _owned_construction_line(fn)
                if built is not None:
                    yield rel, fn, built


def find_violations() -> list[str]:
    out = []
    for rel, fn, built in _handlers():
        gate = _gate_line(fn, rel)
        if gate is None or gate > built:
            out.append(f"{rel}:{fn.lineno} {fn.name} creates a project without require_edit_role(user) first")
    return out


def _creating_routes() -> list[str]:
    return [f"{rel}:{fn.name}" for rel, fn, _ in _handlers()]


def test_project_creation_requires_edit_role():
    assert find_violations() == []


def test_sweep_sees_the_creating_routes():
    # Guard against a sweep that passes because it matches nothing: each
    # module has at least create, duplicate and import.
    found = _creating_routes()
    for m in MODULES:
        assert sum(r.startswith(m + "/") for r in found) >= 3, found


if __name__ == "__main__":
    bad = find_violations()
    for line in bad:
        print(line)
    sys.exit(1 if bad else 0)
