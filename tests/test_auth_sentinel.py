#!/usr/bin/env python3
"""AUTH-02 regression guard — the `user is None` sentinel contract.

`get_current_user()` returns `Optional[User]` and `None` has exactly ONE
meaning: **authentication is disabled** (`auth_enabled()` is False, i.e.
AUTH_MODE=none). It never means "anonymous caller" — a caller with no valid
session is rejected with 401 inside the dependency and never reaches the
handler. The full contract lives in `<module>/src/auth_common.py` and
`pilot/src/auth.py` ("THE `None` CONTRACT").

Two ways to get it wrong, both shipped once (security audit, finding AUTH-02):

  A. treat the sentinel as "unauthenticated" — `if user is None: raise 401`.
     Everything 401s in AUTH_MODE=none, which makes the mode untestable and
     hides regressions. Found in 26 endpoints across the 9 modules.
  B. read `user.<attr>` with no guard — AttributeError -> 500 in
     AUTH_MODE=none. Found in 42 accesses across `watch`.

This file walks the AST of every route module and fails on either. It is
pure stdlib, so it runs two ways:

    python3 tests/test_auth_sentinel.py     # standalone, no dependencies
    pytest tests/test_auth_sentinel.py      # in CI, alongside pilot/tests

Adding a legitimate exception means adding it to `ALLOWLIST` with a reason,
not loosening the analysis.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MODULES = (
    "access", "appsec", "asset", "compliance", "pilot",
    "risk", "surface", "vendor", "watch",
)

# Parameter names that carry the possibly-None authenticated user.
USER_PARAM_NAMES = {"user", "current_user"}
# Dependencies that yield the sentinel.
DEP_NAMES = {"get_current_user", "get_current_user_permissive"}
# Statuses that mean "you are not allowed in".
DENIAL_STATUSES = {401, 403}

# "<module>/<relative path>:<line>" entries deliberately exempted, with the
# reason. Keep this empty unless there is a real one.
ALLOWLIST: dict[str, str] = {}


# ─────────────────────────── contract predicates ──────────────────────────
NOT_NONE = "not_none"
IS_NONE = "is_none"


def _is_var(node, var) -> bool:
    return isinstance(node, ast.Name) and node.id == var


def _is_none_const(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def implies(test, var, truthy):
    """What the outcome of `test` proves about `var`.

    Returns NOT_NONE, IS_NONE or None. `truthy` selects the branch: True for
    "the test evaluated truthy", False for the fall-through.
    """
    if _is_var(test, var):
        return NOT_NONE if truthy else IS_NONE
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        pair = None
        if _is_var(left, var) and _is_none_const(right):
            pair = op
        elif _is_none_const(left) and _is_var(right, var):
            pair = op
        if isinstance(pair, ast.Is):
            return IS_NONE if truthy else NOT_NONE
        if isinstance(pair, ast.IsNot):
            return NOT_NONE if truthy else IS_NONE
        return None
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return implies(test.operand, var, not truthy)
    if isinstance(test, ast.BoolOp):
        results = [implies(v, var, truthy) for v in test.values]
        # `and` taken / `or` not taken => every operand held on this branch,
        # so a single witness is enough. Otherwise only "at least one" held
        # and every operand has to agree.
        if isinstance(test.op, ast.And) == truthy:
            for r in results:
                if r is not None:
                    return r
            return None
        if results and all(r == results[0] for r in results):
            return results[0]
        return None
    return None


def terminates(stmts) -> bool:
    """Conservative: does this block always leave the enclosing block?"""
    for s in stmts:
        if isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(s, ast.If) and s.orelse:
            if terminates(s.body) and terminates(s.orelse):
                return True
    return False


def mentions_auth_enabled(node) -> bool:
    """Is the auth posture part of this condition?

    `if auth_enabled() and user is None: raise 401` is correct defence in
    depth — unreachable in AUTH_MODE=none. `if user is None: raise 401` is
    the bug.
    """
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id == "auth_enabled":
            return True
        if isinstance(n, ast.Attribute) and n.attr == "auth_enabled":
            return True
    return False


def denial_status(stmts):
    """HTTP status of the first "you are not allowed in" exit in `stmts`."""
    for n in ast.walk(ast.Module(body=list(stmts), type_ignores=[])):
        call = None
        if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call):
            call = n.exc
        elif isinstance(n, ast.Return) and isinstance(n.value, ast.Call):
            call = n.value
        if call is None:
            continue
        name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
        if name not in {"HTTPException", "JSONResponse", "Response", "PlainTextResponse"}:
            continue
        for kw in call.keywords:
            if kw.arg == "status_code" and isinstance(kw.value, ast.Constant):
                if kw.value.value in DENIAL_STATUSES:
                    return kw.value.value
        if name == "HTTPException" and call.args and isinstance(call.args[0], ast.Constant):
            if call.args[0].value in DENIAL_STATUSES:
                return call.args[0].value
    return None


# ───────────────────────────── flow analysis ──────────────────────────────
class Analyzer:
    """Tracks, statement by statement, whether `var` is provably not None.

    Only models the guard shapes this codebase actually uses; anything it
    cannot prove counts as unguarded, so it errs towards reporting.
    """

    def __init__(self, var, path, findings, funcs=None, edges=None):
        self.var = var
        self.path = path
        self.findings = findings
        self.funcs = funcs or {}
        self.edges = edges if edges is not None else set()

    # -- expressions ---------------------------------------------------
    def expr(self, node, guarded):
        if node is None:
            return
        if isinstance(node, ast.Attribute) and _is_var(node.value, self.var):
            if not guarded:
                self.findings.append((self.path, node.lineno, f"{self.var}.{node.attr}"))
            return
        if isinstance(node, ast.BoolOp):
            g = guarded
            for v in node.values:
                self.expr(v, g)
                # `and`: the next operand runs only if this one was truthy;
                # `or`: only if it was falsy.
                if implies(v, self.var, isinstance(node.op, ast.And)) == NOT_NONE:
                    g = True
            return
        if isinstance(node, ast.IfExp):
            self.expr(node.test, guarded)
            self.expr(node.body, guarded or implies(node.test, self.var, True) == NOT_NONE)
            self.expr(node.orelse, guarded or implies(node.test, self.var, False) == NOT_NONE)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Call):
            self._record_propagation(node, guarded)
            # getattr(user, "x", default) is None-safe by construction.
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and node.args
                and _is_var(node.args[0], self.var)
            ):
                for a in node.args[1:]:
                    self.expr(a, guarded)
                return
        self.descend(node, guarded)

    def _record_propagation(self, call, guarded):
        """A possibly-None user handed to a same-file helper taints it too."""
        if guarded or not isinstance(call.func, ast.Name):
            return
        target = self.funcs.get(call.func.id)
        if target is None:
            return
        positional = list(target.args.posonlyargs) + list(target.args.args)
        named = positional + list(target.args.kwonlyargs)
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Name) and a.id == self.var and i < len(positional):
                self.edges.add((call.func.id, positional[i].arg))
        for kw in call.keywords:
            if kw.arg and isinstance(kw.value, ast.Name) and kw.value.id == self.var:
                if any(p.arg == kw.arg for p in named):
                    self.edges.add((call.func.id, kw.arg))

    def descend(self, node, guarded):
        """Recurse into every sub-expression, including the ones hanging off
        non-expression wrappers (keyword=, comprehension, slice, withitem)."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.expr(child, guarded)
            elif isinstance(child, (ast.stmt, ast.Lambda)):
                continue
            else:
                self.descend(child, guarded)

    # -- statements ----------------------------------------------------
    def block(self, stmts, guarded):
        for s in stmts:
            guarded = self.stmt(s, guarded)
        return guarded

    def stmt(self, s, guarded):
        if isinstance(s, ast.If):
            self.expr(s.test, guarded)
            self.block(s.body, guarded or implies(s.test, self.var, True) == NOT_NONE)
            self.block(s.orelse, guarded or implies(s.test, self.var, False) == NOT_NONE)
            if guarded:
                return True
            # early-exit guard: `if <... user is None ...>: raise/return`
            if not s.orelse and terminates(s.body):
                return implies(s.test, self.var, False) == NOT_NONE
            return False
        if isinstance(s, ast.Assert):
            self.expr(s.test, guarded)
            self.expr(s.msg, guarded)
            return guarded or implies(s.test, self.var, True) == NOT_NONE
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return guarded
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            self.expr(s.value, guarded)
            targets = s.targets if isinstance(s, ast.Assign) else [s.target]
            for t in targets:
                if _is_var(t, self.var):
                    return True  # rebound (`user = user or X`) — stop tracking
                self.expr(t, guarded)
            return guarded
        if isinstance(s, (ast.For, ast.AsyncFor)):
            self.expr(s.iter, guarded)
            self.expr(s.target, guarded)
            self.block(s.body, guarded)
            self.block(s.orelse, guarded)
            return guarded
        if isinstance(s, ast.While):
            self.expr(s.test, guarded)
            self.block(s.body, guarded or implies(s.test, self.var, True) == NOT_NONE)
            self.block(s.orelse, guarded)
            return guarded
        if isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                self.expr(item.context_expr, guarded)
            self.block(s.body, guarded)
            return guarded
        if isinstance(s, ast.Try):
            self.block(s.body, guarded)
            for h in s.handlers:
                self.block(h.body, guarded)
            self.block(s.orelse, guarded)
            self.block(s.finalbody, guarded)
            return guarded
        for child in ast.iter_child_nodes(s):
            if isinstance(child, ast.stmt):
                self.stmt(child, guarded)
            elif isinstance(child, ast.expr):
                self.expr(child, guarded)
            else:
                self.descend(child, guarded)
        return guarded


# ──────────────────────────────── driver ──────────────────────────────────
def user_params(fn):
    """Parameters of `fn` that hold the possibly-None authenticated user."""
    args = fn.args
    positional = list(args.posonlyargs) + list(args.args)
    defaults = {}
    if args.defaults:
        for a, d in zip(positional[len(positional) - len(args.defaults):], args.defaults):
            defaults[a.arg] = d
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        if d is not None:
            defaults[a.arg] = d
    for a in positional + list(args.kwonlyargs):
        if a.arg not in USER_PARAM_NAMES:
            continue
        d = defaults.get(a.arg)
        via_depends = (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Name)
            and d.func.id == "Depends"
            and d.args
            and isinstance(d.args[0], ast.Name)
            and d.args[0].id in DEP_NAMES
        )
        optional = a.annotation is not None and "Optional" in ast.dump(a.annotation)
        if via_depends or optional:
            yield a.arg


def source_files():
    """Every backend Python file of the 9 modules (excluding vendored addons)."""
    for module in MODULES:
        src = REPO_ROOT / module / "src"
        if not src.is_dir():
            continue
        for path in sorted(src.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path


def rel(path) -> str:
    return str(Path(path).relative_to(REPO_ROOT))


def _tainted_params(tree, path):
    """Fixpoint over `user` params: dependency-seeded, then propagated into
    same-file helpers that receive the sentinel."""
    funcs = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(n.name, n)
    tainted = {(name, var) for name, fn in funcs.items() for var in user_params(fn)}
    while True:
        edges, findings = set(), []
        for name, var in sorted(tainted):
            Analyzer(var, path, findings, funcs, edges).block(funcs[name].body, False)
        new = {e for e in edges if e[0] in funcs} - tainted
        if not new:
            return tainted, funcs, findings
        tainted |= new


def find_unguarded_attribute_reads():
    """Violation B — `user.<attr>` read on a path where `user` may be None."""
    out = []
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        _, _, findings = _tainted_params(tree, path)
        for p, line, expr in sorted(set(findings)):
            key = f"{rel(p)}:{line}"
            if key not in ALLOWLIST:
                out.append(f"{key}: reads `{expr}` — 500 in AUTH_MODE=none")
    return sorted(set(out))


def find_sentinel_denials():
    """Violation A — the sentinel answered with 401/403."""
    out = []
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        tainted, funcs, _ = _tainted_params(tree, path)
        for name, var in sorted(tainted):
            for node in ast.walk(funcs[name]):
                if not isinstance(node, ast.If):
                    continue
                if implies(node.test, var, True) != IS_NONE:
                    continue
                if mentions_auth_enabled(node.test):
                    continue  # `auth_enabled() and user is None` — correct
                status = denial_status(node.body)
                if status is None:
                    continue
                key = f"{rel(path)}:{node.lineno}"
                if key not in ALLOWLIST:
                    out.append(
                        f"{key}: in {name}(), `{var} is None` answers {status} — "
                        f"locks every caller out in AUTH_MODE=none"
                    )
    return sorted(set(out))


def _report(title, violations, rule):
    lines = [f"{len(violations)} violation(s) — {title}", "", rule, ""]
    lines += [f"  - {v}" for v in violations]
    return "\n".join(lines)


# ───────────────────────────────── tests ──────────────────────────────────
def test_sentinel_is_not_treated_as_unauthenticated():
    violations = find_sentinel_denials()
    assert not violations, _report(
        "`user is None` answered with 401/403",
        violations,
        "`None` means auth is DISABLED, not anonymous: an anonymous caller\n"
        "already got a 401 from the dependency. Branch on `auth_enabled()`\n"
        "instead, or drop the check.",
    )


def test_no_unguarded_user_attribute_access():
    violations = find_unguarded_attribute_reads()
    assert not violations, _report(
        "`user.<attr>` read without a None guard",
        violations,
        "In AUTH_MODE=none `user` is None and this raises AttributeError -> 500.\n"
        "Use `user.id if user else None` for ownership, `get_module_role(user)` /\n"
        "`require_admin(user)` for roles, or `require_identity(user)` when a real\n"
        "identity is structurally required (NOT NULL owner_id/user_id FK).",
    )


def main() -> int:
    failed = 0
    for fn in (test_sentinel_is_not_treated_as_unauthenticated,
               test_no_unguarded_user_attribute_access):
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}\n{exc}\n")
        else:
            print(f"ok    {fn.__name__}")
    modules = ", ".join(MODULES)
    print(f"\n{'FAILED' if failed else 'PASSED'} — sentinel contract over: {modules}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
