#!/usr/bin/env python3
"""Every handler the pages can name is declared to the event dispatcher.

The shared event delegation (``data-click``, ``data-change``, ``data-input``,
``data-click-self``) calls a global function by the name the markup carries.
Markup is built from data, so a value that escapes ``esc()`` once can name any
function: the dispatcher only calls names that the code declared beforehand —
the shared handlers in ``cisotoolbox.js`` (``_CT_SHARED_HANDLERS``) and the
module's own list (``_ctDeclareHandlers([...])`` in ``app/ts/*_handlers.ts``).

This guard reads what the browser actually runs — ``app/index.html`` and the
scripts it loads — and checks, for every module:

  A. the page loads its declaration after ``cisotoolbox.js``;
  B. every handler name the page or its scripts render is declared;
  C. every declared name is a function those scripts define (no stale entry).

A handler name reaches the markup in three ways, all covered by B:
  - a literal attribute: ``data-click="saveX"``, ``setAttribute("data-click",
    "saveX")``, ``_menuAction`` with ``data-args='["saveX"]'``;
  - an option key of a shared renderer (``onRowClick: "openX"``…), or the
    default it falls back to (``opts.triageHandler || "_ctFvNoop"``);
  - an argument of a helper that renders the attribute
    (``_dirPicker(value, "saveX", …)``) — see ``HANDLER_ARGS``.
A new helper that takes a handler name must be added to ``HANDLER_ARGS``.

    python3 tests/test_dispatch_allowlist.py
    pytest tests/test_dispatch_allowlist.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

IDENT = r"[A-Za-z_$][\w$]*"

# data-click="name", data-change='name', data-click=\"name\" (inside a JS string).
ATTR_RE = re.compile(r"data-(?:click|change|input|click-self)\s*=\s*\\?[\"'](" + IDENT + r")\\?[\"']")
SET_ATTR_RE = re.compile(
    r"setAttribute\(\s*[\"']data-(?:click|change|input|click-self)[\"']\s*,\s*[\"'](" + IDENT + r")[\"']")
# _menuAction calls its single argument by name.
MENU_RE = re.compile(r"data-click=\\?[\"']_menuAction\\?[\"'][^>]*?data-args=\\?'\[\s*\\?\"(" + IDENT + r")")
# Option keys of the shared renderers that end up in a data-click
# (ct_table: sortHandler, onRowClick, actions[].onClick; ct_finding_view: *Handler).
OPTION_RE = re.compile(r"\b(?:sortHandler|onRowClick|onClick|backHandler|triageHandler|derogationHandler|"
                       r"aiHandler|deleteHandler)\s*:\s*([^,\n}]*)")
# The default a renderer falls back to when the option is absent: opts.xHandler || "name".
FALLBACK_RE = re.compile(r"\.\w*[Hh]andler\s*\|\|\s*[\"'](" + IDENT + r")[\"']")
# Helpers whose argument (0-based index) is written into a data-* handler attribute.
HANDLER_ARGS: dict[str, tuple[int, ...]] = {
    "_dirPicker": (1,),             # directory_picker: data-change
    "_dirMultiPicker": (1, 2),      # directory_picker: data-change, data-click
    "_depSearchInput": (0,),        # asset
    "_cardOpen": (1,),              # vendor (DORA register cards)
    "_addInlineAIBtns": (1,),       # risk (AI suggestion buttons)
}

# Handlers written in markup that no page renders, kept out of every list on
# purpose: declaring one would make an admin action callable from any page.
NEVER_DECLARED = {
    "_dirSetSource": "directory source select; its renderer _dirAdminToggle is called nowhere",
}

SHARED_LIST_RE = re.compile(r"_CT_SHARED_HANDLERS\s*(?::[^=]+)?=\s*\[(.*?)\]", re.S)
DECLARE_RE = re.compile(r"_ctDeclareHandlers\(\s*\[(.*?)\]\s*\)", re.S)
STRING_RE = re.compile(r"[\"'](" + IDENT + r")[\"']")
SCRIPT_RE = re.compile(r"<script[^>]+src=\"([^\"]+)\"")


# function f(…), window.f = …, var f = function, f = function (a TS namespace export).
DEFINED_RE = re.compile(r"\bfunction\s+(" + IDENT + r")\s*\(|\bwindow\.(" + IDENT + r")\s*=(?!=)"
                        r"|\b(?:var|let|const)\s+(" + IDENT + r")\s*=\s*(?:async\s+)?function\b"
                        r"|^[ \t]*(" + IDENT + r")\s*=\s*function\b", re.M)


def defined_names(src: str) -> set[str]:
    return {next(g for g in m if g) for m in DEFINED_RE.findall(src)}


def _call_args(src: str, start: int) -> list[str]:
    """Top-level arguments of the call whose '(' is at ``start``."""
    args, depth, cur, i, quote = [], 0, [], start + 1, None
    while i < len(src):
        c = src[i]
        if quote:
            cur.append(c)
            if c == "\\":
                cur.append(src[i + 1]); i += 2; continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c; cur.append(c)
        elif c in "([{":
            depth += 1; cur.append(c)
        elif c in ")]}":
            if depth == 0:
                args.append("".join(cur).strip()); return args
            depth -= 1; cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
        i += 1
    return args


def handler_names(src: str) -> set[str]:
    """Every handler name a script or page can render into a data-* attribute."""
    names = set(ATTR_RE.findall(src)) | set(SET_ATTR_RE.findall(src))
    names |= set(MENU_RE.findall(src)) | set(FALLBACK_RE.findall(src))
    for value in OPTION_RE.findall(src):     # "x", or cond ? "x" : "y"
        names |= set(STRING_RE.findall(value))
    for helper, positions in HANDLER_ARGS.items():
        for m in re.finditer(r"(?<![\w$.])" + re.escape(helper) + r"\(", src):
            if re.search(r"function\s*$", src[max(0, m.start() - 12):m.start()]):
                continue    # the helper's own definition
            args = _call_args(src, m.end() - 1)
            for p in positions:
                if p < len(args):
                    lit = re.fullmatch(r"[\"'](" + IDENT + r")[\"']", args[p])
                    if lit:
                        names.add(lit.group(1))
    return names


def _apps() -> list[Path]:
    return sorted(p.parent for p in REPO_ROOT.glob("*/app/index.html"))


def _scripts(app: Path) -> list[Path]:
    html = (app / "index.html").read_text(encoding="utf-8")
    out = []
    for src in SCRIPT_RE.findall(html):
        p = (app / src.split("?")[0]).resolve()
        if p.is_file():
            out.append(p)
    return out


def _strings(block: str) -> list[str]:
    return STRING_RE.findall(block)


def _shared_handlers(app: Path) -> list[str]:
    m = SHARED_LIST_RE.search((app / "js" / "cisotoolbox.js").read_text(encoding="utf-8"))
    return _strings(m.group(1)) if m else []


def check_declaration_loaded() -> list[str]:
    errors = []
    for app in _apps():
        names = [p.name for p in _scripts(app)]
        if "cisotoolbox.js" not in names:
            continue
        decl = [i for i, p in enumerate(_scripts(app)) if DECLARE_RE.search(p.read_text(encoding="utf-8"))]
        if not decl:
            errors.append(f"{app.parent.name}: index.html loads no script calling _ctDeclareHandlers")
        elif decl[0] < names.index("cisotoolbox.js"):
            errors.append(f"{app.parent.name}: the handler declaration loads before cisotoolbox.js")
    return errors


def check_rendered_names_declared() -> list[str]:
    errors = []
    for app in _apps():
        scripts = _scripts(app)
        declared = set(_shared_handlers(app))
        used: set[str] = handler_names((app / "index.html").read_text(encoding="utf-8"))
        texts = []
        for p in scripts:
            src = p.read_text(encoding="utf-8")
            texts.append(src)
            used |= handler_names(src)
            for block in DECLARE_RE.findall(src):
                declared |= set(_strings(block))
        defined = defined_names("\n".join(texts))
        for name in sorted(used - declared):
            # A name no script defines does nothing either way (a dead button).
            if name in defined and name not in NEVER_DECLARED:
                errors.append(f"{app.parent.name}: handler {name!r} is rendered but not declared")
        for name in sorted(declared & set(NEVER_DECLARED)):
            errors.append(f"{app.parent.name}: handler {name!r} must not be declared ({NEVER_DECLARED[name]})")
    return errors


def check_declared_names_defined() -> list[str]:
    errors = []
    shared_defined: dict[str, bool] = {}
    shared: set[str] = set()
    for app in _apps():
        scripts = _scripts(app)
        defined = defined_names("\n".join(p.read_text(encoding="utf-8") for p in scripts))
        for p in scripts:
            for block in DECLARE_RE.findall(p.read_text(encoding="utf-8")):
                for name in _strings(block):
                    if name not in defined:
                        errors.append(f"{app.parent.name}: declared handler {name!r} is not defined")
        for name in _shared_handlers(app):
            shared.add(name)
            shared_defined[name] = shared_defined.get(name, False) or name in defined
    for name in sorted(shared):
        if not shared_defined[name]:
            errors.append(f"cisotoolbox.js: shared handler {name!r} is defined by no module's scripts")
    return errors


def test_every_page_loads_its_declaration() -> None:
    assert check_declaration_loaded() == []


def test_every_rendered_handler_is_declared() -> None:
    assert check_rendered_names_declared() == []


def test_every_declared_handler_exists() -> None:
    assert check_declared_names_defined() == []


# Loads the shipped cisotoolbox.js in a bare node context and fires delegated
# events at it. Prints what was called.
_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const listeners = {};
function stub() {
  const f = function () { return stub(); };
  return new Proxy(f, { get: (t, k) => k === Symbol.toPrimitive ? () => "" : (k === "length" ? 0 : stub()) });
}
const document = new Proxy({}, { get: (t, k) => k === "addEventListener"
  ? (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); } : stub() });
const ctx = { document, console: { log() {}, warn() {}, error() {} }, JSON, Object, Array, Math, Date, String,
  Number, RegExp, Error, Promise, Set, Map, setTimeout: () => 0, clearTimeout: () => 0,
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, navigator: { language: "en" },
  location: { search: "", hash: "", pathname: "/" }, matchMedia: () => ({ matches: false, addEventListener() {} }),
  HTMLElement: class {}, Element: class {}, Node: class {} };
ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx, { filename: "cisotoolbox.js" });
const calls = [];
// Names an ordinary object inherits ("toString" in {} is true): spied on the
// window so that a lookup falling through to Object.prototype shows up.
for (const n of ["declared", "undeclared", "fetch", "toString", "constructor", "hasOwnProperty"])
  ctx[n] = function (...a) { calls.push(n + ":" + a.join("|")); };
ctx.toggleMenu = function () {};
function fire(type, attrs) {
  const node = { getAttribute: (k) => attrs[k], hasAttribute: (k) => k in attrs, value: "v", checked: false };
  node.closest = (sel) => (sel.slice(1, -1) in attrs ? node : null);
  (listeners[type] || []).forEach((f) => f({ target: node, stopPropagation() {} }));
}
function round(tag) {
  calls.push("#" + tag);
  for (const fn of ["declared", "undeclared", "fetch", "toString", "constructor", "hasOwnProperty"]) {
    fire("click", { "data-click": fn, "data-args": '["c"]' });
    fire("change", { "data-change": fn, "data-args": '["ch"]' });
    fire("input", { "data-input": fn, "data-args": '["in"]' });
  }
  fire("click", { "data-click": "_menuAction", "data-args": '["undeclared"]' });
  fire("click", { "data-click": "_menuAction", "data-args": '["declared"]' });
}
round("legacy");
ctx._ctDeclareHandlers(["declared"]);
round("declared");
console.log(JSON.stringify(calls));
"""


def _dispatch_calls(tmp_path: Path) -> list[str]:
    import json
    import shutil
    import subprocess
    import pytest
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    script = next(p for p in (a / "js" / "cisotoolbox.js" for a in _apps()) if p.is_file())
    out = subprocess.run(["node", str(harness), str(script)], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_dispatcher_calls_only_declared_handlers(tmp_path: Path) -> None:
    calls = _dispatch_calls(tmp_path)
    declared = calls[calls.index("#declared") + 1:]
    assert declared == ["declared:c", "declared:ch", "declared:in", "declared:"]


def test_undeclared_page_keeps_the_blocklist(tmp_path: Path) -> None:
    calls = _dispatch_calls(tmp_path)
    legacy = calls[1:calls.index("#declared")]
    assert "fetch:c" not in legacy and "undeclared:c" in legacy


def test_scanner_sees_every_form() -> None:
    sample = (
        '<b data-click="a1"></b>'
        "h += '<i data-change=\"a2\" data-pass-value>';"
        'el.setAttribute("data-click", "a3");'
        "<div data-click=\"_menuAction\" data-args='[\"a4\"]'></div>"
        '{ onRowClick: "a5", sortHandler: ok() ? "a6" : undefined }'
        '_dirPicker(m.responsable || "", "a7", _da(i, "x"));'
        '_dirMultiPicker(ids, "a8", "a9");'
        'var x = opts.triageHandler || "a10";'
    )
    assert handler_names(sample) == {"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "_menuAction"}


if __name__ == "__main__":
    problems = check_declaration_loaded() + check_rendered_names_declared() + check_declared_names_defined()
    for line in problems:
        print(line)
    sys.exit(1 if problems else 0)
