#!/usr/bin/env python3
"""Regression guards for the suite-wide contracts between Pilot and modules.

Pilot centralises what every module then stores locally: the SMTP server
config, and the accounts with their per-module role. Each of the seven checks
below encodes something that was actually broken in production, and each is
the kind of divergence that stays invisible until someone reads two modules
side by side.

SMTP (found at a client, one relay refusing AUTH):
  A. **One vocabulary.** Surface stored ``username`` / ``sender`` / ``use_tls``
     where every other module used ``user`` / ``from_addr`` / ``tls``.
  B. **A push can clear.** A field emptied in Pilot arrives as ``""``.
     Skipping empties made the config append-only, so a stale ``smtp.user``
     survived and Surface kept attempting AUTH against a relay with none.
  C. **One guard on every send path.** Surface validated the SMTP host on the
     report path only, so the same config passed or failed by mail type.
  D. **One env name.** Watch read ``PUBLIC_URL`` where the suite reads
     ``PUBLIC_BASE_URL``, and shipped digests with no links at all.

Accounts (leftover habilitations for people who no longer exist):
  E. **De-provisioning exists.** The module role lives in the module's own
     ``users`` row, and ``/internal/sync-user`` only ever created or updated.
     Every module must expose ``POST /internal/delete-user``.
  F. **No FK blocks a delete.** ``ForeignKey("users.id")`` without ``ondelete``
     is NO ACTION: the deletion fails as soon as the person owns something.
     Six modules refused it while four cascaded.

Pure stdlib AST/text sweep, so it runs both ways:

    python3 tests/test_suite_contracts.py
    pytest tests/test_suite_contracts.py
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The vocabulary. Adding a field here means adding it to every receiver.
CANONICAL_FIELDS = ("host", "port", "user", "password", "from_addr", "tls")

# Names that were once used for the same data. A module may never reintroduce
# them as storage keys — they are what made the divergence invisible.
BANNED_KEYS = ("smtp.username", "smtp.sender", "smtp.use_tls")

# Files that legitimately mention the banned keys: the migration that renames
# them away, and this guard.
BANNED_KEY_ALLOWLIST = ("alembic/versions/014_smtp_key_alignment.py",)


def _receivers() -> list[Path]:
    """Every module route file that implements PUT /internal/smtp."""
    found = []
    for p in sorted(REPO_ROOT.glob("*/src/routes/internal.py")):
        if '@router.put("/internal/smtp")' in p.read_text(encoding="utf-8"):
            found.append(p)
    return found


def _smtp_fields_of(path: Path) -> tuple[str, ...] | None:
    """Value of the module-level _SMTP_FIELDS tuple, via AST (no import)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_SMTP_FIELDS" for t in node.targets
        ):
            try:
                return tuple(ast.literal_eval(node.value))
            except ValueError:
                return None
    return None


def test_every_receiver_uses_the_canonical_fields() -> list[str]:
    problems = []
    receivers = _receivers()
    assert receivers, "no /internal/smtp receiver found — did the layout change?"
    for path in receivers:
        fields = _smtp_fields_of(path)
        rel = path.relative_to(REPO_ROOT)
        if fields is None:
            problems.append(f"{rel}: no module-level _SMTP_FIELDS tuple")
        elif tuple(fields) != CANONICAL_FIELDS:
            problems.append(f"{rel}: _SMTP_FIELDS = {fields}, expected {CANONICAL_FIELDS}")
    return problems


def test_every_receiver_can_clear_a_field() -> list[str]:
    """A receiver that never deletes cannot honour a cleared field."""
    problems = []
    for path in _receivers():
        src = path.read_text(encoding="utf-8")
        deco = src.index('@router.put("/internal/smtp")')
        # Skip past the handler's OWN `async def` line, then cut at the next
        # top-level decorator or def — otherwise the body is empty and every
        # receiver looks broken.
        own = src.index("\nasync def ", deco) + 1
        rest = src[src.index("\n", own) + 1:]
        nxt = min((i for i in (rest.find("\n@router"), rest.find("\nasync def "),
                               rest.find("\ndef ")) if i >= 0), default=len(rest))
        body = rest[:nxt]
        if "db.delete(" not in body:
            problems.append(
                f"{path.relative_to(REPO_ROOT)}: receiver never deletes a row — "
                "a field cleared in Pilot can never be cleared here")
    return problems


def test_no_module_reintroduces_a_legacy_key() -> list[str]:
    problems = []
    for path in sorted(REPO_ROOT.glob("*/src/**/*.py")):
        rel = str(path.relative_to(REPO_ROOT))
        if any(rel.endswith(a) for a in BANNED_KEY_ALLOWLIST):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for key in BANNED_KEYS:
            if f'"{key}"' in text or f"'{key}'" in text:
                problems.append(f"{rel}: legacy SMTP key {key!r}")
    return problems


def test_every_surface_send_validates_the_host() -> list[str]:
    """Surface guards its SMTP host against loopback / metadata / sibling
    services. It used to do so on the report path only, so the same config
    passed or failed depending on which mail was going out."""
    problems = []
    for path in sorted((REPO_ROOT / "surface" / "src").rglob("*.py")):
        # mailer_common.py is the REPLICATED shared transport: its own
        # send_html_email() serves Watch/Asset, which have no allowlist. The
        # validator is a caller's concern, injected via host_validator=.
        if path.name == "mailer_common.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if name != "smtp_deliver":
                continue
            if not any(kw.arg == "host_validator" for kw in node.keywords):
                problems.append(
                    f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                    "smtp_deliver() without host_validator")
    return problems


def test_mail_links_use_the_suite_env_name() -> list[str]:
    """Absolute links in mails come from PUBLIC_BASE_URL across the suite.
    Watch read PUBLIC_URL alone, so a correctly configured deployment got a
    digest with no links while every other module's mails were fine."""
    problems = []
    for path in sorted(REPO_ROOT.glob("*/src/**/*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "PUBLIC_URL" not in text:
            continue
        # Match the env READS, not the prose: a docstring naming the right
        # variable must not stand in for actually reading it.
        read = set()
        for node in ast.walk(ast.parse(text)):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "attr", "") in ("getenv", "get")
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value in ("PUBLIC_URL", "PUBLIC_BASE_URL")):
                read.add(node.args[0].value)
        if "PUBLIC_URL" in read and "PUBLIC_BASE_URL" not in read:
            problems.append(
                f"{path.relative_to(REPO_ROOT)}: reads PUBLIC_URL but never "
                "PUBLIC_BASE_URL — the suite-wide name")
    return problems


def _modules_with_users() -> list[str]:
    return [p.parts[0] for p in
            (q.relative_to(REPO_ROOT) for q in REPO_ROOT.glob("*/src/models.py"))
            if '__tablename__ = "users"' in (REPO_ROOT / p).read_text(encoding="utf-8")
            and p.parts[0] != "pilot"]


def test_every_module_can_deprovision() -> list[str]:
    """Pilot owns the directory, but the module role lives in the module's own
    `users` row. A module with no de-provisioning route keeps that role for
    ever after the account is deleted — the leftover habilitations bug."""
    problems = []
    for mod in sorted(_modules_with_users()):
        f = REPO_ROOT / mod / "src" / "routes" / "internal.py"
        if not f.exists() or '"/internal/delete-user"' not in f.read_text(encoding="utf-8"):
            problems.append(f"{mod}: no POST /internal/delete-user")
    return problems


# What Pilot pushes to every module from its settings (`_push_to_modules`).
# Pilot did not read the answers, so a module without the route never got the
# config and nothing said so: Surface had no `ai-custom` (its custom LLM always
# answered "not configured"), and Surface, AppSec and Watch had no `proxy`.
# A route Pilot pushes only to the modules that opted in is listed here.
PILOT_PUSH_OPT_IN = {"smtp": "only the modules that send mail receive the relay config"}


def _pilot_pushes() -> list[str]:
    src = (REPO_ROOT / "pilot" / "src" / "routes" / "settings.py").read_text(encoding="utf-8")
    return sorted(set(re.findall(r'client\.put\(base \+ "/api/internal/([a-z-]+)"', src)))


def test_every_module_receives_what_pilot_pushes() -> list[str]:
    pushed = [r for r in _pilot_pushes() if r not in PILOT_PUSH_OPT_IN]
    if not pushed:
        return ["no PUT /api/internal/* found in Pilot's settings push — has it moved?"]
    problems = []
    for f in sorted(REPO_ROOT.glob("*/src/routes/internal.py")):
        if f.parts[-4] == "pilot":
            continue
        src = f.read_text(encoding="utf-8")
        problems += [f"{f.parts[-4]}: no PUT /internal/{r} (pushed by Pilot)"
                     for r in pushed if f'@router.put("/internal/{r}")' not in src]
    return problems


def test_every_module_restores_its_proxy_at_startup() -> list[str]:
    """A module that receives Pilot's proxy stores it, and must export it again
    when it starts: the environment does not outlive the process. Each such
    module's `on_startup` awaits `restore_proxy` (src.proxy_common)."""
    problems = []
    for f in sorted(REPO_ROOT.glob("*/src/routes/internal.py")):
        module = f.parts[-4]
        if module == "pilot" or '@router.put("/internal/proxy")' not in f.read_text(encoding="utf-8"):
            continue
        tree = ast.parse((REPO_ROOT / module / "src" / "main.py").read_text(encoding="utf-8"))
        startups = [n for n in ast.walk(tree)
                    if isinstance(n, ast.AsyncFunctionDef) and n.name == "on_startup"]
        awaited = {c.value.func.id for fn in startups for c in ast.walk(fn)
                   if isinstance(c, ast.Await) and isinstance(c.value, ast.Call)
                   and isinstance(c.value.func, ast.Name)}
        if "restore_proxy" not in awaited:
            problems.append(f"{module}: on_startup does not await restore_proxy "
                            "(the pushed proxy is lost at every restart)")
    return problems


def test_backups_leave_out_what_pilot_pushes() -> list[str]:
    """A module's backup/restore of `app_settings` leaves out what Pilot pushes
    (`ai_*`, `proxy.*`): a restore must not bring back another deployment's
    keys or an outbound proxy, which start-up exports without re-validating.
    Every `startswith(...)` filter that names `ai_` must name `proxy.` too,
    and a module that backs up `app_settings` must filter it at all.
    (Surface's routes are also exercised: tests/unit/test_backup_settings.py.)"""
    problems = []
    for f in sorted(REPO_ROOT.glob("*/src/routes/internal.py")):
        src = f.read_text(encoding="utf-8")
        filters = []
        for node in ast.walk(ast.parse(src)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "startswith" and node.args):
                arg = node.args[0]
                values = [e.value for e in (arg.elts if isinstance(arg, ast.Tuple) else [arg])
                          if isinstance(e, ast.Constant)]
                if "ai_" in values:
                    filters.append((node.lineno, values))
        rel = f.relative_to(REPO_ROOT)
        if '"app_settings"' in src and not filters:
            problems.append(f"{rel}: backs up app_settings without leaving out ai_* / proxy.*")
        problems += [f"{rel}:{line}: excludes ai_* but not proxy.*"
                     for line, values in filters if "proxy." not in values]
    return problems


def test_user_fks_never_block_a_delete() -> list[str]:
    """Every FK to users.id must say what happens on delete. PostgreSQL's
    default (NO ACTION) makes the deletion fail as soon as the person owns
    something — six modules refused it while four cascaded."""
    problems = []
    fk_re = re.compile(r'ForeignKey\(\s*["\']users\.id["\']([^)]*)\)')
    for path in sorted(REPO_ROOT.glob("*/src/models.py")):
        for m in fk_re.finditer(path.read_text(encoding="utf-8")):
            if "ondelete" not in m.group(1):
                problems.append(
                    f"{path.relative_to(REPO_ROOT)}: ForeignKey(\"users.id\") "
                    "without ondelete= (defaults to NO ACTION, blocks deletion)")
    return problems


def test_secret_settings_are_decrypted_on_read() -> list[str]:
    """A secret read out of `app_settings` must go through decrypt_setting().

    `_set_setting` encrypts every key `is_secret_key()` recognises, so reading
    the column raw hands the CIPHERTEXT to the provider. It answers 401, which
    Pilot reported as "Invalid API key configured on server" — an accusation
    against a key that was perfectly valid. Pilot keeps its own copy of the AI
    route and had never been given the decryption the shared source does.

    Silent on a cleartext-legacy deployment (decrypt_setting passes unmarked
    values through), which is exactly why it survived so long.
    """
    # Checked per FUNCTION, not per file: `decrypt_setting` appearing somewhere
    # in the module says nothing about the accessor that actually returns the
    # key. A file-level check passes on the exact bug it is meant to catch.
    READERS = ("_get_api_key", "_get_setting")
    problems = []
    for path in sorted(REPO_ROOT.glob("*/src/**/*.py")):
        if not path.name.startswith("ai"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "AppSettings" not in text:
            continue
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in READERS:
                continue
            body = ast.dump(node)
            if "AppSettings" not in body:
                continue
            if "'decrypt_setting'" not in body:
                problems.append(
                    f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.name}() "
                    "reads AppSettings without decrypt_setting — an encrypted "
                    "secret would be handed over as ciphertext")
    return problems


def _py_catalogue() -> dict:
    """AI_PROVIDERS as declared by the shared Python source (via AST)."""
    path = REPO_ROOT / "pilot" / "src" / "ai_models_common.py"
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "AI_PROVIDERS":
            return ast.literal_eval(node.value)
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "AI_PROVIDERS" for t in node.targets):
            return ast.literal_eval(node.value)
    return {}


def test_one_model_catalogue_everywhere() -> list[str]:
    """One list of models, everywhere.

    It existed three times — the shared proxy for the modules, Pilot's own AI
    route, and the browser copy for standalone mode — and they drifted: Pilot
    offered Opus 4.6 and defaulted to Sonnet 4.6 while the modules offered and
    defaulted to Sonnet 5. Picking a model in Pilot could name something a
    module had never heard of.

    Python side is now a single source imported by both; the browser copy
    cannot import Python, so it is verified here instead.
    """
    problems = []
    py = _py_catalogue()
    if not py:
        return ["pilot/src/ai_models_common.py: AI_PROVIDERS not found"]

    # No module may reintroduce a local catalogue.
    for path in sorted(REPO_ROOT.glob("*/src/**/*.py")):
        if path.name == "ai_models_common.py":
            continue
        if "AI_PROVIDERS = {" in path.read_text(encoding="utf-8", errors="ignore"):
            problems.append(f"{path.relative_to(REPO_ROOT)}: local AI_PROVIDERS — "
                            "import it from src.ai_models_common instead")

    # Browser copy: same ids, same defaults.
    js = REPO_ROOT / "pilot" / "app" / "js" / "ai_common.js"
    if not js.exists():
        js = next(iter(sorted(REPO_ROOT.glob("*/app/js/ai_common.js"))), None)
    if js is not None:
        text = js.read_text(encoding="utf-8", errors="ignore")
        for provider, conf in py.items():
            for m in conf.get("models", []):
                if f'"{m["id"]}"' not in text and f"'{m['id']}'" not in text:
                    problems.append(f"{js.relative_to(REPO_ROOT)}: missing model "
                                    f"{m['id']!r} ({provider})")
            dflt = conf.get("defaultModel", "")
            if dflt and f'"{dflt}"' not in text and f"'{dflt}'" not in text:
                problems.append(f"{js.relative_to(REPO_ROOT)}: default {dflt!r} "
                                f"({provider}) absent from the browser catalogue")
    return problems


def test_every_catalogued_provider_can_be_called() -> list[str]:
    """A provider offered in the UI must have a call branch on both paths.

    Pilot listed and managed a Gemini key but had no Gemini branch: the call
    fell through to the OpenAI request shape and failed. Offering a provider
    nobody can call is worse than not offering it.
    """
    problems = []
    py = _py_catalogue()
    paths = [REPO_ROOT / "pilot" / "src" / "routes" / "ai.py",
             REPO_ROOT / "risk" / "src" / "ai_proxy_common.py"]
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for provider in py:
            if provider in ("anthropic", "openai"):
                continue          # the two default branches, always present
            if f'"{provider}"' not in text:
                problems.append(f"{path.relative_to(REPO_ROOT)}: provider "
                                f"{provider!r} is catalogued but never branched on")
    return problems


def test_actions_are_pinned_to_a_commit() -> list[str]:
    """Every GitHub Action must be pinned to a full 40-char commit SHA.

    A tag is mutable: its owner can repoint `v4` at another commit without a
    single visible change in the workflow file, and CI then runs whatever that
    commit contains — with the repository token in hand. This is not
    theoretical (tj-actions/changed-files, reviewdog/action-setup). Reputable
    publishers reduce the likelihood, not the mechanism.

    Keep the human-readable version as a trailing comment:
        uses: actions/checkout@11d5960…  # v4
    """
    sha_re = re.compile(r"^[0-9a-f]{40}$")
    problems = []
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r"uses:\s*(\S+)", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue          # local composite action / container ref
            if "@" not in ref:
                problems.append(f"{path.name}:{i}: {ref} has no ref at all")
                continue
            if not sha_re.match(ref.rsplit("@", 1)[1]):
                problems.append(f"{path.name}:{i}: {ref} is pinned to a MUTABLE "
                                "tag — use the 40-char commit SHA")
    return problems


def test_login_redirect_is_validated() -> list[str]:
    """`?redirect=` must never reach `location.href` unvalidated.

    It is attacker-supplied: a crafted login link sends the user off-site after
    signing in, and `javascript:` assigned to `location.href` runs IN THIS
    ORIGIN — an XSS on the login page. The server has always filtered its own
    redirects (`_sanitize_redirect`); the browser side had no rule at all.
    """
    # Checked at every READ, not once per file: the helper merely being
    # defined somewhere proves nothing — dropping the call while leaving the
    # function in place is exactly how this regresses.
    problems = []
    for path in sorted(REPO_ROOT.glob("*/app/js/login*.js")):
        for i, line in enumerate(path.read_text(encoding="utf-8",
                                                errors="ignore").splitlines(), 1):
            if 'get("redirect")' not in line:
                continue
            if "safeRedirect(" not in line:
                problems.append(f"{path.relative_to(REPO_ROOT)}:{i}: ?redirect= "
                                "read without safeRedirect()")
    return problems


def _modules() -> list[Path]:
    """Every module directory of the suite, discovered — never a fixed list."""
    return sorted(p.parent.parent.parent for p in REPO_ROOT.glob("*/src/routes/ai.py"))


# ── SSRF egress (audit finding H4) ───────────────────────────────────
#
# Moved here from risk/tests/unit/test_ssrf_egress.py: these sweep every
# module, so living inside one module meant nobody ran them when touching
# another. The behavioural tests, which exercise risk's own
# _validate_proxy_url, stayed there.
#
# They used to grep for "resolve_safe_target" in routes/ai.py and
# "getaddrinfo" in routes/internal.py. Both guards were factored into
# src/ssrf_guard.py, so the greps found nothing and validated no module at
# all. Two traps when repairing them, still worth respecting:
#   - scanning ssrf_guard.py itself would make them tautological — that file
#     DEFINES the functions being looked for;
#   - asserting `"ssrf_guard" in src` matched the function's DOCSTRING and
#     survived deleting the delegation, hence the import-form assertion.
# resolve_safe_request: pinned like resolve_safe_url directly, by name through the proxy.
GUARD_CALLS = ("resolve_safe_url", "resolve_safe_target", "resolve_safe_request")


def test_every_custom_llm_branch_has_ssrf_guard() -> list[str]:
    problems, checked = [], 0
    for mod in _modules():
        src = (mod / "src" / "routes" / "ai.py").read_text(encoding="utf-8")
        common = mod / "src" / "ai_proxy_common.py"
        if common.exists():
            src += common.read_text(encoding="utf-8")
        if 'provider == "custom"' not in src:
            continue  # no custom-LLM branch, nothing to guard
        checked += 1
        if not any(c in src for c in GUARD_CALLS):
            problems.append(f"{mod.name}: custom-LLM branch does not call the shared SSRF guard")
    if not checked:
        problems.append("no module has a custom-LLM branch — has the branch been renamed?")
    return problems


def _function(path, name):
    """The (async) function ``name`` defined in ``path``, as an AST node, or None."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next((n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)


def _calls(fn, name):
    """The calls to ``name`` (a plain or attribute name) inside ``fn``."""
    return [n for n in ast.walk(fn) if isinstance(n, ast.Call)
            and (getattr(n.func, "id", None) == name or getattr(n.func, "attr", None) == name)]


def _swallows(fn) -> bool:
    """An ``except`` in ``fn`` that does not raise again."""
    return any(not any(isinstance(x, ast.Raise) for x in ast.walk(h))
               for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler))


def _allow_private(call):
    """The ``allow_private`` keyword of ``call``: None if absent, else its literal value
    (True for anything that is not a literal)."""
    for kw in call.keywords:
        if kw.arg == "allow_private":
            return kw.value.value if isinstance(kw.value, ast.Constant) else True
    return None


def _proxy_common_delegates(mod) -> bool:
    """The module's proxy_common.check_proxy_url calls the shared guard and
    lets its refusal through."""
    common = mod / "src" / "proxy_common.py"
    fn = _function(common, "check_proxy_url") if common.exists() else None
    if fn is None or _swallows(fn):
        return False
    calls = _calls(fn, "validate_public_url")
    # allow_private passed on from the caller as a keyword (not forced to a
    # literal, not through **kwargs): the Pilot push relies on its default.
    return bool(calls) and all(
        any(kw.arg == "allow_private" and isinstance(kw.value, ast.Name) and kw.value.id == "allow_private"
            for kw in c.keywords) and not any(kw.arg is None for kw in c.keywords)
        for c in calls)


def test_every_proxy_validator_delegates_to_the_guard() -> list[str]:
    """Every proxy URL the module exports is checked by ssrf_guard, directly
    or through proxy_common.check_proxy_url, and a refusal is never
    swallowed: the Pilot push (internal.py), which refuses private
    addresses, and the standalone settings (proxy_settings_common.py)."""
    problems, checked = [], 0
    for mod in _modules():
        internal = mod / "src" / "routes" / "internal.py"
        settings = mod / "src" / "proxy_settings_common.py"
        # Every copy, Pilot's included: it relies on the default (refused).
        if (mod / "src" / "proxy_common.py").exists() and not _proxy_common_delegates(mod):
            problems.append(f"{mod.name}/proxy_common.py check_proxy_url does not call ssrf_guard "
                            "with the caller's allow_private, or swallows its refusal")
        if settings.exists():
            fn = _function(settings, "_clean_url")
            if fn is None or not _calls(fn, "check_proxy_url") or _swallows(fn) or not _proxy_common_delegates(mod):
                problems.append(f"{mod.name}/proxy_settings_common.py does not check the proxy with ssrf_guard")
        if not internal.exists():
            continue
        fn = _function(internal, "_validate_proxy_url")
        if fn is None:
            continue
        checked += 1
        direct = _calls(fn, "validate_public_url")
        via_common = _calls(fn, "check_proxy_url") if _proxy_common_delegates(mod) else []
        if not (direct or via_common):
            problems.append(f"{mod.name}/internal.py _validate_proxy_url does not delegate to ssrf_guard")
        if any(_allow_private(c) for c in direct + via_common):
            problems.append(f"{mod.name}/internal.py _validate_proxy_url widens the guard (allow_private)")
        if _swallows(fn) or not any(isinstance(x, ast.Raise) for x in ast.walk(fn)):
            problems.append(f"{mod.name}/internal.py _validate_proxy_url swallows a refusal")
    if not checked:
        problems.append("no module defines _validate_proxy_url — has it been renamed?")
    return problems


# ── Add-ons: what ships must be loadable ───────────────────────────────
#
# Access shipped for a while an image with NONE of its 22 connectors: they live
# under addons/generic/ and the Dockerfile only copied src/, app/ and alembic/.
# Nothing flagged it — the loader emits a warning at best and the UI shows an
# empty grid. The README promised 22 connectors, the API returned zero, and
# every check was green.
#
# The rule is not "bundle everything": Surface deliberately keeps its generic
# tier optional (heavy scanners, layered by build-client-image.sh). It is: every
# non-empty tier must be either bundled, or declared optional here, with its
# reason.
# Add-on tiers a published image does NOT bundle. Only `custom` belongs here:
# it is by definition client-specific and layered by Dockerfile.addons.
# `generic` left this list in 2026-09 — the published images (standalone, suite,
# and the client images derived from them) now carry the full set of
# scanners/connectors.
OPTIONAL_ADDON_TIERS = {
    ("surface", "custom"): "add-ons specifiques client",
    ("access", "custom"): "connecteurs specifiques client",
}


def _final_stage(dockerfile: str) -> str:
    """The contents of the last FROM stage of a multi-stage Dockerfile."""
    parts = re.split(r'^FROM\s', dockerfile, flags=re.M)
    return parts[-1] if parts else dockerfile


def _addon_tiers() -> list[tuple[str, str, int]]:
    """(module, tier, add-on count) for every non-empty tier."""
    out = []
    for addons in sorted(REPO_ROOT.glob("*/addons")):
        module = addons.parent.name
        for tier in sorted(p for p in addons.iterdir() if p.is_dir()):
            n = sum(1 for d in tier.iterdir() if d.is_dir())
            if n:
                out.append((module, tier.name, n))
    return out


def test_every_bundled_addon_tier_is_copied() -> list[str]:
    problems = []
    for module, tier, n in _addon_tiers():
        if (module, tier) in OPTIONAL_ADDON_TIERS:
            continue
        dockerfile = REPO_ROOT / module / "Dockerfile"
        if not dockerfile.is_file():
            problems.append(f"{module}: no Dockerfile, cannot ship its {n} {tier} add-on(s)")
            continue
        # Only the LAST stage counts: a COPY in the builder (to install the
        # deps) puts nothing in the final image — it even wipes it. A first
        # draft of this check matched that very COPY and let through the exact
        # failure it was meant to catch.
        src = _final_stage(dockerfile.read_text(encoding="utf-8"))
        if not re.search(rf'^COPY\b[^#\n]*addons/{tier}\b', src, re.M):
            problems.append(
                f"{module}: {n} add-on(s) in addons/{tier}/ but the Dockerfile never "
                f"COPYs them — the image would ship none. Bundle the tier, or declare "
                f"it in OPTIONAL_ADDON_TIERS with a reason."
            )
    return problems


def test_every_image_installs_its_lock() -> list[str]:
    """Every image that installs Python packages installs its
    requirements-lock.txt, with --require-hashes: going back to
    `-r requirements.txt` would let every unpinned transitive float again."""
    problems = []
    for dockerfile in sorted(REPO_ROOT.glob("*/Dockerfile")):
        src = "\n".join(l for l in dockerfile.read_text(encoding="utf-8").splitlines()
                        if not l.lstrip().startswith("#"))
        if "pip install" not in src:
            continue
        module = dockerfile.parent.name
        if not re.search(r"pip install[^\n]*--require-hashes[^\n]*-r requirements-lock\.txt", src):
            problems.append(f"{module}: the Dockerfile does not install requirements-lock.txt with --require-hashes")
        elif not (dockerfile.parent / "requirements-lock.txt").is_file():
            problems.append(f"{module}: the Dockerfile installs requirements-lock.txt, which is missing")
    return problems


def test_bundled_addons_get_their_dependencies() -> list[str]:
    """A bundled add-on whose deps are missing is skipped with a mere warning:
    twenty connectors work, three do not, and nothing says so. The image
    installs requirements-lock.txt (--require-hashes): each bundled add-on's
    requirements must be in that lock, and the Dockerfile must install it."""
    problems = []
    pin = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")
    canon = lambda n: re.sub(r"[-_.]+", "-", n).lower()
    for module, tier, _n in _addon_tiers():
        if (module, tier) in OPTIONAL_ADDON_TIERS:
            continue
        reqs = sorted((REPO_ROOT / module / "addons" / tier).glob("*/requirements.txt"))
        if not reqs:
            continue
        dockerfile = REPO_ROOT / module / "Dockerfile"
        if not dockerfile.is_file():
            continue
        # Comments do not count: a Dockerfile that DESCRIBES the install
        # without performing it used to satisfy the search.
        src = "\n".join(l for l in dockerfile.read_text(encoding="utf-8").splitlines()
                        if not l.lstrip().startswith("#"))
        if not re.search(r"pip install[^\n]*--require-hashes[^\n]*-r requirements-lock\.txt", src):
            problems.append(f"{module}: the Dockerfile does not install requirements-lock.txt "
                            f"with --require-hashes — its bundled add-ons' deps are not installed")
            continue
        lock = REPO_ROOT / module / "requirements-lock.txt"
        locked = {canon(m.group(1)): m.group(2) for l in (lock.read_text(encoding="utf-8").splitlines()
                  if lock.is_file() else []) if (m := pin.match(l.strip()))}
        for req in reqs:
            for line in req.read_text(encoding="utf-8").splitlines():
                m = pin.match(line.split("#", 1)[0].strip())
                if m and locked.get(canon(m.group(1))) != m.group(2):
                    problems.append(
                        f"{module}: add-on {req.parent.name} asks for {m.group(1)}=={m.group(2)} "
                        f"but requirements-lock.txt holds {locked.get(canon(m.group(1)), 'nothing')} — "
                        f"it would load broken while the others work.")
    return problems


def test_externally_built_artefacts_are_verified_at_build() -> list[str]:
    """An artefact compiled OUTSIDE the image must be checked by the Dockerfile.

    Real case: addons/generic/smb_scan_rs carries a Rust worker cross-compiled by
    rust/build.sh, gitignored, impossible to produce in a builder stage (rustc
    segfaults under qemu). It was forgotten, and the images published before
    2026-09 bundled the add-on with an empty bin/: the scanner failed at first
    use, at a client site, with nothing flagging it at build time.

    A COPY that succeeds does not prove the copied directory is not empty.
    """
    problems = []
    for addons in sorted(REPO_ROOT.glob("*/addons")):
        module = addons.parent.name
        dockerfile = REPO_ROOT / module / "Dockerfile"
        if not dockerfile.is_file():
            continue
        src = dockerfile.read_text(encoding="utf-8")
        for build_dir in sorted(addons.glob("*/*/rust")):
            addon = build_dir.parent
            if (module, addon.parent.name) in OPTIONAL_ADDON_TIERS:
                continue
            # The Dockerfile must name the artefact AND know how to fail.
            names_it = re.search(rf'{re.escape(addon.name)}/bin/', src)
            fails = re.search(r'\bexit\s+1\b', src)
            if not (names_it and fails):
                problems.append(
                    f"{module}: {addon.name} ships an artefact built outside the image "
                    f"({build_dir.relative_to(REPO_ROOT)}) but the Dockerfile does not "
                    f"verify it — the image would ship the add-on with an empty bin/ "
                    f"and the scanner would fail at first use."
                )
    return problems


def test_ai_requests_carry_no_precomposed_prompt() -> list[str]:
    """FEAT-41 / the server-side prompt composition rule — the frontend sends structured fields.

    A request model of an AI endpoint that declares a `user`, `prompt` or
    `user_prompt` field of type `str` is the signature of a prompt already
    composed by the browser, that the backend would merely relay. A guarantee
    can only be held where the prompt is built: FEAT-40 requires the model to
    see the whole measure plan, which is unverifiable if the client decides
    whether to include it.

    This is invisible when reviewing a diff — hence this check.
    """
    suspects = {"user", "prompt", "user_prompt", "system_prompt", "messages"}
    # Modules whose prompts are ALL composed server-side. Every new FEAT-41
    # migration is added HERE: that is what enforces cutting the generic proxy
    # and forbids any pre-composed-prompt model.
    migrated = {"risk", "compliance", "vendor", "audit"}
    # AICompleteRequest IS a pre-composed prompt — that is the contract of the
    # generic /api/ai/complete proxy. The class exists in EVERY module
    # (ai_proxy_common imports it at load time), but in a migrated module the
    # route that reads it is cut off (generic_complete=False, checked below):
    # the guarantee is carried by the cut-off, not by the absence of the class.
    tolerated_class = "AICompleteRequest"
    problems = []
    for route in sorted(list(REPO_ROOT.glob("*/src/routes/ai.py"))
                        + list(REPO_ROOT.glob("*/src/schemas.py"))
                        + list(REPO_ROOT.glob("*/src/ai_proxy_common.py"))):
        module = route.parts[route.parts.index("src") - 1]
        rel = "/".join(route.parts[route.parts.index(module) + 1:])
        try:
            tree = ast.parse(route.read_text(encoding="utf-8"))
        except SyntaxError as e:
            problems.append(f"{module}: {rel} does not parse ({e})")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Any class with a base is a candidate: requiring `BaseModel`
            # among the DIRECT bases let indirect inheritance through
            # (class X(AICompleteRequest)) — and schemas.py was not scanned at
            # all, even though the live violation lived there.
            if not node.bases:
                continue
            if node.name == tolerated_class:
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                    continue
                name = stmt.target.id
                if name not in suspects:
                    continue
                annot = ast.unparse(stmt.annotation)
                if "str" not in annot:
                    continue
                problems.append(
                    f"{module}: {rel}: {node.name}.{name}: {annot} looks like a "
                    f"pre-composed prompt. The frontend must send structured fields "
                    f"and routes/ai.py must build the prompt (the project conventions 5.1)."
                )
    # A migrated module must CUT OFF the generic proxy: without that, a
    # modified client bypasses every business guarantee via /api/ai/complete.
    for module in sorted(migrated):
        route = REPO_ROOT / module / "src" / "routes" / "ai.py"
        if route.exists() and "generic_complete=False" not in route.read_text(encoding="utf-8"):
            problems.append(
                f"{module}: routes/ai.py must call make_ai_router(generic_complete=False) "
                f"— every prompt is composed server-side, the generic proxy is a bypass.")
    return problems


# ── Login pages: each one is its module's own ──────────────────────────
#
# Each module has its own app/login.html, with its name written in it (tab
# title, logo, subtitle). Pages were created by copying another module's:
# AppSec, Surface and Watch said "Access Review", Audit "Asset Management".

def _login_identity(mod: Path) -> dict | None:
    login = mod / "app" / "login.html"
    if not login.exists():
        return None
    html = login.read_text(encoding="utf-8")
    index = (mod / "app" / "index.html").read_text(encoding="utf-8")

    def first(pattern, text):
        m = re.search(pattern, text, re.S)
        return m.group(1).strip() if m else ""

    return {
        "title": first(r"<title>(.*?)</title>", html),
        "logo": first(r'class="login-logo">(.*?)</div>', html),
        "subtitle": first(r'class="login-subtitle">(.*?)</div>', html),
        "app": first(r"<title>(.*?) - CISO Toolbox</title>", index),
    }


def test_every_login_page_names_its_own_module() -> list[str]:
    """No login page carries another module's identity: its logo and
    subtitle are its own (no two modules share one), the tab title starts
    with the logo, and the logo is not another module's application name."""
    problems, pages = [], {}
    for mod in _modules():
        page = _login_identity(mod)
        if page is None:
            problems.append(f"{mod.name}: no app/login.html")
        else:
            pages[mod.name] = page
    for name, page in pages.items():
        if not page["logo"] or not page["subtitle"] or not page["app"]:
            problems.append(f"{name}: login logo, login subtitle or the index.html title not found")
            continue
        if page["title"] != f"{page['logo']} — Sign in":
            problems.append(f"{name}/app/login.html: tab title {page['title']!r} is not "
                            f"'{page['logo']} — Sign in'")
        for other, theirs in pages.items():
            if other == name:
                continue
            if page["logo"] == theirs["logo"]:
                problems.append(f"{name}/app/login.html: same logo as {other} ({page['logo']!r})")
            if page["subtitle"] == theirs["subtitle"]:
                problems.append(f"{name}/app/login.html: same subtitle as {other}")
            if theirs["app"] and page["logo"].lower() == theirs["app"].lower() != page["app"].lower():
                problems.append(f"{name}/app/login.html: logo {page['logo']!r} is {other}'s name")
    return problems


# ── Module roles: one ladder per module, the same in Pilot and the module ─
#
# Pilot's user screen offers, per module, the roles of that module's ladder;
# a standalone module offers the same ones (auth_common.MODULE_ROLES). The two
# tables must agree, and every role of a ladder must be one the module's own
# routes know.

def _pilot_role_ladders() -> dict[str, list[str]]:
    ts = (REPO_ROOT / "pilot" / "app" / "ts" / "Pilot_app.ts").read_text(encoding="utf-8")
    block = re.search(r"var _MODULE_ROLES[^=]*=\s*\{(.*?)\};", ts, re.S)
    if not block:
        return {}
    return {m: [r for r in re.findall(r'"([a-z]*)"', roles) if r]
            for m, roles in re.findall(r"(\w+):\s*\[([^\]]*)\]", block.group(1))}


def _module_role_ladders(mod: Path) -> dict | None:
    common = mod / "src" / "auth_common.py"
    if not common.exists():
        return None
    for node in ast.walk(ast.parse(common.read_text(encoding="utf-8"))):
        target = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else (
            node.target if isinstance(node, ast.AnnAssign) else None)
        if isinstance(target, ast.Name) and target.id == "MODULE_ROLES" and node.value is not None:
            return {k: list(v) for k, v in ast.literal_eval(node.value).items()}
    return None


def test_module_role_ladders_agree() -> list[str]:
    problems = []
    pilot = _pilot_role_ladders()
    if not pilot:
        return ["pilot/app/ts/Pilot_app.ts: _MODULE_ROLES not found"]
    for mod in _modules():
        if not (mod / "src" / "auth_common.py").exists():
            continue  # Pilot: its own src/auth.py, the table lives in its frontend
        ladders = _module_role_ladders(mod)
        if ladders is None:
            problems.append(f"{mod.name}/src/auth_common.py: no MODULE_ROLES")
            continue
        if ladders != pilot:
            problems.append(f"{mod.name}/src/auth_common.py: MODULE_ROLES differs from Pilot's _MODULE_ROLES")
    for mod in _modules():
        if mod.name == "pilot":
            continue  # the orchestrator: no ladder of its own
        ladder = pilot.get(mod.name)
        if ladder is None:
            problems.append(f"{mod.name}: no role ladder in Pilot's _MODULE_ROLES")
            continue
        for path in sorted((mod / "src").rglob("*.py")):
            if path.name == "auth_common.py":
                continue
            for name, roles in re.findall(r"^(_?[A-Z_]*ROLES[A-Z_]*)\s*=\s*\[([^\]]*)\]",
                                          path.read_text(encoding="utf-8"), re.M):
                known = re.findall(r'"([a-z]+)"', roles)
                missing = [r for r in ladder if r not in known]
                if missing:
                    problems.append(f"{mod.name}/{path.relative_to(mod).as_posix()}: {name} lacks {missing}")
    return problems


# ── Write journal: one implementation ─────────────────────────────────
#
# Some modules keep the shared write journal as src/audit.py, a copy the
# propagation does not refresh (it refreshes src/audit_common.py where a
# module has one). A change to the shared journal then reached three modules
# out of nine. Every src/audit.py must stay the shared one.

def _without_header(text: str) -> str:
    lines = text.splitlines()
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    return "\n".join(lines).strip()


def test_every_write_journal_is_the_shared_one() -> list[str]:
    reference = next((m / "src" / "audit_common.py" for m in _modules()
                      if (m / "src" / "audit_common.py").exists()), None)
    if reference is None:
        return ["no module has src/audit_common.py — has the shared journal been renamed?"]
    shared = _without_header(reference.read_text(encoding="utf-8"))
    problems = []
    for mod in _modules():
        copy = mod / "src" / "audit.py"
        if copy.exists() and "def install_write_journal_middleware" in copy.read_text(encoding="utf-8"):
            if _without_header(copy.read_text(encoding="utf-8")) != shared:
                problems.append(f"{mod.name}/src/audit.py differs from the shared write journal "
                                f"({reference.relative_to(REPO_ROOT).as_posix()})")
    return problems


# ── Sign-in routes: one implementation ──────────────────────────────
#
# Every backend module signs in the same way (its key, identity providers,
# Pilot in the suite): its routes/auth.py only mounts the shared router.

def test_every_module_mounts_the_shared_sign_in() -> list[str]:
    problems = []
    for mod in _modules():
        if mod.name == "pilot":
            continue  # the suite's own sign-in
        wrapper = mod / "src" / "routes" / "auth.py"
        if not (mod / "src" / "auth_routes_common.py").exists():
            problems.append(f"{mod.name}: no src/auth_routes_common.py")
        elif not wrapper.exists() or "from src.auth_routes_common import router" not in wrapper.read_text(encoding="utf-8") \
                or any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       for n in ast.walk(ast.parse(wrapper.read_text(encoding="utf-8")))):
            problems.append(f"{mod.name}/src/routes/auth.py is not the shared sign-in's wrapper")
    return problems


CHECKS = (
    ("canonical field names", test_every_receiver_uses_the_canonical_fields),
    ("no pre-composed prompt", test_ai_requests_carry_no_precomposed_prompt),
    ("external artefacts verified", test_externally_built_artefacts_are_verified_at_build),
    ("a push can clear a field", test_every_receiver_can_clear_a_field),
    ("no legacy storage key", test_no_module_reintroduces_a_legacy_key),
    ("every send validates the host", test_every_surface_send_validates_the_host),
    ("mail links use PUBLIC_BASE_URL", test_mail_links_use_the_suite_env_name),
    ("every module can de-provision", test_every_module_can_deprovision),
    ("Pilot pushes reach every module", test_every_module_receives_what_pilot_pushes),
    ("pushed proxy restored at start-up", test_every_module_restores_its_proxy_at_startup),
    ("backups leave out what Pilot pushes", test_backups_leave_out_what_pilot_pushes),
    ("user FKs never block a delete", test_user_fks_never_block_a_delete),
    ("secrets decrypted on read", test_secret_settings_are_decrypted_on_read),
    ("one model catalogue", test_one_model_catalogue_everywhere),
    ("catalogued providers callable", test_every_catalogued_provider_can_be_called),
    ("actions pinned to a commit", test_actions_are_pinned_to_a_commit),
    ("login redirect validated", test_login_redirect_is_validated),
    ("custom-LLM branch guarded", test_every_custom_llm_branch_has_ssrf_guard),
    ("proxy validator delegates", test_every_proxy_validator_delegates_to_the_guard),
    ("each login page is its module's", test_every_login_page_names_its_own_module),
    ("one role ladder per module", test_module_role_ladders_agree),
    ("one write journal", test_every_write_journal_is_the_shared_one),
    ("one sign-in", test_every_module_mounts_the_shared_sign_in),
    ("bundled add-on tiers copied", test_every_bundled_addon_tier_is_copied),
    ("every image installs its lock", test_every_image_installs_its_lock),
    ("bundled add-ons get their deps", test_bundled_addons_get_their_dependencies),
)

# The checks above RETURN their findings — they are consumed by `main()` (the
# CLI) and by the aggregating `test_suite_contracts()` below, which is the real
# pytest entry point. Their `test_*` names would otherwise make pytest collect
# each as a standalone test that returns a list: it "passes" without asserting
# anything (and warns about the returned value), so a broken contract still
# showed green on those lines — only the aggregator actually fails. Mark them
# non-collectable so the single assert below is what enforces the contract.
for _label, _check in CHECKS:
    _check.__test__ = False


def test_suite_contracts() -> None:
    """pytest entry point — one assert carrying every problem found."""
    problems: list[str] = []
    for _, check in CHECKS:
        problems.extend(check())
    assert not problems, "Suite contract violated:\n  " + "\n  ".join(problems)


def main() -> int:
    total = 0
    for label, check in CHECKS:
        problems = check()
        total += len(problems)
        print(f"{'FAIL' if problems else ' OK '}  {label}")
        for p in problems:
            print(f"        {p}")
    print(f"\n{len(_receivers())} receiver(s) checked — "
          f"{total or 'no'} problem(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
