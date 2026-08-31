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
    route and had never been given the decryption the shared master does.

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
    """AI_PROVIDERS as declared by the shared Python master (via AST)."""
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

    Python side is now a single master imported by both; the browser copy
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
GUARD_CALLS = ("resolve_safe_url", "resolve_safe_target")


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


def test_every_proxy_validator_delegates_to_the_guard() -> list[str]:
    problems, checked = [], 0
    for mod in _modules():
        internal = mod / "src" / "routes" / "internal.py"
        if not internal.exists():
            continue
        src = internal.read_text(encoding="utf-8")
        if "def _validate_proxy_url" not in src:
            continue
        checked += 1
        if "from src.ssrf_guard import" not in src:
            problems.append(f"{mod.name}/internal.py _validate_proxy_url does not delegate to ssrf_guard")
    if not checked:
        problems.append("no module defines _validate_proxy_url — has it been renamed?")
    return problems


# ── Add-ons : ce qui est livre doit etre chargeable ────────────────────
#
# Access a expedie pendant un temps une image sans AUCUN de ses 22 connecteurs :
# ils vivent sous addons/generic/ et le Dockerfile ne copiait que src/, app/ et
# alembic/. Rien ne le signalait — le chargeur emet au mieux un avertissement et
# l'interface affiche une grille vide. Le README promettait 22 connecteurs,
# l'API en renvoyait zero, et tous les controles etaient au vert.
#
# La regle n'est pas "tout embarquer" : Surface laisse volontairement son palier
# generic optionnel (scanners lourds, superposes par build-client-image.sh).
# Elle est : tout palier non vide doit etre soit embarque, soit declare optionnel
# ici, avec sa raison.
OPTIONAL_ADDON_TIERS = {
    ("surface", "generic"): "scanners lourds/optionnels, superposes par build-client-image.sh",
    ("surface", "custom"): "add-ons specifiques client",
    ("access", "custom"): "connecteurs specifiques client",
}


def _final_stage(dockerfile: str) -> str:
    """Le contenu de la derniere etape FROM d'un Dockerfile multi-stage."""
    parts = re.split(r'^FROM\s', dockerfile, flags=re.M)
    return parts[-1] if parts else dockerfile


def _addon_tiers() -> list[tuple[str, str, int]]:
    """(module, palier, nombre d'add-ons) pour chaque palier non vide."""
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
        # Seule la DERNIERE etape compte : un COPY dans le builder (pour
        # installer les deps) ne met rien dans l'image finale — il l'efface
        # meme. Un premier jet de ce controle matchait ce COPY-la et laissait
        # passer la panne qu'il etait cense attraper.
        src = _final_stage(dockerfile.read_text(encoding="utf-8"))
        if not re.search(rf'^COPY\b[^#\n]*addons/{tier}\b', src, re.M):
            problems.append(
                f"{module}: {n} add-on(s) in addons/{tier}/ but the Dockerfile never "
                f"COPYs them — the image would ship none. Bundle the tier, or declare "
                f"it in OPTIONAL_ADDON_TIERS with a reason."
            )
    return problems


def test_bundled_addons_get_their_dependencies() -> list[str]:
    """Un add-on embarque dont les deps manquent est ignore avec un simple
    avertissement : vingt connecteurs marchent, trois non, et rien ne le dit."""
    problems = []
    for module, tier, _n in _addon_tiers():
        if (module, tier) in OPTIONAL_ADDON_TIERS:
            continue
        reqs = list((REPO_ROOT / module / "addons" / tier).glob("*/requirements.txt"))
        if not reqs:
            continue
        dockerfile = REPO_ROOT / module / "Dockerfile"
        if not dockerfile.is_file():
            continue
        src = dockerfile.read_text(encoding="utf-8")
        installs = re.search(r'addons?[^\n]*requirements\.txt|requirements\.txt[^\n]*addons', src) \
            or re.search(r'find\s+\S*addons\S*\s+-name\s+requirements\.txt', src)
        if not installs:
            names = ", ".join(sorted(r.parent.name for r in reqs))
            problems.append(
                f"{module}: {len(reqs)} bundled add-on(s) ship their own requirements.txt "
                f"({names}) but the Dockerfile never installs them — they would load "
                f"broken while the others work."
            )
    return problems


CHECKS = (
    ("canonical field names", test_every_receiver_uses_the_canonical_fields),
    ("a push can clear a field", test_every_receiver_can_clear_a_field),
    ("no legacy storage key", test_no_module_reintroduces_a_legacy_key),
    ("every send validates the host", test_every_surface_send_validates_the_host),
    ("mail links use PUBLIC_BASE_URL", test_mail_links_use_the_suite_env_name),
    ("every module can de-provision", test_every_module_can_deprovision),
    ("user FKs never block a delete", test_user_fks_never_block_a_delete),
    ("secrets decrypted on read", test_secret_settings_are_decrypted_on_read),
    ("one model catalogue", test_one_model_catalogue_everywhere),
    ("catalogued providers callable", test_every_catalogued_provider_can_be_called),
    ("actions pinned to a commit", test_actions_are_pinned_to_a_commit),
    ("login redirect validated", test_login_redirect_is_validated),
    ("custom-LLM branch guarded", test_every_custom_llm_branch_has_ssrf_guard),
    ("proxy validator delegates", test_every_proxy_validator_delegates_to_the_guard),
    ("bundled add-on tiers copied", test_every_bundled_addon_tier_is_copied),
    ("bundled add-ons get their deps", test_bundled_addons_get_their_dependencies),
)


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
