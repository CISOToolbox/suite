"""Regression: a scope makes the organisation's SMTP send LLM-written mail.

Any account, viewer included, could create a scope, give it a 10 000-char
threat prompt run with web search, and address it to any mailbox; the
preview ran the LLM on every reload. Now: editing a scope, its targets or its
recipients needs a role that can edit, a threat prompt needs AI access, a
recipient must be known (directory, Watch account, allowed domain), and the
preview only runs the LLM for AI users, within a rate limit.
"""
import asyncio
import html
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import digest, scopes, targets  # noqa: E402


class _Result:
    def __init__(self, value=None, row=None):
        self._value = value
        self._row = row

    def scalar_one_or_none(self):
        return self._value

    def first(self):
        return self._row

    def scalars(self):
        return SimpleNamespace(all=lambda: [], __iter__=lambda: iter([]))


class _FakeDB:
    """The first query loads the scope, the second finds `then` (the target
    to edit; None = no existing recipient or target). `account` is the email
    of an existing Watch account: a query bound to that exact address finds
    it."""

    def __init__(self, scope=None, account=None, then=None):
        self.added = []
        self.scope = scope
        self.account = account
        self.then = then
        self._calls = 0

    async def execute(self, _stmt):
        self._calls += 1
        if self._calls == 1 and self.scope is not None:
            return _Result(self.scope)
        if self._calls == 2 and self.then is not None:
            return _Result(self.then)
        bound = _stmt.compile().params.values()
        return _Result(None, (uuid.uuid4(),) if self.account in bound else None)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass

    async def flush(self):
        pass


def _user(module_role, ai="false", role="user"):
    u = SimpleNamespace(id=uuid.uuid4(), email="u@medsecure.local", name="U",
                        role=role, ai_enabled=ai)
    u._module_role = module_role
    return u


def _scope(owner, prompt=""):
    return SimpleNamespace(id=uuid.uuid4(), owner_id=owner.id, name="MedSecure",
                           threat_prompt=prompt)


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    async def _noop(*_a, **_k):
        return None
    monkeypatch.setattr(scopes, "log_action", _noop)
    monkeypatch.setattr(scopes, "_scope_to_response", lambda *a, **k: None)
    monkeypatch.setattr(scopes, "_load_recipients", lambda *a, **k: _async([]))
    monkeypatch.setattr(scopes, "_owner_email", lambda *a, **k: _async(""))


def _async(value):
    async def _v():
        return value
    return _v()


def _create_body(prompt=""):
    return scopes.ScopeCreate(name="MedSecure", threat_prompt=prompt)


# ── Role gate ────────────────────────────────────────────────────

@pytest.mark.parametrize("call", [
    lambda u, db: scopes.create_scope(_create_body(), None, u, db),
    lambda u, db: scopes.update_scope(db.scope.id, scopes.ScopeUpdate(name="x"), None, u, db),
    lambda u, db: scopes.add_recipient(db.scope.id, scopes.ScopeRecipientAdd(email="a@medsecure.local"), None, u, db),
    lambda u, db: targets.create_target(db.scope.id, targets.WatchTargetCreate(kind="keyword", value="medsecure"), None, u, db),
    lambda u, db: targets.update_target(db.scope.id, uuid.uuid4(), targets.WatchTargetUpdate(), None, u, db),
], ids=["create", "update", "recipient", "target-create", "target-update"])
def test_viewer_cannot_edit_a_scope(request, _directory, call):
    # `_directory` makes the recipient address known: only the role refuses.
    viewer = _user("viewer")
    scope = _scope(viewer)
    target = None
    if request.node.callspec.id == "target-update":
        now = datetime.now(timezone.utc)
        target = SimpleNamespace(id=uuid.uuid4(), scope_id=scope.id, kind="keyword", value="medsecure",
                                 label="", version_constraint="", notes="", enabled=True,
                                 created_at=now, updated_at=now)
    db = _FakeDB(scope, then=target)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(call(viewer, db))
    assert exc.value.status_code == 403
    assert exc.value.detail == "Requires a role that can edit"
    assert db.added == []


# ── Threat prompt needs AI access ────────────────────────────────

def test_prompt_on_create_needs_ai_access():
    db = _FakeDB()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(scopes.create_scope(_create_body("ransomware"), None, _user("editor"), db))
    assert exc.value.status_code == 403
    assert db.added == []


def test_create_without_prompt_or_with_ai_access_passes():
    db = _FakeDB()
    asyncio.run(scopes.create_scope(_create_body(), None, _user("editor"), db))
    asyncio.run(scopes.create_scope(_create_body("ransomware"), None, _user("editor", ai="true"), db))
    assert len(db.added) == 2


def test_new_prompt_on_update_needs_ai_access():
    editor = _user("editor")
    db = _FakeDB(_scope(editor, prompt="ransomware"))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(scopes.update_scope(db.scope.id, scopes.ScopeUpdate(threat_prompt="phishing"), None, editor, db))
    assert exc.value.status_code == 403
    assert db.scope.threat_prompt == "ransomware"


def test_unchanged_or_cleared_prompt_on_update_passes():
    editor = _user("editor")
    scope = _scope(editor, prompt="ransomware")
    asyncio.run(scopes.update_scope(scope.id, scopes.ScopeUpdate(threat_prompt="ransomware"), None, editor, _FakeDB(scope)))
    asyncio.run(scopes.update_scope(scope.id, scopes.ScopeUpdate(threat_prompt=""), None, editor, _FakeDB(scope)))
    assert scope.threat_prompt == ""


# ── Recipients must be known ─────────────────────────────────────

@pytest.fixture
def _directory(monkeypatch):
    # raising=False: these names do not exist before the fix, and the tests
    # must then fail on their assertions, not in this fixture.
    monkeypatch.setattr(scopes, "_ALLOWED_EMAIL_DOMAINS", ("medsecure.local",), raising=False)
    monkeypatch.setattr(scopes, "_get_directory_source", lambda _db: _async("local"), raising=False)
    monkeypatch.setattr(scopes, "list_local_personnel",
                        lambda _db: _async([{"email": "Auditor@Partner.example"}]), raising=False)


def _add(email, user, account=None):
    owner = user or _user("editor")
    db = _FakeDB(_scope(owner), account=account)
    asyncio.run(scopes.add_recipient(db.scope.id, scopes.ScopeRecipientAdd(email=email), None, user, db))
    return db


@pytest.mark.parametrize("email", ["a@medsecure.local", "auditor@partner.example"])
def test_known_recipient_is_added(_directory, email):
    assert len(_add(email, _user("editor")).added) == 1


def test_watch_account_is_added(_directory):
    db = _add("colleague@elsewhere.example", _user("editor"), account="colleague@elsewhere.example")
    assert len(db.added) == 1


@pytest.mark.parametrize("email,account", [
    ("victim@elsewhere.example", None),
    # another address has an account: only the exact address counts
    ("victim@elsewhere.example", "colleague@elsewhere.example"),
    # neighbours of the allowed domain are not that domain
    ("victim@evilmedsecure.local", None),
    ("victim@sub.medsecure.local", None),
    ("victim@medsecure.local.evil.example", None),
    # a directory address contained in the requested one is not that address
    ("xauditor@partner.example", None),
])
def test_unknown_recipient_is_refused(_directory, email, account):
    with pytest.raises(HTTPException) as exc:
        _add(email, _user("editor"), account=account)
    assert exc.value.status_code == 403


def test_unreachable_pilot_directory_refuses(monkeypatch, _directory):
    monkeypatch.setattr(scopes, "_get_directory_source", lambda _db: _async("pilot"), raising=False)
    monkeypatch.setattr(scopes, "_fetch_pilot_directory", lambda: _async([]), raising=False)
    with pytest.raises(HTTPException) as exc:
        _add("auditor@partner.example", _user("editor"))
    assert exc.value.status_code == 403


def test_pilot_directory_entry_is_added(monkeypatch, _directory):
    monkeypatch.setattr(scopes, "_get_directory_source", lambda _db: _async("pilot"), raising=False)
    monkeypatch.setattr(scopes, "_fetch_pilot_directory",
                        lambda: _async([{"email": "auditor@partner.example"}]), raising=False)
    assert len(_add("auditor@partner.example", _user("editor")).added) == 1


@pytest.mark.parametrize("user", [None, _user("", role="admin"), _user("admin")])
def test_admins_may_address_anyone(_directory, user):
    assert len(_add("victim@elsewhere.example", user).added) == 1


# ── Preview runs the LLM only for AI users, within a limit ───────

LIMIT = 5  # PREVIEW_LLM_LIMIT


class _Calls(list):
    skipped: list


@pytest.fixture
def _preview(monkeypatch):
    calls = _Calls()

    async def _brief(*_a, **_k):
        calls.append(1)
        return "<p>brief</p>", []
    monkeypatch.setattr(digest, "_render_threat_brief", _brief)
    monkeypatch.setattr(digest, "_alerts_for_scope", lambda *a, **k: _async([]))
    calls.skipped = []
    monkeypatch.setattr(digest, "render_html",
                        lambda *a, **k: calls.skipped.append(k.get("threat_skipped", "")) or "")
    if hasattr(digest, "RateLimiter"):
        monkeypatch.setattr(digest, "_preview_limiter", digest.RateLimiter())
    return calls


def test_preview_skips_the_brief_without_ai_access(monkeypatch, _preview):
    editor = _user("editor")
    monkeypatch.setattr(digest, "_user_scopes", lambda *a: _async([_scope(editor, "ransomware")]))
    asyncio.run(digest.preview_digest(None, editor, None))
    assert _preview == []
    assert _preview.skipped == ["no_ai"]


def test_preview_briefs_are_capped_per_llm_call(monkeypatch, _preview):
    editor = _user("editor", ai="true")
    two = [_scope(editor, "ransomware"), _scope(editor, "phishing")]
    monkeypatch.setattr(digest, "_user_scopes", lambda *a: _async(two))
    # Each request asks for two briefs: the third request goes over the cap
    # and still renders, the rest of it without a brief.
    for _ in range(LIMIT):
        asyncio.run(digest.preview_digest(None, editor, None))
    assert len(_preview) == LIMIT
    # the preview says why the remaining briefs are missing
    assert _preview.skipped.count("rate_limited") == 2 * LIMIT - LIMIT


@pytest.mark.parametrize("reason,text", [
    ("no_ai", "accès à l'IA"),
    ("rate_limited", "limite d'aperçus"),
])
def test_preview_html_states_the_skip_reason(reason, text):
    from src.digest import render_html
    page = html.unescape(render_html("MedSecure", [], {}, language="fr", threat_skipped=reason))
    assert text in page
    assert "clé Anthropic" not in page
