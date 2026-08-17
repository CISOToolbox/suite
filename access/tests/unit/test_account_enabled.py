"""Unit: account_enabled (IdP active/disabled state) wiring — FEAT-16.

Mirrors the last_login_at pipeline: UserRecord field → SiUser/ReviewEntry
columns (migration 013) → connectors normalize their active signal → review
import propagates it.
"""
import os

from src.plugins.base import UserRecord

HERE = os.path.dirname(__file__)
PLUGINS = os.path.join(HERE, "..", "..", "src", "plugins")


def _src(name: str) -> str:
    with open(os.path.join(PLUGINS, name)) as f:
        return f.read()


def test_userrecord_has_account_enabled_default_none():
    r = UserRecord(email="a@b.c")
    assert r.account_enabled is None
    assert UserRecord(email="a@b.c", account_enabled=True).account_enabled is True
    assert UserRecord(email="a@b.c", account_enabled=False).account_enabled is False


def test_migration_adds_account_enabled_to_both_tables():
    mig = os.path.join(HERE, "..", "..", "alembic", "versions", "013_account_enabled.py")
    s = open(mig).read()
    assert 'add_column("si_users"' in s and "account_enabled" in s
    assert 'add_column("review_entries"' in s


def test_connectors_normalize_account_enabled():
    """Every connector that exposes an active signal sets account_enabled."""
    for name in ("entra_id.py", "m365.py", "okta.py", "gitlab.py",
                 "google_workspace.py", "jumpcloud.py", "jira_confluence.py",
                 "servicenow.py", "ldap_ad.py"):
        assert "account_enabled=" in _src(name), f"{name}: account_enabled not set on UserRecord"


def test_review_import_propagates_account_enabled():
    reviews = os.path.join(HERE, "..", "..", "src", "routes", "reviews.py")
    s = open(reviews).read()
    # refreshed on the matched SiUser, the existing entry, and new entries —
    # guarded on `is not None` so a False (disabled) value is persisted.
    assert "ur.account_enabled is not None" in s
    assert "account_enabled=ur.account_enabled" in s
