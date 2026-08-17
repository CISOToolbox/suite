import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from routes.entitlements import _can_edit


class _U:
    def __init__(self, email, role="user"):
        self.email = email
        self._module_role = role


class _S:
    def __init__(self, email, manager_email=""):
        self.email = email
        self.manager_email = manager_email


# alice -> bob -> carol (ascending managers)
ALICE = _S("alice@x", "bob@x")
BOB = _S("bob@x", "carol@x")
CAROL = _S("carol@x", "")
BY_EMAIL = {"alice@x": ALICE, "bob@x": BOB, "carol@x": CAROL}


class TestCanEdit:
    def test_admin_always(self):
        assert _can_edit(_U("x@x", "admin"), ALICE, BY_EMAIL) is True

    def test_no_auth_user_is_admin(self):
        assert _can_edit(None, ALICE, BY_EMAIL) is True

    def test_direct_manager(self):
        assert _can_edit(_U("bob@x"), ALICE, BY_EMAIL) is True

    def test_skip_level_manager(self):
        """Manager's manager can edit too (decision 2)."""
        assert _can_edit(_U("carol@x"), ALICE, BY_EMAIL) is True

    def test_unrelated_denied(self):
        assert _can_edit(_U("dave@x"), ALICE, BY_EMAIL) is False

    def test_self_is_not_own_manager(self):
        assert _can_edit(_U("alice@x"), ALICE, BY_EMAIL) is False

    def test_cycle_terminates(self):
        a = _S("a@x", "b@x")
        b = _S("b@x", "a@x")
        be = {"a@x": a, "b@x": b}
        assert _can_edit(_U("c@x"), a, be) is False
