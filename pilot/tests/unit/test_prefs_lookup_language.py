"""Regression: an account that saved no preference has chosen no language.

The lookup the module mailers call answered ``"lang": "en"`` for an account
without a stored row, as if English had been chosen: AppSec then ignored the
language set on the application, and its alerts went out in English. Such an
account now answers an empty language and the module applies its own.
"""
import asyncio
from types import SimpleNamespace

from src.routes import internal
from src.routes.notifications import _dict, _lookup_dict


def _row(lang: str) -> SimpleNamespace:
    return SimpleNamespace(enabled=True, day_of_week=1, upcoming_days=14, include_overdue=True,
                           scope="mine", modules=[], lang=lang, subject_prefix="",
                           module_prefs={})


def test_an_account_without_preferences_tells_the_modules_no_language():
    assert _lookup_dict(None)["lang"] == ""


def test_the_rest_of_the_defaults_is_unchanged():
    told, shown = _lookup_dict(None), _dict(None)
    assert {k: v for k, v in told.items() if k != "lang"} == {k: v for k, v in shown.items() if k != "lang"}
    # the account's own page still opens on English
    assert shown["lang"] == "en"


def test_a_saved_language_is_told_as_it_is():
    assert _lookup_dict(_row("fr"))["lang"] == "fr"
    assert _lookup_dict(_row("en"))["lang"] == "en"


class _Request:
    def __init__(self, emails):
        self.headers = {"X-Service-Token": "lookup-token"}
        self._emails = emails

    async def json(self):
        return {"emails": self._emails}


class _Db:
    """Answers the lookup query with the rows of an outer join."""

    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _query):
        return SimpleNamespace(all=lambda: self._rows)


def test_the_lookup_route_tells_no_language_for_an_account_without_preferences(monkeypatch):
    monkeypatch.setattr(internal, "SERVICE_TOKEN", "lookup-token")
    rows = [(SimpleNamespace(email="New@MedSecure.example"), None),
            (SimpleNamespace(email="ciso@medsecure.example"), _row("fr"))]
    told = asyncio.run(internal.internal_lookup_prefs(
        _Request(["new@medsecure.example", "ciso@medsecure.example"]), _Db(rows)))
    assert told["new@medsecure.example"]["lang"] == ""
    assert told["ciso@medsecure.example"]["lang"] == "fr"
