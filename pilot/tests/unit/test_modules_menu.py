"""Unit tests for the FEAT-31 module-switcher menu payload.

_menu_payload() is what both GET /api/modules/menu (Pilot frontend) and
GET /api/internal/modules-menu (sibling-module proxies) serve to browsers:
it must never leak internal_url, must prepend Pilot, and must list every
registry row (unreachable != undeployed).
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.routes.modules import _menu_payload  # noqa: E402


def _row(mid, name, ext, internal="http://secret:8080"):
    return SimpleNamespace(id=mid, name=name, external_url=ext,
                           internal_url=internal, status="unreachable")


def test_pilot_prepended_and_all_rows_listed():
    menu = _menu_payload([_row("risk", "Risk", "/risk/"), _row("watch", "Watch", "/watch/")])
    assert [e["id"] for e in menu] == ["pilot", "risk", "watch"]


def test_no_internal_url_leak():
    menu = _menu_payload([_row("risk", "Risk", "/risk/")])
    for e in menu:
        assert set(e.keys()) == {"id", "name", "url"}
        assert "secret" not in str(e.values())


def test_urls_come_from_external_url():
    menu = _menu_payload([_row("compliance", "Compliance", "/compliance/")])
    assert menu[1]["url"] == "/compliance/"
