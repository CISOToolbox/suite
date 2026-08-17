"""Unit tests for the connector-sync retire reconciliation.

`_reconcile_retired()` is the pure core of the "assets go to Retire when the
connector that added them stops returning them" feature:
  - an asset is retired only once NO connector still returns it;
  - a multi-source asset stays active while any owner still reports it;
  - legacy rows without a `seen` map are seeded from `keys`, so they can't be
    mass-retired on the first sync after this feature shipped;
  - purely manual assets (no connector keys) are never touched.
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

from routes.plugins import _reconcile_retired  # noqa: E402

NOW = datetime(2026, 6, 1, 12, 0, 0)


class _Asset:
    """Minimal stand-in: the helper only touches these four attributes."""
    def __init__(self, id, sources, statut="actif"):
        self.id = id
        self.sources = sources
        self.statut = statut
        self.updated_at = None


def _seen(*plugins):
    return {p: "2026-05-01T00:00:00" for p in plugins}


def test_retire_when_sole_owner_drops_it():
    a = _Asset("A-001", {"keys": {"p1": "k1"}, "seen": _seen("p1")})
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 1
    assert a.statut == "retire"
    assert a.sources["seen"] == {}
    assert a.sources["fields"]["statut"] == "p1"
    assert a.updated_at == NOW


def test_kept_active_when_other_connector_still_sees_it():
    a = _Asset("A-002", {"keys": {"p1": "k1", "p2": "k2"}, "seen": _seen("p1", "p2")})
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "actif"
    assert "p1" not in a.sources["seen"]
    assert "p2" in a.sources["seen"]


def test_legacy_multi_source_seeded_from_keys_not_retired():
    # No "seen" map (pre-feature row); p1 absent, p2 still owns it.
    a = _Asset("A-003", {"keys": {"p1": "k1", "p2": "k2"}})
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "actif"
    assert a.sources["seen"] == {"p2": NOW.isoformat()}


def test_legacy_sole_owner_retired():
    a = _Asset("A-004", {"keys": {"p1": "k1"}})  # no seen map
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 1
    assert a.statut == "retire"


def test_present_asset_untouched():
    a = _Asset("A-005", {"keys": {"p1": "k1"}, "seen": _seen("p1")})
    n = _reconcile_retired([a], present_ids={"A-005"}, plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "actif"
    assert a.sources["seen"] == _seen("p1")  # untouched (returned this run)


def test_asset_not_owned_by_plugin_untouched():
    a = _Asset("A-006", {"keys": {"p2": "k2"}, "seen": _seen("p2")})
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "actif"
    assert a.sources["seen"] == _seen("p2")


def test_already_retired_not_recounted():
    a = _Asset("A-007", {"keys": {"p1": "k1"}, "seen": _seen("p1")}, statut="retire")
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "retire"
    assert a.sources["seen"] == {}  # seen still updated even if no transition


def test_manual_asset_without_keys_untouched():
    a = _Asset("A-008", {})  # purely manual, no connector keys
    n = _reconcile_retired([a], present_ids=set(), plugin_id="p1", now=NOW)
    assert n == 0
    assert a.statut == "actif"


def test_counts_multiple_retired():
    a1 = _Asset("A-101", {"keys": {"p1": "k"}, "seen": _seen("p1")})
    a2 = _Asset("A-102", {"keys": {"p1": "k"}, "seen": _seen("p1")})
    present = _Asset("A-103", {"keys": {"p1": "k"}, "seen": _seen("p1")})
    n = _reconcile_retired([a1, a2, present], present_ids={"A-103"}, plugin_id="p1", now=NOW)
    assert n == 2
    assert a1.statut == "retire" and a2.statut == "retire"
    assert present.statut == "actif"
