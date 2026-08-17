"""Unit tests for the renewal deadline selection logic.

compute_due_echeances() is the single source of truth for "what gets
alerted": it must mirror the frontend _echeances() in Asset_app.js — a
deadline is selected only when it is overdue or within its notice window
(licence: preavis_jours, default 30; hardware fin_support/fin_vie: 90 d).
"""
import os
import sys
from datetime import date, timedelta
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from renewal_scheduler import compute_due_echeances  # noqa: E402

TODAY = date(2026, 6, 8)


def _asset(aid, nom="", fin_support="", fin_vie="", licence=None):
    return SimpleNamespace(id=aid, nom=nom, fin_support=fin_support,
                           fin_vie=fin_vie, licence=licence or {})


def _iso(days_from_today):
    return (TODAY + timedelta(days=days_from_today)).isoformat()


def test_licence_within_default_notice_is_selected():
    a = _asset("A-1", licence={"date_renouvellement": _iso(20)})  # 20 <= 30
    out = compute_due_echeances([a], TODAY)
    assert len(out) == 1
    assert out[0]["kind"] == "licence" and out[0]["days"] == 20


def test_licence_beyond_notice_is_excluded():
    a = _asset("A-1", licence={"date_renouvellement": _iso(45)})  # 45 > 30
    assert compute_due_echeances([a], TODAY) == []


def test_custom_preavis_is_respected():
    a = _asset("A-1", licence={"date_renouvellement": _iso(45), "preavis_jours": 60})
    out = compute_due_echeances([a], TODAY)
    assert len(out) == 1 and out[0]["days"] == 45


def test_overdue_licence_has_negative_days():
    a = _asset("A-1", licence={"date_renouvellement": _iso(-5)})
    out = compute_due_echeances([a], TODAY)
    assert out[0]["days"] == -5


def test_hardware_support_uses_90_day_window():
    inside = _asset("A-1", fin_support=_iso(80))
    outside = _asset("A-2", fin_support=_iso(120))
    out = compute_due_echeances([inside, outside], TODAY)
    assert [e["asset_id"] for e in out] == ["A-1"]
    assert out[0]["kind"] == "support"


def test_fin_vie_selected_within_window():
    a = _asset("A-1", fin_vie=_iso(30))
    out = compute_due_echeances([a], TODAY)
    assert out[0]["kind"] == "vie"


def test_all_three_kinds_for_one_asset():
    a = _asset("A-1", fin_support=_iso(10), fin_vie=_iso(20),
               licence={"date_renouvellement": _iso(5)})
    kinds = sorted(e["kind"] for e in compute_due_echeances([a], TODAY))
    assert kinds == ["licence", "support", "vie"]


def test_empty_and_invalid_dates_are_ignored():
    a = _asset("A-1", fin_support="", fin_vie="not-a-date",
               licence={"date_renouvellement": None})
    assert compute_due_echeances([a], TODAY) == []


def test_sorted_soonest_first():
    a = _asset("A-1", fin_support=_iso(80), fin_vie=_iso(-3),
               licence={"date_renouvellement": _iso(10)})
    days = [e["days"] for e in compute_due_echeances([a], TODAY)]
    assert days == sorted(days)
    assert days[0] == -3  # overdue first
