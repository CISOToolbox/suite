"""Unit tests for the FEAT-32 cache re-key on composite-format change.

When a module switches its source_id format ("<id>@<uuid>" → "<uuid8>:<id>",
audit), the sync must adopt the legacy row in place — same MeasureCache.id —
so ProjectMeasureLink rows survive, instead of insert-new + purge-old.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.routes.measures import _legacy_source_equiv  # noqa: E402

UUID = "9f206ff0-5c78-409c-87e1-000000000000"


def _row(source_id, entity_id=UUID):
    return SimpleNamespace(source_id=source_id, entity_id=entity_id)


def test_adopts_legacy_audit_row():
    legacy = _row(f"MES-001@{UUID}")
    by_source = {legacy.source_id: legacy}
    assert _legacy_source_equiv(f"{UUID[:8]}:MES-001", UUID, by_source) is legacy


def test_no_match_on_different_entity():
    legacy = _row(f"MES-001@{UUID}")
    by_source = {legacy.source_id: legacy}
    other = "12345678-0000-0000-0000-000000000000"
    assert _legacy_source_equiv("12345678:MES-001", other, by_source) is None


def test_plain_ids_never_rekey():
    by_source = {"MES-001": _row("MES-001", "")}
    assert _legacy_source_equiv("MES-002", "", by_source) is None


def test_risk_style_composites_without_legacy_sibling():
    # risk already used ":" — no "@" sibling exists, insert path untouched.
    by_source = {"4e2f5e79:M-01": _row("4e2f5e79:M-01", "4e2f5e79-full")}
    assert _legacy_source_equiv("4e2f5e79:M-02", "4e2f5e79-full", by_source) is None
