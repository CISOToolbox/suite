"""CSV export of a PSAT campaign's per-user progress (FEAT-53)."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from src.routes.awareness import _assignments_csv, _cell, _data_day, _zone

_SYNC = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)


def _row(**kw):
    base = dict(last_name="Martin", first_name="Alice", email="a@medsecure.example",
                sent_date="2026-03-01", completion_date="2026-03-10",
                status="completed", psat_status="Completed", synced_at=_SYNC)
    base.update(kw)
    return SimpleNamespace(**base)


def _parse(text: str) -> list[list[str]]:
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:]), delimiter=";"))


def test_columns_and_translated_status():
    fr = _parse(_assignments_csv([_row(status="completed_late")], "fr"))
    assert fr[0] == ["Nom", "Prénom", "E-mail", "Date d'envoi", "Date de réalisation", "Statut", "Statut PSAT",
                     "Données au"]
    assert fr[1] == ["Martin", "Alice", "a@medsecure.example", "2026-03-01", "2026-03-10",
                     "Terminé en retard", "Completed", "2026-11-02 23:30 UTC"]
    en = _parse(_assignments_csv([_row(status="excluded", completion_date="")], "en"))
    assert en[0][0] == "Last name" and en[1][4:6] == ["", "Excluded"]


def test_unknown_language_falls_back_to_english():
    assert _parse(_assignments_csv([], "de"))[0][0] == "Last name"


def test_formulas_are_neutralised():
    assert _cell("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert [_cell(v) for v in ("+1", "-1", "@a", "\tx")] == ["'+1", "'-1", "'@a", "'\tx"]
    assert _cell("Durand-Petit") == "Durand-Petit"
    # A leading space or line break does not hide a formula from the check.
    assert [_cell(v) for v in (" =1+1", "\n=1")] == ["' =1+1", "'\n=1"]
    rows = _parse(_assignments_csv([_row(last_name="=cmd|' /C calc'!A0")], "en"))
    assert rows[1][0].startswith("'=")


def test_separator_inside_a_value_is_quoted():
    rows = _parse(_assignments_csv([_row(last_name="Doe; Jr")], "en"))
    assert rows[1][0] == "Doe; Jr"


def test_rows_carry_their_sync_in_the_viewer_time_zone():
    rows = _parse(_assignments_csv([_row()], "en", timezone(timedelta(hours=1))))
    assert rows[0][-1] == "Data as of"
    assert rows[1][-1] == "2026-11-03 00:30 UTC+01:00"


def test_file_is_named_after_the_day_of_its_data():
    old = datetime(2026, 10, 30, 8, 0, tzinfo=timezone.utc)
    rows = [_row(synced_at=old), _row(synced_at=_SYNC)]
    assert _data_day(rows, timezone.utc) == "2026-11-02"
    assert _data_day(rows, timezone(timedelta(hours=1))) == "2026-11-03"


def test_offset_from_the_browser_or_utc():
    assert _zone(None) is timezone.utc and _zone(0) is timezone.utc
    assert _zone(60) == timezone(timedelta(hours=1))
    assert _zone(-330).utcoffset(None) == timedelta(minutes=-330)


def test_a_naive_timestamp_is_read_as_utc_whatever_the_host_zone():
    naive = _row(synced_at=_SYNC.replace(tzinfo=None))
    assert _parse(_assignments_csv([naive], "en"))[1][-1] == "2026-11-02 23:30 UTC"
    assert _data_day([naive], timezone(timedelta(hours=1))) == "2026-11-03"
