"""CSV export of a PSAT campaign's per-user progress (FEAT-53)."""
from __future__ import annotations

import csv
import io
from types import SimpleNamespace

from src.routes.awareness import _assignments_csv, _cell


def _row(**kw):
    base = dict(last_name="Martin", first_name="Alice", email="a@medsecure.example",
                sent_date="2026-03-01", completion_date="2026-03-10",
                status="completed", psat_status="Completed")
    base.update(kw)
    return SimpleNamespace(**base)


def _parse(text: str) -> list[list[str]]:
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:]), delimiter=";"))


def test_columns_and_translated_status():
    fr = _parse(_assignments_csv([_row(status="completed_late")], "fr"))
    assert fr[0] == ["Nom", "Prénom", "E-mail", "Date d'envoi", "Date de réalisation", "Statut", "Statut PSAT"]
    assert fr[1] == ["Martin", "Alice", "a@medsecure.example", "2026-03-01", "2026-03-10",
                     "Terminé en retard", "Completed"]
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
