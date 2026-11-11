"""The findings list keeps the rows a filter row includes and drops the rows
it excludes.

`_include_exclude` backs the severity, scanner and status rows of
`GET /api/findings`: a value passes when it is one of the included values
(or nothing is included) and none of the excluded ones. A missing value is
never excluded, the way the browser filters. Run against an in-memory
SQLite table so the SQL itself is checked, NULL handling included.

    pytest tests/unit/test_findings_filters.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ.setdefault("AUTH_MODE", "none")

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, select  # noqa: E402

from src.routes.findings import _include_exclude  # noqa: E402

_meta = MetaData()
_rows = Table("rows", _meta, Column("id", Integer, primary_key=True), Column("status", String))
_DATA = {1: "new", 2: "to_fix", 3: "false_positive", 4: "fixed", 5: None}


def _ids(include, exclude):
    engine = create_engine("sqlite://")
    _meta.create_all(engine)
    with engine.begin() as conn:
        conn.execute(_rows.insert(), [{"id": k, "status": v} for k, v in _DATA.items()])
        query = _include_exclude(select(_rows.c.id), _rows.c.status, include, exclude)
        return sorted(r[0] for r in conn.execute(query))


def test_no_filter_keeps_everything():
    assert _ids(None, None) == [1, 2, 3, 4, 5]


def test_include_keeps_only_the_included_values():
    assert _ids(["new", "to_fix"], None) == [1, 2]


def test_exclude_drops_the_excluded_values_and_keeps_missing_ones():
    assert _ids(None, ["false_positive", "fixed"]) == [1, 2, 5]


def test_include_and_exclude_combine():
    assert _ids(["new", "fixed"], ["fixed"]) == [1]


def test_empty_values_are_ignored():
    assert _ids([""], [""]) == [1, 2, 3, 4, 5]
