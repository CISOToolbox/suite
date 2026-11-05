"""The PSAT detail and its CSV export carry the date of their data (FEAT-63).

A failed sync leaves the previous per-user snapshot in place: the export must
not look like today's data when it is days old.
"""
from datetime import datetime, timezone

import pytest

from src.connectors.proofpoint_psat import DETAIL_KEY
from src.models import AppSettings, PsatAssignment

pytestmark = pytest.mark.asyncio

_OLD = datetime(2026, 10, 30, 23, 30, tzinfo=timezone.utc)


async def _seed(db):
    db.add_all([
        PsatAssignment(campaign="Phishing 2026", email="a@medsecure.example", last_name="Martin",
                       first_name="Alice", status="pending", synced_at=_OLD),
        AppSettings(key=DETAIL_KEY, value='{"campaigns": [], "generated_at": "2026-11-05T08:00:00+00:00"}'),
    ])
    await db.commit()


async def test_detail_reports_per_campaign_when_the_export_rows_were_synced(client, db):
    await _seed(db)
    data = (await client.get("/api/awareness")).json()
    assert data["generated_at"] == "2026-11-05T08:00:00+00:00"
    # Keyed as the export looks a campaign up; the offset reaches the browser.
    assert data["assignments_synced_at"] == {"phishing 2026": "2026-10-30T23:30:00+00:00"}


async def test_a_campaign_without_rows_has_no_export_date(client, db):
    # A campaign added just before a failed per-user write: the panel shows it,
    # the table does not, and it must not borrow another campaign's date.
    db.add_all([
        PsatAssignment(campaign="Phishing 2026", email="a@medsecure.example", status="pending",
                       synced_at=_OLD),
        AppSettings(key=DETAIL_KEY, value='{"campaigns": [{"name": "Phishing 2026"}, {"name": "New campaign"}]}'),
    ])
    await db.commit()
    dates = (await client.get("/api/awareness")).json()["assignments_synced_at"]
    assert set(dates) == {"phishing 2026"}


async def test_detail_without_rows_has_no_export_date(client, db):
    db.add(AppSettings(key=DETAIL_KEY, value='{"campaigns": []}'))
    await db.commit()
    assert (await client.get("/api/awareness")).json()["assignments_synced_at"] == {}


async def test_export_is_named_and_dated_after_its_data(client, db):
    await _seed(db)
    r = await client.get("/api/awareness/export.csv",
                         params={"campaign": "phishing 2026", "lang": "fr", "utc_offset": 60})
    assert r.status_code == 200
    # 23:30 UTC on 30 October is already 31 October at UTC+1.
    assert r.headers["content-disposition"].endswith('-2026-10-31.csv"')
    lines = r.text.lstrip("﻿").splitlines()
    assert lines[0].endswith(";Données au")
    assert lines[1].endswith(";2026-10-31 00:30 UTC+01:00")


async def test_export_without_offset_is_in_utc(client, db):
    await _seed(db)
    r = await client.get("/api/awareness/export.csv", params={"campaign": "Phishing 2026"})
    assert r.status_code == 200
    assert r.headers["content-disposition"].endswith('-2026-10-30.csv"')
    assert r.text.splitlines()[1].endswith(";2026-10-30 23:30 UTC")


async def test_an_out_of_range_offset_is_refused(client, db):
    await _seed(db)
    r = await client.get("/api/awareness/export.csv",
                         params={"campaign": "Phishing 2026", "utc_offset": 100000})
    assert r.status_code == 422
