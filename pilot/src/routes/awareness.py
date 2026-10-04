"""Awareness (Proofpoint PSAT) reporting endpoint — FEAT-18 Lot 2.

Serves the detailed panel payload produced by the PSAT connector's run()
(stored as JSON in AppSettings). Tenant-wide reporting: overall completion,
per-campaign breakdown, daily trend and the top overdue users — and the CSV
export of one campaign's per-user progress (FEAT-53).
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.connectors.proofpoint_psat import DETAIL_KEY, _campaign_slug
from src.database import get_db
from src.models import AppSettings, PsatAssignment, User

router = APIRouter(prefix="/api/awareness", tags=["awareness"])

_EMPTY = {
    "configured": False,
    "overall_completion_pct": 0,
    "users_total": 0,
    "users_compliant": 0,
    "campaigns": [],
    "overdue": [],
    "overdue_total": 0,
    "trend": [],
}


@router.get("")
async def get_awareness(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(AppSettings).where(AppSettings.key == DETAIL_KEY))
    s = r.scalar_one_or_none()
    if not s or not s.value:
        return _EMPTY
    try:
        data = json.loads(s.value)
    except (ValueError, TypeError):
        return _EMPTY
    data["configured"] = True
    return data


_CSV_HEADERS = {
    "fr": ["Nom", "Prénom", "E-mail", "Date d'envoi", "Date de réalisation", "Statut", "Statut PSAT"],
    "en": ["Last name", "First name", "E-mail", "Sent on", "Completed on", "Status", "PSAT status"],
}
_CSV_STATUS = {
    "fr": {"completed": "Terminé", "completed_late": "Terminé en retard", "overdue": "En retard",
           "pending": "À réaliser", "excluded": "Exclu"},
    "en": {"completed": "Completed", "completed_late": "Completed late", "overdue": "Overdue",
           "pending": "Pending", "excluded": "Excluded"},
}


def _cell(value: str) -> str:
    """Neutralise a spreadsheet formula: names and statuses come from an
    external platform."""
    v = str(value or "")
    return "'" + v if v.lstrip(" ")[:1] in ("=", "+", "-", "@", "\t", "\r", "\n") else v


def _assignments_csv(rows: list, lang: str) -> str:
    """CSV of a campaign's per-user progress, for Excel: UTF-8 BOM, ``;``."""
    lang = lang if lang in _CSV_HEADERS else "en"
    out = io.StringIO()
    out.write("\ufeff")
    w = csv.writer(out, delimiter=";", lineterminator="\r\n")
    w.writerow(_CSV_HEADERS[lang])
    for r in rows:
        w.writerow([_cell(x) for x in (
            r.last_name, r.first_name, r.email, r.sent_date, r.completion_date,
            _CSV_STATUS[lang].get(r.status, r.status), r.psat_status,
        )])
    return out.getvalue()


@router.get("/export.csv")
async def export_campaign_csv(
    campaign: str = Query(..., min_length=1, max_length=2000),
    lang: str = Query("en", pattern="^(fr|en)$"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        # The KPI carries the campaign as configured, the snapshot as PSAT
        # spells it, cut to the column size: compare like the connector does.
        select(PsatAssignment).where(
            func.lower(func.trim(PsatAssignment.campaign)) == campaign[:500].strip().lower())
        .order_by(PsatAssignment.last_name, PsatAssignment.first_name, PsatAssignment.email)
    )).scalars().all()
    if not rows:
        raise HTTPException(404, "No per-user data for this campaign yet — run the PSAT sync")
    day = datetime.now(timezone.utc).date().isoformat()
    name = re.sub(r"[^a-z0-9-]", "", _campaign_slug(campaign)) or "campaign"
    return Response(
        content=_assignments_csv(rows, lang),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="psat-{name}-{day}.csv"'},
    )
