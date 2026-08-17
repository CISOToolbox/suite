"""Awareness (Proofpoint PSAT) reporting endpoint — FEAT-18 Lot 2.

Serves the detailed panel payload produced by the PSAT connector's run()
(stored as JSON in AppSettings). Tenant-wide reporting: overall completion,
per-campaign breakdown, daily trend and the top overdue users.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.connectors.proofpoint_psat import DETAIL_KEY
from src.database import get_db
from src.models import AppSettings, User

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
