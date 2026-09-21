"""FEAT-45 — non-conformities and derogations, Access flavour.

The mechanics (states, validation, router, expiry) are shared; this file
says what a derogation covers here — an entitlement anomaly, i.e. a review
entry found non-compliant — and what "derogated" does to it: the entry
leaves the non-compliant count for its own category and comes back to
`non_conforme` when the derogation ends.

Subject ids are `<project_id>:<review_id>:<entry_id>`; measure ids are
`<project_id>:<measure_id>` (both are keyed by project in this module).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Application, Derogation, Measure, Nonconformity, Project, Review, ReviewEntry
from src.nonconformity_common import make_internal_router, make_router
from src.auth import require_min_role

# Same ladder as the module's own write routes: an editor writes, a viewer does not.
_ROLES = ["viewer", "reader", "triager", "editor", "contributor", "manager", "admin", "control"]

SUBJECT_TYPE = "review_entry"


def split_entry_key(key: str) -> Optional[tuple]:
    parts = (key or "").split(":", 2)
    if len(parts) != 3:
        return None
    try:
        return uuid.UUID(parts[0]), parts[1], parts[2]
    except ValueError:
        return None


def split_measure_key(key: str) -> Optional[tuple]:
    parts = (key or "").split(":", 1)
    if len(parts) != 2:
        return None
    try:
        return uuid.UUID(parts[0]), parts[1]
    except ValueError:
        return None


class EntryHook:
    async def _entry(self, db: AsyncSession, subject_id: str) -> Optional[Any]:
        key = split_entry_key(subject_id)
        return await db.get(ReviewEntry, key) if key else None

    async def exists(self, db: AsyncSession, subject_type: str, subject_id: str, project_id: str = "") -> Optional[str]:
        if subject_type != SUBJECT_TYPE:
            return None
        key = split_entry_key(subject_id)
        # The entry names its project: a record never reaches into another one.
        if key is None or (project_id and str(key[0]) != str(project_id)):
            return None
        e = await self._entry(db, subject_id)
        if e is None:
            return None
        if e.decision != "non_conforme":
            raise HTTPException(status_code=409, detail=f"review entry is '{e.decision}': only a non-compliant entry can be derogated")
        review = await db.get(Review, (e.project_id, e.review_id))
        app = await db.get(Application, (e.project_id, review.application_id)) if review else None
        return f"{e.email_or_login}{' — ' + app.nom if app and app.nom else ''}"[:500]

    async def apply(self, db: AsyncSession, derogation: Any) -> None:
        e = await self._entry(db, derogation.subject_id)
        if e is None:
            return
        e.decision = "derogated"
        e.decided_by = derogation.decided_by or "system"
        e.decided_at = datetime.now(timezone.utc).date().isoformat()
        e.updated_at = datetime.now(timezone.utc)

    async def release(self, db: AsyncSession, derogation: Any, reason: str) -> None:
        e = await self._entry(db, derogation.subject_id)
        if e is None or e.decision != "derogated":
            return
        e.decision = "non_conforme"
        e.notes = ((e.notes or "") + f"\n[Derogation {derogation.reference} {reason}]").strip()[:2000]
        e.updated_at = datetime.now(timezone.utc)

    async def missing_measures(self, db: AsyncSession, ids: list, project_id: str = "") -> list:
        missing = []
        for i in ids:
            key = split_measure_key(i)
            # A measure is its project's: a record never links another one's.
            if key is None or (project_id and str(key[0]) != str(project_id)) or await db.get(Measure, key) is None:
                missing.append(i)
        return missing

    async def measure_states(self, db: AsyncSession, ids: list, project_id: str = "") -> dict:
        out = {}
        for i in ids:
            key = split_measure_key(i)
            if key is None or (project_id and str(key[0]) != str(project_id)):
                continue
            m = await db.get(Measure, key)
            if m is not None:
                out[i] = m.statut
        return out


ENTRY_HOOK = EntryHook()
class ProjectScope:
    """The register is project-scoped here: a record belongs to the project it
    was declared in, and a user only ever sees or touches the projects the
    module already grants them. A record without a project came from the
    console: it is module-level and stays visible to everyone."""

    async def readable(self, db: AsyncSession, user: Any) -> list:
        from src.routes.projects import _user_permissions
        rows = (await db.execute(select(Project))).scalars().all()
        return [str(p.id) for p in rows if "read" in _user_permissions(p, user)]

    async def writable(self, db: AsyncSession, user: Any, project_id: str) -> None:
        from src.routes.auth_helpers import get_project_or_404
        try:
            pid = uuid.UUID(str(project_id))
        except ValueError:
            raise HTTPException(status_code=404, detail="Project not found")
        await get_project_or_404(pid, user, db, require_perm="edit")


PROJECT_SCOPE = ProjectScope()


router = make_router(Nonconformity, Derogation, ENTRY_HOOK, subject_types=(SUBJECT_TYPE,),
                     require_writer=lambda u: require_min_role(u, "editor", _ROLES),
                     project_scope=PROJECT_SCOPE)

# Pilot's view of the register (service token): the same operations, relayed
# with the Pilot user as actor. The token check is the module's own.
from src.routes.internal import _check_service_token  # noqa: E402

internal_router = make_internal_router(Nonconformity, Derogation, ENTRY_HOOK, subject_types=(SUBJECT_TYPE,),
                                       check_service_token=_check_service_token)
