from __future__ import annotations

import csv
import io
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import Application, User
from src.routes.auth_helpers import get_project_or_404
from src.upload_common import read_csv_upload

router = APIRouter(prefix="/api/projects/{project_id}", tags=["applications"])


@router.get("/applications")
async def list_applications(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    result = await db.execute(select(Application).where(Application.project_id == project_id).order_by(Application.sort_order))
    return [_to_dict(a) for a in result.scalars().all()]


@router.post("/applications", status_code=201)
async def create_application(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    max_order = await db.scalar(select(func.coalesce(func.max(Application.sort_order), 0)).where(Application.project_id == project_id))
    app = Application(
        project_id=project_id, id=body.get("id", ""), sort_order=(max_order or 0) + 1,
        nom=body.get("nom", ""), url=body.get("url", ""),
        reviewers=body.get("reviewers") or [],
        frequence_revue=body.get("frequence_revue", "semestrielle"),
        owner_email=_norm_owner_email(body.get("owner_email")),
        type=_norm_type(body.get("type")),
        roles=_norm_roles(body.get("roles")),
    )
    db.add(app)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(app)
    return _to_dict(app)


@router.patch("/applications/{app_id}")
async def patch_application(project_id: uuid.UUID, app_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    app = await db.get(Application, (project_id, app_id))
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    for f in ("nom", "url", "frequence_revue"):
        if f in body:
            setattr(app, f, str(body[f]) if body[f] is not None else "")
    if "owner_email" in body:
        app.owner_email = _norm_owner_email(body["owner_email"])
    if "reviewers" in body:
        app.reviewers = body["reviewers"] if isinstance(body["reviewers"], list) else []
    if "type" in body:
        app.type = _norm_type(body["type"])
    if "roles" in body:
        app.roles = _norm_roles(body["roles"])
    if "sort_order" in body:
        app.sort_order = int(body["sort_order"])
    app.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(app)
    return _to_dict(app)


@router.delete("/applications/{app_id}", status_code=204)
async def delete_application(project_id: uuid.UUID, app_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    app = await db.get(Application, (project_id, app_id))
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    await db.delete(app)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


@router.post("/applications/import-csv")
async def import_csv(project_id: uuid.UUID, file: UploadFile, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import applications from CSV. Columns: nom, url, frequence_revue."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")

    content = await read_csv_upload(file, 5 * 1024 * 1024)

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = content.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise HTTPException(status_code=400, detail="Cannot decode file")

    first_line = text.split("\n")[0]
    delimiter = ";" if first_line.count(";") > first_line.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV has no header row")

    _COL_MAP = {
        "nom": "nom", "name": "nom", "application": "nom", "app": "nom",
        "url": "url", "lien": "url", "link": "url",
        "frequence": "frequence_revue", "frequence_revue": "frequence_revue",
        "frequency": "frequence_revue", "review_frequency": "frequence_revue",
    }
    _FREQ_MAP = {
        "trimestrielle": "trimestrielle", "quarterly": "trimestrielle", "3m": "trimestrielle",
        "semestrielle": "semestrielle", "semi-annual": "semestrielle", "6m": "semestrielle",
        "annuelle": "annuelle", "annual": "annuelle", "yearly": "annuelle", "12m": "annuelle",
    }

    existing = await db.execute(select(Application).where(Application.project_id == project_id))
    all_apps = existing.scalars().all()
    max_num = 0
    for a in all_apps:
        try:
            n = int(re.sub(r'\D', '', a.id) or '0')
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    existing_names = {a.nom.lower() for a in all_apps if a.nom}
    current_order = len(all_apps)
    imported = 0

    for row in reader:
        mapped = {}
        for csv_col, csv_val in row.items():
            if csv_col is None:
                continue
            key = csv_col.strip().lower().replace(" ", "_").replace("-", "_")
            field = _COL_MAP.get(key)
            if field and csv_val is not None:
                mapped[field] = csv_val.strip()

        nom = mapped.get("nom", "")
        if not nom or nom.lower() in existing_names:
            continue

        max_num += 1
        current_order += 1
        freq = _FREQ_MAP.get((mapped.get("frequence_revue") or "").lower(), "semestrielle")

        db.add(Application(
            project_id=project_id, id=f"APP-{max_num:03d}", sort_order=current_order,
            nom=nom, url=mapped.get("url", ""), frequence_revue=freq, reviewers=[],
        ))
        existing_names.add(nom.lower())
        imported += 1

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"imported": imported}


@router.post("/applications/sync-asset")
async def sync_from_asset(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Sync applications from Asset module — imports assets of type 'application'."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")

    asset_url = os.getenv("ASSET_URL", "")
    service_token = os.getenv("SERVICE_TOKEN", "")
    if not asset_url:
        raise HTTPException(status_code=503, detail="Asset module URL not configured (ASSET_URL)")
    if not service_token:
        raise HTTPException(status_code=503, detail="Service token not configured")

    # Fetch all asset projects, then get assets of type 'application'
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                asset_url.rstrip("/") + "/api/internal/export",
                headers={"X-Service-Token": service_token},
            )
            resp.raise_for_status()
            asset_projects = resp.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Cannot reach Asset module: {e}")

    # Collect all 'application' type assets across all projects
    app_assets = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for ap in asset_projects:
            try:
                resp = await client.get(
                    asset_url.rstrip("/") + f"/api/internal/export/{ap['id']}",
                    headers={"X-Service-Token": service_token},
                )
                if resp.is_success:
                    data = resp.json().get("data", {})
                    for asset in data.get("assets", []):
                        if asset.get("type") == "application":
                            app_assets.append(asset)
            except Exception:
                continue

    if not app_assets:
        return {"imported": 0, "message": "No application-type assets found in Asset module"}

    # Get existing applications to avoid duplicates (match by nom)
    existing = await db.execute(select(Application).where(Application.project_id == project_id))
    all_apps = existing.scalars().all()
    existing_names = {a.nom.lower() for a in all_apps if a.nom}
    max_num = 0
    for a in all_apps:
        try:
            n = int(re.sub(r'\D', '', a.id) or '0')
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    current_order = len(all_apps)
    imported = 0

    for asset in app_assets:
        nom = asset.get("nom", "")
        if not nom or nom.lower() in existing_names:
            continue

        max_num += 1
        current_order += 1

        # Build URL from asset data if available
        url = asset.get("url", "") or ""
        if not url and asset.get("fournisseur"):
            url = ""  # no guess

        db.add(Application(
            project_id=project_id, id=f"APP-{max_num:03d}", sort_order=current_order,
            nom=nom, url=url, frequence_revue="semestrielle", reviewers=[],
        ))
        existing_names.add(nom.lower())
        imported += 1

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"imported": imported, "total_assets_found": len(app_assets)}


_VALID_PERIM_TYPES = {"application", "infrastructure", "physique"}


def _norm_type(v) -> str:
    v = str(v or "application").strip().lower()
    return v if v in _VALID_PERIM_TYPES else "application"


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _norm_owner_email(v) -> str:
    """FEAT-42 — server-side validation: '' or a plausible email, else 422."""
    s = str(v or "").strip()
    if s and not _EMAIL_RE.match(s):
        raise HTTPException(status_code=422, detail="owner_email must be an email address or empty")
    return s


def _norm_roles(v) -> list:
    if not isinstance(v, list):
        return []
    return [str(r).strip() for r in v if str(r).strip()][:200]


def _to_dict(a: Application) -> dict:
    return {
        "id": a.id, "nom": a.nom, "url": a.url,
        "reviewers": a.reviewers or [],
        "frequence_revue": a.frequence_revue,
        "owner_email": a.owner_email or "",
        # BUG-27: anchor for the first review's due date (fresh perimeter =
        # due at created_at + frequency, not instantly overdue).
        "created_at": a.created_at.date().isoformat() if a.created_at else "",
        "type": a.type or "application",
        "roles": a.roles or [],
    }
