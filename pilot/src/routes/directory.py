"""Personnel directory — central user registry shared across all modules."""

from __future__ import annotations

import csv
import io
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import ModuleRegistry, Personnel, User
from src.upload_common import read_csv_upload

router = APIRouter(tags=["directory"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


_PERSONNEL_PUSH_BG_TASKS: set = set()

_BLOCKED_URL_HOSTS = {
    "169.254.169.254",                  # AWS / GCP metadata
    "metadata.google.internal",
    "metadata.internal",
}


def _is_safe_module_url(url: str) -> bool:
    """Guard against SSRF via a rogue ModuleRegistry.internal_url.
    Allows http(s) to anywhere EXCEPT loopback and known cloud-metadata
    endpoints. Intentionally permissive for the typical docker bridge
    (172.x / 192.168.x) where modules live."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in _BLOCKED_URL_HOSTS or host.startswith("127.") or host == "localhost":
        return False
    return True


async def _push_personnel_to_modules(db: AsyncSession, payload: dict, exclude_module: str | None = None) -> None:
    """Fire-and-forget broadcast of a personnel change to every module.

    Modules that care implement `POST /api/internal/personnel-sync`
    (service-token protected). Errors are swallowed — the source of
    truth is Pilot and each module stays eventually consistent via the
    on-demand `POST /si-users/sync-from-pilot` fallback.

    `exclude_module` skips one module by registry id — used for Access-sourced
    entries so Pilot never pushes them back to Access (one-directional, no loop).
    """
    import asyncio
    import httpx
    import logging
    logger = logging.getLogger("pilot-directory")
    if not SERVICE_TOKEN:
        return
    result = await db.execute(
        select(ModuleRegistry).where(ModuleRegistry.status == "active")
    )
    modules = [m for m in result.scalars().all() if m.id != exclude_module]

    async def _push_one(url: str):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    url.rstrip("/") + "/api/internal/personnel-sync",
                    headers={"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"},
                    json=payload,
                )
        except Exception as e:
            logger.debug("personnel-sync push to %s failed: %s", url, e)

    for mod in modules:
        url = mod.internal_url
        if not url:
            continue
        if not _is_safe_module_url(url):
            logger.warning("personnel-sync: skipping unsafe module url %s", url)
            continue
        # Use create_task + strong reference set so the coroutine isn't
        # garbage-collected mid-flight (PEP 3156 / deprecation of bare
        # ensure_future without holding the Task).
        task = asyncio.create_task(_push_one(url))
        _PERSONNEL_PUSH_BG_TASKS.add(task)
        task.add_done_callback(_PERSONNEL_PUSH_BG_TASKS.discard)


async def _sync_to_users(db: AsyncSession, email: str, name: str):
    """Create a User record with role=pending and no modules if not exists."""
    email = (email or "").strip().lower()
    if not email:
        return
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        return
    db.add(User(
        email=email, name=name, provider="directory", provider_id="directory",
        role="pending", modules=[], ai_enabled="false",
    ))


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    import secrets as _secrets
    if not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


def _to_dict(p: Personnel) -> dict:
    return {
        "id": str(p.id),
        "nom": p.nom or "",
        "prenom": p.prenom or "",
        "email": p.email or "",
        "fonction": p.fonction or "",
        "departement": p.departement or "",
        "statut": p.statut or "actif",
        "telephone": p.telephone or "",
        "site": p.site or "",
        "manager_email": p.manager_email or "",
        "sync_source": getattr(p, "sync_source", "") or "",
    }


# ── Admin CRUD routes (requires auth) ──────────────────────────

@router.get("/api/directory")
async def list_personnel(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Personnel).order_by(Personnel.nom, Personnel.prenom))
    return [_to_dict(p) for p in result.scalars().all()]


@router.post("/api/directory", status_code=201)
async def create_personnel(body: dict, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    email = (body.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    manager_email = (body.get("manager_email") or "").strip().lower()
    existing = await db.execute(select(Personnel).where(Personnel.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists in directory")
    p = Personnel(
        nom=body.get("nom", ""), prenom=body.get("prenom", ""),
        email=email, fonction=body.get("fonction", ""),
        departement=body.get("departement", ""), statut=body.get("statut", "actif"),
        telephone=body.get("telephone", ""), site=body.get("site", ""),
        manager_email=manager_email,
    )
    db.add(p)
    name = ((body.get("prenom") or "") + " " + (body.get("nom") or "")).strip()
    await _sync_to_users(db, email, name)
    await db.commit()
    await db.refresh(p)
    # Broadcast to modules (fire-and-forget)
    await _push_personnel_to_modules(db, {"action": "upsert", "personnel": _to_dict(p)})
    return _to_dict(p)


@router.patch("/api/directory/{person_id}")
async def update_personnel(person_id: uuid.UUID, body: dict, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    p = await db.get(Personnel, person_id)
    if not p:
        raise HTTPException(status_code=404, detail="Person not found")
    if (p.sync_source or "") == "access":
        raise HTTPException(status_code=403, detail="Cette personne est gérée par Access (connecteur RH) — édition désactivée dans Pilot.")
    old_email = p.email
    for f in ("nom", "prenom", "email", "fonction", "departement", "statut", "telephone", "site", "manager_email"):
        if f in body:
            val = str(body[f]) if body[f] is not None else ""
            # Email-like fields are normalized to lowercase so casing
            # variants don't collide as duplicate users/personnel.
            if f in ("email", "manager_email"):
                val = val.strip().lower()
            setattr(p, f, val)
    p.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(p)
    # Broadcast to modules (fire-and-forget). Include old_email so
    # downstream modules can match rows even if email changed.
    payload = {"action": "upsert", "personnel": _to_dict(p)}
    if old_email and old_email != p.email:
        payload["old_email"] = old_email
    await _push_personnel_to_modules(db, payload)
    return _to_dict(p)


@router.delete("/api/directory/{person_id}", status_code=204)
async def delete_personnel(person_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    p = await db.get(Personnel, person_id)
    if not p:
        raise HTTPException(status_code=404, detail="Person not found")
    if (p.sync_source or "") == "access":
        raise HTTPException(status_code=403, detail="Cette personne est gérée par Access (connecteur RH) — suppression désactivée dans Pilot.")
    snapshot = _to_dict(p)
    await db.delete(p)
    await db.commit()
    await _push_personnel_to_modules(db, {"action": "delete", "personnel": snapshot})


@router.post("/api/directory/import-csv")
async def import_csv(file: UploadFile, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import personnel from CSV. Columns: nom, prenom, email, fonction, departement, statut, telephone, site, manager_email."""
    require_admin(user)
    content = await read_csv_upload(file, 5 * 1024 * 1024)
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = content.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise HTTPException(status_code=400, detail="Cannot decode file")

    first_line = text.split("\n")[0]
    delimiter = ";" if first_line.count(";") > first_line.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="No header row")

    _COL = {
        "nom": "nom", "name": "nom", "last_name": "nom", "lastname": "nom",
        "prenom": "prenom", "first_name": "prenom", "firstname": "prenom",
        "email": "email", "mail": "email",
        "fonction": "fonction", "role": "fonction", "title": "fonction", "job_title": "fonction",
        "departement": "departement", "department": "departement", "service": "departement",
        "statut": "statut", "status": "statut",
        "telephone": "telephone", "phone": "telephone", "tel": "telephone",
        "site": "site", "location": "site", "localisation": "site",
        "manager": "manager_email", "manager_email": "manager_email",
    }

    existing_result = await db.execute(select(Personnel.email))
    existing_emails = {row[0].lower() for row in existing_result.all()}
    imported = 0

    for row in reader:
        mapped = {}
        for col, val in row.items():
            if col is None:
                continue
            key = col.strip().lower().replace(" ", "_").replace("-", "_")
            field = _COL.get(key)
            if field and val is not None:
                mapped[field] = val.strip()

        email = (mapped.get("email") or "").strip().lower()
        if not email or email in existing_emails:
            continue
        manager_email = (mapped.get("manager_email") or "").strip().lower()

        db.add(Personnel(
            nom=mapped.get("nom", ""), prenom=mapped.get("prenom", ""),
            email=email, fonction=mapped.get("fonction", ""),
            departement=mapped.get("departement", ""),
            statut=mapped.get("statut", "actif"),
            telephone=mapped.get("telephone", ""),
            site=mapped.get("site", ""),
            manager_email=manager_email,
        ))
        name = ((mapped.get("prenom") or "") + " " + (mapped.get("nom") or "")).strip()
        await _sync_to_users(db, email, name)
        existing_emails.add(email)
        imported += 1

    await db.commit()
    return {"imported": imported}


# ── Internal endpoint for modules (service token) ──────────────

@router.get("/api/internal/directory")
async def internal_directory(request: Request, db: AsyncSession = Depends(get_db)):
    """Return personnel directory for other modules. Protected by service token."""
    _check_service_token(request)
    result = await db.execute(select(Personnel).where(Personnel.statut != "inactif").order_by(Personnel.nom, Personnel.prenom))
    return [_to_dict(p) for p in result.scalars().all()]


@router.post("/api/internal/directory", status_code=201)
async def internal_create_personnel(request: Request, body: dict, db: AsyncSession = Depends(get_db)):
    """Create a personnel entry on behalf of a module (service-token auth).

    Modules that proxy `POST /api/directory` forward here instead of
    requiring admin credentials — the module already enforces its own
    auth on the caller. Validates email uniqueness (409 on conflict).
    """
    _check_service_token(request)
    email = (body.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    manager_email = (body.get("manager_email") or "").strip().lower()
    existing = await db.execute(select(Personnel).where(Personnel.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists in directory")
    p = Personnel(
        nom=body.get("nom", ""), prenom=body.get("prenom", ""),
        email=email, fonction=body.get("fonction", ""),
        departement=body.get("departement", ""), statut=body.get("statut", "actif"),
        telephone=body.get("telephone", ""), site=body.get("site", ""),
        manager_email=manager_email,
    )
    db.add(p)
    name = ((body.get("prenom") or "") + " " + (body.get("nom") or "")).strip()
    await _sync_to_users(db, email, name)
    await db.commit()
    await db.refresh(p)
    await _push_personnel_to_modules(db, {"action": "upsert", "personnel": _to_dict(p)})
    return _to_dict(p)


@router.post("/api/internal/directory/from-access")
async def internal_directory_from_access(request: Request, body: dict, db: AsyncSession = Depends(get_db)):
    """Receive the identity referential PUSHED by Access (service-token auth).

    Access owns these identities (an HR connector feeds it); Pilot mirrors them
    as `sync_source="access"` (read-only in Pilot) and re-broadcasts to the
    OTHER modules — **never back to Access** (one-directional, no loop). Access
    is expected to send statut already mapped to Pilot's form (actif/inactif).
    """
    _check_service_token(request)
    users = body.get("users") or []
    existing = await db.execute(select(Personnel))
    by_email = {p.email.lower(): p for p in existing.scalars().all() if p.email}
    created = updated = skipped = 0
    touched: list[Personnel] = []
    for e in users:
        email = (e.get("email") or "").strip().lower()
        if not email:
            skipped += 1
            continue
        fields = {
            "nom": e.get("nom") or "", "prenom": e.get("prenom") or "",
            "fonction": e.get("fonction") or "", "departement": e.get("departement") or "",
            "statut": e.get("statut") or "actif",
            "manager_email": (e.get("manager_email") or "").strip().lower(),
        }
        p = by_email.get(email)
        if p:
            for k, v in fields.items():
                setattr(p, k, v)
            p.sync_source = "access"
            p.updated_at = datetime.now(timezone.utc)
            updated += 1
        else:
            p = Personnel(email=email, sync_source="access", **fields)
            db.add(p)
            by_email[email] = p
            name = (fields["prenom"] + " " + fields["nom"]).strip()
            await _sync_to_users(db, email, name)
            created += 1
        touched.append(p)
    await db.commit()
    # Re-broadcast to the OTHER modules (risk, compliance, …) but NOT Access.
    for p in touched:
        await db.refresh(p)
        await _push_personnel_to_modules(db, {"action": "upsert", "personnel": _to_dict(p)}, exclude_module="access")
    return {"created": created, "updated": updated, "skipped": skipped, "total": len(users)}
