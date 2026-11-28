"""Personnel directory — central user registry shared across all modules."""

from __future__ import annotations

import csv
import io
import os
import uuid
from datetime import date, datetime, timezone

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


async def _retire_directory_entry(db: AsyncSession, email: str) -> dict | None:
    """Detach the directory entry of a deleted account from its address.

    The entry is kept for history (name, function, manager), marked
    `inactif`, and its email is rewritten to a unique address under the
    reserved `.invalid` TLD, which keeps the original readable. Entries match
    by email, so otherwise the next account given that address would take
    the former holder's entry over — function, manager and status included.

    Entries fed by Access (`sync_source="access"`) are left alone: Access
    owns them and would push them back on its next sync.

    Returns the change to broadcast once committed (a rename, with
    `old_email`, to `inactif`), or None: a module that mirrors the directory
    keeps the person, departed, with what it holds of its own."""
    email = (email or "").strip().lower()
    if not email:
        return None
    p = (await db.execute(select(Personnel).where(Personnel.email == email))).scalar_one_or_none()
    if p is None or (p.sync_source or "") == "access":
        return None
    suffix = f".deleted-{p.id.hex[:12]}.invalid"
    p.email = email[:255 - len(suffix)] + suffix
    if (p.statut or "").lower() != "inactif":
        p.date_depart = date.today().isoformat()       # left today, unless it already said when
    p.statut = "inactif"
    p.updated_at = datetime.now(timezone.utc)
    return {"action": "upsert", "personnel": _to_dict(p), "old_email": email}


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    import secrets as _secrets
    if not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


STATUTS = ("recrutement", "actif", "inactif")
CONTRATS = ("interne", "externe", "alternant", "stagiaire")


def _status(statut: object, type_contrat: object, current: tuple[str, str] = ("actif", "")) -> tuple[str, str]:
    """The activity and the contract of a person, checked: two notions (an
    external contractor can be active). The former `externe` status is read
    as an active person with an external contract. A contract nobody gave
    stays empty: the modules then keep the one they know."""
    s = str(statut or "").strip().lower() or current[0]
    c = str(type_contrat or "").strip().lower() or current[1]
    if s == "externe":
        s, c = "actif", (str(type_contrat or "").strip().lower() or "externe")
    if s not in STATUTS:
        raise HTTPException(status_code=422, detail=f"statut must be one of {', '.join(STATUTS)}, not {s[:20]}")
    if c and c not in CONTRATS:
        raise HTTPException(status_code=422, detail=f"type_contrat must be one of {', '.join(CONTRATS)}, not {c[:20]}")
    return s, c


# The English words a CSV file may use for a status or a contract.
_CSV_WORDS = {"active": "actif", "inactive": "inactif", "left": "inactif", "recruiting": "recrutement",
              "internal": "interne", "employee": "interne", "external": "externe", "contractor": "externe",
              "apprentice": "alternant", "intern": "stagiaire"}


def _departure(statut: str, value: object) -> str | None:
    """The departure date to store: YYYY-MM-DD, and only for a person who
    left (`inactif`); refused when it is not a date."""
    text = str(value or "").strip()
    if not text or (statut or "actif").strip().lower() != "inactif":
        return None
    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"date_depart must be a date (YYYY-MM-DD), not {text[:20]}") from None
    if parsed.isoformat() != text:
        raise HTTPException(status_code=422, detail=f"date_depart must be a date (YYYY-MM-DD), not {text[:20]}")
    return text


def _csv_departure(statut: str, value: object) -> str | None:
    """The import keeps going past a line it cannot read: a date that is not
    one is left out, not a reason to refuse the file."""
    try:
        return _departure(statut, value)
    except HTTPException:
        return None


def _to_dict(p: Personnel) -> dict:
    return {
        "id": str(p.id),
        "nom": p.nom or "",
        "prenom": p.prenom or "",
        "email": p.email or "",
        "fonction": p.fonction or "",
        "departement": p.departement or "",
        "statut": p.statut or "actif",
        "type_contrat": p.type_contrat or "",
        "date_depart": p.date_depart or None,
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
    statut, type_contrat = _status(body.get("statut"), body.get("type_contrat"))
    p = Personnel(
        nom=body.get("nom", ""), prenom=body.get("prenom", ""),
        email=email, fonction=body.get("fonction", ""),
        departement=body.get("departement", ""), statut=statut, type_contrat=type_contrat,
        date_depart=_departure(statut, body.get("date_depart")),
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
        raise HTTPException(status_code=403, detail="This person is managed by Access (HR connector): editing is disabled in Pilot.")
    old_email = p.email
    if "statut" in body or "type_contrat" in body:
        p.statut, p.type_contrat = _status(body.get("statut"), body.get("type_contrat"),
                                           (p.statut or "actif", p.type_contrat or ""))
        if "type_contrat" in body and not str(body.get("type_contrat") or "").strip() \
                and str(body.get("statut") or "").strip().lower() != "externe":
            p.type_contrat = ""                         # "Not given" chosen: the modules keep their own again
    for f in ("nom", "prenom", "email", "fonction", "departement", "telephone", "site", "manager_email"):
        if f in body:
            val = str(body[f]) if body[f] is not None else ""
            # Email-like fields are normalized to lowercase so casing
            # variants don't collide as duplicate users/personnel.
            if f in ("email", "manager_email"):
                val = val.strip().lower()
            setattr(p, f, val)
    # Sent or not, a person back from inactif keeps no departure date.
    p.date_depart = _departure(p.statut, body.get("date_depart", p.date_depart))
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
        raise HTTPException(status_code=403, detail="This person is managed by Access (HR connector): deletion is disabled in Pilot.")
    snapshot = _to_dict(p)
    await db.delete(p)
    await db.commit()
    await _push_personnel_to_modules(db, {"action": "delete", "personnel": snapshot})


@router.post("/api/directory/import-csv")
async def import_csv(file: UploadFile, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import personnel from CSV. Columns: nom, prenom, email, fonction, departement, statut, type_contrat, date_depart, telephone, site, manager_email."""
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
        "type_contrat": "type_contrat", "contrat": "type_contrat", "contract": "type_contrat", "contract_type": "type_contrat",
        "date_depart": "date_depart", "departure_date": "date_depart", "left_on": "date_depart",
        "telephone": "telephone", "phone": "telephone", "tel": "telephone",
        "site": "site", "location": "site", "localisation": "site",
        "manager": "manager_email", "manager_email": "manager_email",
    }

    existing_result = await db.execute(select(Personnel.email))
    existing_emails = {row[0].lower() for row in existing_result.all()}
    imported = unreadable = 0

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
        try:
            statut, type_contrat = _status(_CSV_WORDS.get((mapped.get("statut") or "").strip().lower(), mapped.get("statut")),
                                           _CSV_WORDS.get((mapped.get("type_contrat") or "").strip().lower(), mapped.get("type_contrat")))
        except HTTPException:
            unreadable += 1                             # a status it cannot read: the line is left out, and counted
            continue

        db.add(Personnel(
            nom=mapped.get("nom", ""), prenom=mapped.get("prenom", ""),
            email=email, fonction=mapped.get("fonction", ""),
            departement=mapped.get("departement", ""),
            statut=statut, type_contrat=type_contrat,
            date_depart=_csv_departure(statut, mapped.get("date_depart")),
            telephone=mapped.get("telephone", ""),
            site=mapped.get("site", ""),
            manager_email=manager_email,
        ))
        name = ((mapped.get("prenom") or "") + " " + (mapped.get("nom") or "")).strip()
        await _sync_to_users(db, email, name)
        existing_emails.add(email)
        imported += 1

    await db.commit()
    return {"imported": imported, "unreadable": unreadable}


# ── Internal endpoint for modules (service token) ──────────────

@router.get("/api/internal/directory")
async def internal_directory(request: Request, include_inactive: bool = False, db: AsyncSession = Depends(get_db)):
    """Return personnel directory for other modules. Protected by service token.
    The people who left (`inactif`) only with `include_inactive`: a module that
    mirrors the directory needs them to see a departure."""
    _check_service_token(request)
    query = select(Personnel) if include_inactive else select(Personnel).where(Personnel.statut != "inactif")
    result = await db.execute(query.order_by(Personnel.nom, Personnel.prenom))
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
    statut, type_contrat = _status(body.get("statut"), body.get("type_contrat"))
    p = Personnel(
        nom=body.get("nom", ""), prenom=body.get("prenom", ""),
        email=email, fonction=body.get("fonction", ""),
        departement=body.get("departement", ""), statut=statut, type_contrat=type_contrat,
        date_depart=_departure(statut, body.get("date_depart")),
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
    sends the status (recrutement, actif, inactif) and the contract type
    (interne, externe, alternant, stagiaire) in Pilot's own words.
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
            "manager_email": (e.get("manager_email") or "").strip().lower(),
        }
        try:
            fields["statut"], fields["type_contrat"] = _status(e.get("statut"), e.get("type_contrat"))
        except HTTPException:
            skipped += 1
            continue
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
