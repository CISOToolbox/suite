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
from src.crypto import decrypt_config
from src.database import get_db
from src.models import PluginConfig, SiUser, SyncJob, User
from src.plugins import PLUGIN_REGISTRY
from src.proof_rules import enforce_proof_evidence
from src.routes.auth_helpers import get_project_or_404
from src.upload_common import read_csv_upload

PILOT_URL = os.getenv("PILOT_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

router = APIRouter(prefix="/api/projects/{project_id}", tags=["si_users"])


def _validate_url_field(value: str, field_name: str, max_len: int = 500) -> str:
    """Backend guard for user-provided URL fields. Allows https?://, mailto:
    and empty/unset. Rejects javascript:, data:, file:, vbscript:, etc.
    Protects downstream renderers (CSV exports, future anchor tags,
    Pilot dashboards) from stored XSS / open redirects."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a string")
    v = value.strip()
    if len(v) > max_len:
        raise HTTPException(status_code=422,
                            detail=f"{field_name} too long (max {max_len})")
    low = v.lower()
    # Anything with a scheme must be http(s) or mailto. Relative URLs are OK.
    if "://" in low:
        if not (low.startswith("http://") or low.startswith("https://")):
            raise HTTPException(status_code=422,
                                detail=f"{field_name}: only http(s) URLs are allowed")
    elif low.startswith(("javascript:", "data:", "vbscript:", "file:", "about:")):
        raise HTTPException(status_code=422,
                            detail=f"{field_name}: disallowed URL scheme")
    return v


@router.get("/si-users")
async def list_si_users(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    result = await db.execute(select(SiUser).where(SiUser.project_id == project_id).order_by(SiUser.sort_order))
    return [_to_dict(u) for u in result.scalars().all()]


_VALID_STATUTS = {"actif", "ancien", "recrutement"}
_VALID_TYPES = {"salarie", "prestataire", "stagiaire", "alternant"}


def _validate_statut(v: str) -> str:
    v = (v or "actif").strip().lower()
    if v not in _VALID_STATUTS:
        raise HTTPException(status_code=422, detail=f"Invalid statut: {v}")
    return v


def _validate_type_compte(v: str) -> str:
    v = (v or "salarie").strip().lower()
    if v not in _VALID_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid type_compte: {v}")
    return v


def _validate_contract_end(type_compte: str, date_fin_contrat: str) -> str:
    """FEAT-15: date_fin_contrat is required for every type except 'salarie'."""
    v = (date_fin_contrat or "").strip()
    if type_compte != "salarie" and not v:
        raise HTTPException(
            status_code=422,
            detail="Date de fin de contrat requise pour les non-salariés",
        )
    return v


@router.post("/si-users", status_code=201)
async def create_si_user(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    max_order = await db.scalar(select(func.coalesce(func.max(SiUser.sort_order), 0)).where(SiUser.project_id == project_id))
    tc = _validate_type_compte(body.get("type_compte", "salarie"))
    su = SiUser(
        project_id=project_id, id=body.get("id", ""), sort_order=(max_order or 0) + 1,
        nom=body.get("nom", ""), prenom=body.get("prenom", ""),
        email=body.get("email", ""),
        statut=_validate_statut(body.get("statut", "actif")),
        type_compte=tc,
        fonction=body.get("fonction", ""),
        equipe=str(body.get("equipe", "")),
        date_fin_contrat=_validate_contract_end(tc, body.get("date_fin_contrat", "")),
        manager_email=str(body.get("manager_email", "")),
        politique_validee=bool(body.get("politique_validee")),
        politique_date=body.get("politique_date", ""),
        politique_justification=str(body.get("politique_justification", ""))[:2000],
        mfa_active=bool(body.get("mfa_active")),
        mfa_date=body.get("mfa_date", ""),
        mfa_justification=str(body.get("mfa_justification", ""))[:2000],
        sensibilisation=bool(body.get("sensibilisation")),
        sensibilisation_date=body.get("sensibilisation_date", ""),
        sensibilisation_justification=str(body.get("sensibilisation_justification", ""))[:2000],
        background_check=bool(body.get("background_check")),
        background_check_date=body.get("background_check_date", ""),
        background_check_justification=str(body.get("background_check_justification", ""))[:2000],
        background_check_url=_validate_url_field(
            body.get("background_check_url", ""), "background_check_url"),
        nda_signed=bool(body.get("nda_signed")),
        nda_date=body.get("nda_date", ""),
        nda_justification=str(body.get("nda_justification", ""))[:2000],
    )
    # A proof is only kept validated when it carries a date AND a comment.
    enforce_proof_evidence(su)
    db.add(su)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(su)
    return _to_dict(su)


@router.patch("/si-users/{si_user_id}")
async def patch_si_user(project_id: uuid.UUID, si_user_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    su = await db.get(SiUser, (project_id, si_user_id))
    if not su:
        raise HTTPException(status_code=404, detail="SI user not found")
    _FIELDS = [
        "nom", "prenom", "email", "fonction", "equipe", "manager_email",
        "politique_date", "mfa_date", "sensibilisation_date", "background_check_date", "nda_date",
        "background_check_url",
    ]
    # Justification text fields — capped at 2000 chars to prevent DoS.
    _JUSTIFICATIONS = [
        "politique_justification", "mfa_justification", "sensibilisation_justification",
        "background_check_justification", "nda_justification",
    ]
    _BOOLS = ["politique_validee", "mfa_active", "sensibilisation",
              "background_check", "nda_signed"]
    # When this SiUser is managed by Pilot, identity fields are owned by
    # the central directory — any attempt to change them from Access is
    # rejected (defence in depth against UI tampering). `statut` is
    # included because Pilot maps it from its own actif/inactif state.
    _PILOT_LOCKED = {"nom", "prenom", "email", "fonction", "statut"}
    if su.sync_source == "pilot":
        attempted = [f for f in _PILOT_LOCKED if f in body and str(body[f] or "") != (getattr(su, f) or "")]
        if attempted:
            raise HTTPException(
                status_code=403,
                detail=f"These fields are managed by Pilot and cannot be edited here: {', '.join(attempted)}",
            )
    # statut + type_compte go through enum validation.
    if "statut" in body:
        su.statut = _validate_statut(body["statut"])
    if "type_compte" in body:
        su.type_compte = _validate_type_compte(body["type_compte"])
    for f in _FIELDS:
        if f in body:
            val = str(body[f]) if body[f] is not None else ""
            if f == "background_check_url":
                val = _validate_url_field(val, "background_check_url")
            setattr(su, f, val)
    for f in _JUSTIFICATIONS:
        if f in body:
            val = str(body[f]) if body[f] is not None else ""
            setattr(su, f, val[:2000])
    for f in _BOOLS:
        if f in body:
            setattr(su, f, bool(body[f]))
    if "date_fin_contrat" in body:
        su.date_fin_contrat = str(body["date_fin_contrat"] or "")
    # FEAT-15: contract end date required for non-salarie. Enforce only when the
    # patch touches the type or the date, so unrelated patches (e.g. proof
    # toggles) on legacy rows missing the date are not blocked.
    if ("date_fin_contrat" in body or "type_compte" in body) \
            and su.type_compte != "salarie" and not (su.date_fin_contrat or "").strip():
        raise HTTPException(
            status_code=422,
            detail="Date de fin de contrat requise pour les non-salariés",
        )
    if "sort_order" in body:
        su.sort_order = int(body["sort_order"])
    # A proof is only kept validated when it carries a date AND a comment.
    enforce_proof_evidence(su)
    su.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(su)
    return _to_dict(su)


@router.delete("/si-users/{si_user_id}", status_code=204)
async def delete_si_user(project_id: uuid.UUID, si_user_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    su = await db.get(SiUser, (project_id, si_user_id))
    if not su:
        raise HTTPException(status_code=404, detail="SI user not found")
    await db.delete(su)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


_CSV_COL_MAP = {
    "nom": "nom", "name": "nom", "lastname": "nom", "last_name": "nom", "nom_de_famille": "nom",
    "prenom": "prenom", "firstname": "prenom", "first_name": "prenom",
    "email": "email", "mail": "email", "e_mail": "email", "courriel": "email",
    "fonction": "fonction", "function": "fonction", "role": "fonction", "poste": "fonction", "title": "fonction",
    "equipe": "equipe", "team": "equipe", "departement": "equipe", "department": "equipe", "service": "equipe",
    "type_compte": "type_compte", "type": "type_compte", "account_type": "type_compte",
    "date_fin_contrat": "date_fin_contrat", "fin_contrat": "date_fin_contrat",
    "contract_end": "date_fin_contrat", "end_date": "date_fin_contrat", "echeance_contrat": "date_fin_contrat",
    "manager_email": "manager_email", "manager": "manager_email", "responsable_hierarchique": "manager_email",
    "superieur": "manager_email", "supérieur": "manager_email",
    "statut": "statut", "status": "statut",
    # accented header variants (lowercased, accents preserved by normalisation)
    "prénom": "prenom", "équipe": "equipe",
}
_CSV_TYPE_MAP = {
    "salarie": "salarie", "salarié": "salarie", "employe": "salarie", "employee": "salarie",
    "prestataire": "prestataire", "contractor": "prestataire", "externe": "prestataire", "external": "prestataire",
    "stagiaire": "stagiaire", "intern": "stagiaire",
    "alternant": "alternant", "apprenti": "alternant", "apprentice": "alternant",
}
_CSV_STATUT_MAP = {
    "actif": "actif", "active": "actif",
    "ancien": "ancien", "former": "ancien", "inactif": "ancien", "inactive": "ancien",
    "recrutement": "recrutement", "recruiting": "recrutement", "onboarding": "recrutement",
}


@router.post("/si-users/import-csv")
async def import_si_users_csv(project_id: uuid.UUID, file: UploadFile, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import users into the referential from CSV (FEAT-15 Lot 1b).

    Upsert by email (case-insensitive), like sync-from-pilot. Recognised
    columns (FR/EN, accents tolerated): nom, prenom, email, fonction, equipe,
    type_compte, date_fin_contrat, manager_email, statut. Compliance proofs
    are never touched. Rows without an email are skipped.
    """
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

    existing_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    existing = existing_result.scalars().all()
    by_email = {su.email.lower(): su for su in existing if su.email}
    max_num = 0
    for su in existing:
        try:
            n = int(re.sub(r"\D", "", su.id) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    max_order = await db.scalar(
        select(func.coalesce(func.max(SiUser.sort_order), 0)).where(SiUser.project_id == project_id)
    ) or 0

    created = updated = skipped = 0
    for row in reader:
        mapped: dict[str, str] = {}
        for csv_col, csv_val in row.items():
            if csv_col is None or csv_val is None:
                continue
            key = csv_col.strip().lower().replace(" ", "_").replace("-", "_")
            field = _CSV_COL_MAP.get(key)
            if field:
                mapped[field] = csv_val.strip()

        email = mapped.get("email", "").strip()
        if not email:
            skipped += 1
            continue

        key = email.lower()
        if key in by_email:
            su = by_email[key]
            for f in ("nom", "prenom", "fonction", "equipe", "manager_email", "date_fin_contrat"):
                if mapped.get(f):
                    setattr(su, f, mapped[f])
            if "type_compte" in mapped:
                su.type_compte = _CSV_TYPE_MAP.get(mapped["type_compte"].lower(), su.type_compte)
            if "statut" in mapped:
                su.statut = _CSV_STATUT_MAP.get(mapped["statut"].lower(), su.statut)
            su.updated_at = datetime.now(timezone.utc)
            updated += 1
        else:
            max_num += 1
            max_order += 1
            db.add(SiUser(
                project_id=project_id, id=f"USR-{max_num:03d}", sort_order=max_order,
                nom=mapped.get("nom", ""), prenom=mapped.get("prenom", ""), email=email,
                fonction=mapped.get("fonction", ""), equipe=mapped.get("equipe", ""),
                manager_email=mapped.get("manager_email", ""),
                date_fin_contrat=mapped.get("date_fin_contrat", ""),
                type_compte=_CSV_TYPE_MAP.get((mapped.get("type_compte") or "").lower(), "salarie"),
                statut=_CSV_STATUT_MAP.get((mapped.get("statut") or "").lower(), "actif"),
            ))
            by_email[key] = True  # guard against duplicate emails within the same file
            created += 1

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"created": created, "updated": updated, "skipped": skipped}


@router.post("/si-users/sync-from-pilot")
async def sync_si_users_from_pilot(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upsert SiUser entries from Pilot's personnel directory.

    - Matches by email (case-insensitive). Updates nom/prenom/fonction
      if the row already exists, never overwrites compliance flags.
    - Creates missing entries with statut='actif'. Pilot's own statut
      ('actif'/'inactif') is mapped to 'actif'/'ancien'.
    - Does nothing when PILOT_URL / SERVICE_TOKEN aren't configured
      (standalone mode).
    """
    project = await get_project_or_404(project_id, user, db, require_perm="edit")

    if not PILOT_URL or not SERVICE_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Pilot not configured (PILOT_URL / SERVICE_TOKEN missing)",
        )

    # Fetch Pilot directory
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                PILOT_URL.rstrip("/") + "/api/internal/directory",
                headers={"X-Service-Token": SERVICE_TOKEN},
            )
            if not resp.is_success:
                raise HTTPException(
                    status_code=502,
                    detail=f"Pilot directory returned HTTP {resp.status_code}",
                )
            personnel = resp.json()
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Pilot unreachable: {e}")

    # Load existing SiUsers indexed by lowercase email
    existing_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    existing = existing_result.scalars().all()
    by_email = {su.email.lower(): su for su in existing if su.email}

    # Compute next ID + sort_order
    max_num = 0
    for su in existing:
        try:
            n = int(re.sub(r"\D", "", su.id) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    max_order = await db.scalar(
        select(func.coalesce(func.max(SiUser.sort_order), 0)).where(SiUser.project_id == project_id)
    ) or 0

    # Migration 008 renamed 'employe' → 'actif' to match Pilot's vocabulary.
    _STATUT_MAP = {"actif": "actif", "inactif": "ancien"}

    created = 0
    updated = 0
    skipped = 0
    for p in personnel:
        email = (p.get("email") or "").strip()
        if not email:
            skipped += 1
            continue
        key = email.lower()
        if key in by_email:
            su = by_email[key]
            changed = False
            # Only fill in empty fields or refresh name/fonction from Pilot
            if p.get("nom") and su.nom != p["nom"]:
                su.nom = p["nom"]; changed = True
            if p.get("prenom") and su.prenom != p["prenom"]:
                su.prenom = p["prenom"]; changed = True
            if p.get("fonction") and su.fonction != p["fonction"]:
                su.fonction = p["fonction"]; changed = True
            pilot_statut = _STATUT_MAP.get((p.get("statut") or "").lower())
            if pilot_statut and su.statut != pilot_statut:
                su.statut = pilot_statut; changed = True
            if su.sync_source != "pilot":
                su.sync_source = "pilot"; changed = True
            if changed:
                su.updated_at = datetime.now(timezone.utc)
                updated += 1
        else:
            max_num += 1
            max_order += 1
            pilot_statut = _STATUT_MAP.get((p.get("statut") or "").lower(), "actif")
            db.add(SiUser(
                project_id=project_id,
                id=f"USR-{max_num:03d}",
                sort_order=max_order,
                prenom=p.get("prenom") or "",
                nom=p.get("nom") or "",
                email=email,
                fonction=p.get("fonction") or "",
                statut=pilot_statut,
                sync_source="pilot",
            ))
            created += 1

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "total_pilot": len(personnel),
        "created": created,
        "updated": updated,
        "skipped": skipped,
    }


@router.post("/si-users/sync-hr")
async def sync_si_users_from_hr(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Upsert the user referential from the enabled HR connector(s)
    (plugin_type='hr_generic'), FEAT-15 Lot 1c.

    Same upsert-by-email contract as sync-from-pilot: identity/team/manager/
    contract fields are refreshed, type/statut normalised like the CSV import,
    compliance proofs are never touched, sync_source is set to 'hr_generic'.
    """
    project = await get_project_or_404(project_id, user, db, require_perm="edit")

    inst_result = await db.execute(select(PluginConfig).where(
        PluginConfig.project_id == project_id,
        PluginConfig.plugin_type == "hr_generic",
        PluginConfig.enabled.is_(True),
    ))
    instances = inst_result.scalars().all()
    if not instances:
        raise HTTPException(
            status_code=503,
            detail="Aucun connecteur RH actif. Configurez un connecteur 'SIRH' dans Connecteurs et activez-le.",
        )
    cls = PLUGIN_REGISTRY.get("hr_generic")
    if not cls:
        raise HTTPException(status_code=400, detail="Plugin hr_generic indisponible dans ce déploiement")

    existing_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    existing = existing_result.scalars().all()
    by_email: dict[str, object] = {su.email.lower(): su for su in existing if su.email}
    max_num = 0
    for su in existing:
        try:
            n = int(re.sub(r"\D", "", su.id) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    max_order = await db.scalar(
        select(func.coalesce(func.max(SiUser.sort_order), 0)).where(SiUser.project_id == project_id)
    ) or 0

    created = updated = skipped = 0
    errors: list[str] = []
    for pc in instances:
        now = datetime.now(timezone.utc)
        job = SyncJob(project_id=project_id, plugin_id=pc.id, status="running")
        db.add(job)
        await db.flush()
        config: dict = {}
        if pc.config_enc:
            try:
                config = decrypt_config(pc.config_enc)
            except Exception:
                job.status = "error"; job.error_message = "decrypt failed"; job.completed_at = now
                pc.last_sync_at = now; pc.last_sync_status = "error"
                errors.append(f"{pc.id}: decrypt failed")
                continue
        try:
            sync_result = await cls().sync(config, pc.group_filters or [])
        except Exception as e:
            job.status = "error"; job.error_message = type(e).__name__[:200]; job.completed_at = now
            pc.last_sync_at = now; pc.last_sync_status = "error"
            errors.append(f"{pc.id}: {type(e).__name__}")
            continue

        inst_created = inst_updated = 0
        for rec in sync_result.users:
            ident = rec.raw_data or {}
            email = (rec.email or ident.get("email", "")).strip()
            if not email:
                skipped += 1
                continue
            key = email.lower()
            tc = _CSV_TYPE_MAP.get((ident.get("type_compte") or "").lower())
            st = _CSV_STATUT_MAP.get((ident.get("statut") or "").lower())
            if key in by_email:
                su = by_email[key]
                if not isinstance(su, SiUser):
                    continue
                changed = False
                for f in ("nom", "prenom", "fonction", "equipe", "manager_email", "date_fin_contrat"):
                    val = ident.get(f)
                    if val and getattr(su, f) != val:
                        setattr(su, f, val); changed = True
                if tc and su.type_compte != tc:
                    su.type_compte = tc; changed = True
                if st and su.statut != st:
                    su.statut = st; changed = True
                if su.sync_source != "hr_generic":
                    su.sync_source = "hr_generic"; changed = True
                if changed:
                    su.updated_at = now
                    updated += 1; inst_updated += 1
            else:
                max_num += 1; max_order += 1
                nu = SiUser(
                    project_id=project_id, id=f"USR-{max_num:03d}", sort_order=max_order,
                    nom=ident.get("nom", ""), prenom=ident.get("prenom", ""), email=email,
                    fonction=ident.get("fonction", ""), equipe=ident.get("equipe", ""),
                    manager_email=ident.get("manager_email", ""),
                    date_fin_contrat=ident.get("date_fin_contrat", ""),
                    type_compte=tc or "salarie", statut=st or "actif", sync_source="hr_generic",
                )
                db.add(nu)
                by_email[key] = nu
                created += 1; inst_created += 1

        job.status = "success" if not sync_result.errors else "partial"
        job.users_found = len(sync_result.users)
        job.users_created = inst_created; job.users_updated = inst_updated
        job.completed_at = now
        if sync_result.errors:
            job.error_message = ("; ".join(sync_result.errors))[:2000]
            errors.extend(sync_result.errors)
        pc.last_sync_at = now; pc.last_sync_status = job.status

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # One-directional self-sync to Pilot: Access owns these HR-fed identities,
    # so mirror them into Pilot's directory (Pilot marks them sync_source=
    # "access", read-only there, and re-broadcasts to the other modules — never
    # back to Access). Fire-and-forget; never blocks the HR sync result.
    try:
        from src.routes.directory_proxy import push_identities_to_pilot, siuser_to_pilot_dict
        hr_rows = (await db.execute(select(SiUser).where(
            SiUser.project_id == project_id, SiUser.sync_source == "hr_generic",
        ))).scalars().all()
        await push_identities_to_pilot([siuser_to_pilot_dict(su) for su in hr_rows])
    except Exception:
        pass

    return {"instances": len(instances), "created": created, "updated": updated, "skipped": skipped, "errors": errors[:20]}


def _to_dict(u: SiUser) -> dict:
    return {
        "id": u.id, "nom": u.nom, "prenom": u.prenom, "email": u.email,
        "statut": u.statut, "type_compte": u.type_compte or "salarie", "fonction": u.fonction,
        "equipe": u.equipe or "", "date_fin_contrat": u.date_fin_contrat or "",
        "manager_email": u.manager_email or "",
        "politique_validee": u.politique_validee,
        "politique_date": u.politique_date,
        "politique_justification": u.politique_justification or "",
        "mfa_active": u.mfa_active,
        "mfa_date": u.mfa_date,
        "mfa_justification": u.mfa_justification or "",
        "sensibilisation": u.sensibilisation,
        "sensibilisation_date": u.sensibilisation_date,
        "sensibilisation_justification": u.sensibilisation_justification or "",
        "sensibilisation_history": u.sensibilisation_history or {},
        "background_check": u.background_check,
        "background_check_date": u.background_check_date or "",
        "background_check_justification": u.background_check_justification or "",
        "background_check_url": u.background_check_url or "",
        "nda_signed": u.nda_signed,
        "nda_date": u.nda_date or "",
        "nda_justification": u.nda_justification or "",
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else "",
        "account_enabled": u.account_enabled,
        "sync_source": u.sync_source or "",
    }
