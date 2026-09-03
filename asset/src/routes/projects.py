from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import ADMIN_MODULE_ROLES, VIEWER_MODULE_ROLES, auth_enabled, get_current_user
from src.database import get_db
from src.models import (
    Asset,
    AssetGroup,
    Measure,
    Project,
    ProjectMetadata,
    User,
)
from src.schemas import (
    ProjectCreate,
    ProjectListItem,
    ProjectResponse,
    ProjectUpdate,
    ShareRequest,
)
from src.upload_common import read_csv_upload, read_json_upload

router = APIRouter(prefix="/api/projects", tags=["projects"])


# ── Helpers ────────────────────────────────────────────────────────

def _user_permissions(project: Project, user: Optional[User]) -> list[str]:
    """Asset has a single shared inventory — no per-user ownership.
    Any authenticated user who passed get_current_user gets read+edit.
    Only admin gets delete+share."""
    if not auth_enabled() or user is None:
        return ["read", "edit", "delete", "share"]
    mrole = getattr(user, "_module_role", "")
    if user.role == "admin" or mrole in ADMIN_MODULE_ROLES:
        return ["read", "edit", "delete", "share"]
    if mrole in VIEWER_MODULE_ROLES:
        return ["read"]
    return ["read", "edit"]


def _can(perm: str, project: Project, user: Optional[User]) -> bool:
    return perm in _user_permissions(project, user)


# ── Reconstruct D object from relational tables ───────────────────

def _asset_to_dict(a: Asset) -> dict:
    return {
        "id": a.id,
        "nom": a.nom or "",
        "type": a.type or "application",
        "description": a.description or "",
        "criticite": a.criticite or 2,
        "proprietaire": a.proprietaire or "",
        "localisation": a.localisation or "",
        "quantite": a.quantite or 1,
        "os": a.os or "",
        "version": a.version or "",
        "fournisseur": a.fournisseur or "",
        "fin_support": a.fin_support or "",
        "fin_vie": a.fin_vie or "",
        "statut": a.statut or "actif",
        "notes": a.notes or "",
        "ip_address": a.ip_address or "",
        "sources": a.sources or {},
        "depends_on": a.depends_on or [],
        "licence": a.licence or {},
        "groupe_ids": [],  # computed below
        "last_login_at": a.last_login_at.isoformat() if a.last_login_at else "",
    }


def _group_to_dict(g: AssetGroup) -> dict:
    return {
        "id": g.id,
        "nom": g.nom or "",
        "principe": g.principe or "",
        "criticite": g.criticite or 2,
        "notes": g.notes or "",
        "raci": g.raci or [],
        "politique_sauvegarde": g.politique_sauvegarde or {},
        "politique_supervision": g.politique_supervision or {},
        "politique_maj": g.politique_maj or {},
        "asset_ids": g.asset_ids or [],
        "depends_on_groups": g.depends_on_groups or [],
    }


async def _reconstruct_data(db: AsyncSession, project_id: uuid.UUID) -> dict:
    """Reconstruct the D object from relational tables."""
    meta_result = await db.execute(
        select(ProjectMetadata).where(ProjectMetadata.project_id == project_id)
    )
    meta = meta_result.scalar_one_or_none()

    assets_result = await db.execute(
        select(Asset).where(Asset.project_id == project_id).order_by(Asset.sort_order)
    )
    assets = assets_result.scalars().all()

    groups_result = await db.execute(
        select(AssetGroup).where(AssetGroup.project_id == project_id).order_by(AssetGroup.sort_order)
    )
    groups = groups_result.scalars().all()

    # Build group membership: asset_ids from groups -> compute asset.groupe_ids
    group_members: dict[str, list[str]] = {}
    for g in groups:
        for aid in (g.asset_ids or []):
            group_members.setdefault(aid, []).append(g.id)

    # Build assets with computed groupe_ids
    assets_data = []
    for a in assets:
        d = _asset_to_dict(a)
        d["groupe_ids"] = group_members.get(a.id, [])
        assets_data.append(d)

    # FEAT-22: measures exposed READ-ONLY for the export round-trip. They are
    # NOT consumed by _decompose_data and NOT deleted by _delete_children — a
    # dedicated REST CRUD owns them, so a blob autosave never wipes a measure
    # (e.g. one the renewal scheduler just created).
    measures_result = await db.execute(
        select(Measure).where(Measure.project_id == project_id).order_by(Measure.sort_order)
    )
    measures = measures_result.scalars().all()

    data = {
        "metadata": {
            "organization": meta.organization or "" if meta else "",
            "created": meta.created_date or "" if meta else "",
        },
        "assets": assets_data,
        "groupes": [_group_to_dict(g) for g in groups],
        # Per-project user-defined asset types (flat list).
        "custom_asset_types": (meta.custom_asset_types or []) if meta else [],
        "measures": [
            {
                "id": m.id, "title": m.title, "description": m.description or "",
                "statut": m.statut, "responsable": m.responsable or "",
                "echeance": m.echeance or "", "progress_log": m.progress_log or [],
                "origine": m.origine or "manual", "asset_id": m.asset_id or "",
                # Round-trip completeness (FEAT-30): auto_key carries the
                # renewal-scheduler dedup identity; timestamps keep the
                # original dates through a backup/restore cycle.
                "sort_order": m.sort_order, "auto_key": m.auto_key,
                "created_at": m.created_at.isoformat() if m.created_at else None,
                "updated_at": m.updated_at.isoformat() if m.updated_at else None,
            }
            for m in measures
        ],
    }
    return data


# ── Decompose D object into relational tables ─────────────────────

async def _delete_children(db: AsyncSession, project_id: uuid.UUID):
    """Delete all child rows for a project."""
    await db.execute(delete(Asset).where(Asset.project_id == project_id))
    await db.execute(delete(AssetGroup).where(AssetGroup.project_id == project_id))
    await db.execute(delete(ProjectMetadata).where(ProjectMetadata.project_id == project_id))


def _s(val) -> str:
    """Safe str cast for VARCHAR columns receiving int/float from JSON."""
    if val is None:
        return ""
    return str(val)


def _sanitize_ip(val) -> str:
    """Accept only a valid IPv4/IPv6 literal or an empty string.
    Returns the canonical compressed form; anything invalid becomes ""
    so junk CSV cells and buggy connector payloads don't persist."""
    if val in (None, ""):
        return ""
    s = str(val).strip()
    if not s:
        return ""
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return ""


async def _decompose_data(db: AsyncSession, project_id: uuid.UUID, data: dict):
    """Decompose a D object into relational child rows."""
    # Metadata
    meta = data.get("metadata") or {}
    # Custom asset types can travel either at the root of the blob
    # (matching the _reconstruct_data shape) or nested under metadata
    # (older exports) — accept both.
    custom_types = data.get("custom_asset_types")
    if custom_types is None:
        custom_types = meta.get("custom_asset_types") or []
    # Light validation: each entry must be a dict with at least an id + label.
    clean_types = []
    seen_ids = set()
    for ct in custom_types if isinstance(custom_types, list) else []:
        if not isinstance(ct, dict):
            continue
        cid = str(ct.get("id") or "").strip().lower()
        if not cid or cid in seen_ids:
            continue
        seen_ids.add(cid)
        clean_types.append({
            "id": cid[:64],
            "label": str(ct.get("label") or cid)[:100],
            "label_en": str(ct.get("label_en") or "")[:100],
            "color": str(ct.get("color") or "#6b7280")[:16],
        })
    db.add(ProjectMetadata(
        project_id=project_id,
        organization=meta.get("organization", ""),
        created_date=meta.get("created", ""),
        custom_asset_types=clean_types,
    ))

    # Assets
    for i, a in enumerate(data.get("assets") or []):
        crit = a.get("criticite", 2)
        if isinstance(crit, str):
            try:
                crit = int(crit)
            except ValueError:
                crit = 2
        quant = a.get("quantite", 1)
        if isinstance(quant, str):
            try:
                quant = int(quant)
            except ValueError:
                quant = 1

        db.add(Asset(
            project_id=project_id,
            id=a.get("id", ""),
            sort_order=i,
            nom=_s(a.get("nom", "")),
            type=_s(a.get("type", "application")),
            description=_s(a.get("description", "")),
            criticite=crit,
            proprietaire=_s(a.get("proprietaire", "")),
            localisation=_s(a.get("localisation", "")),
            quantite=quant,
            os=_s(a.get("os", "")),
            version=_s(a.get("version", "")),
            fournisseur=_s(a.get("fournisseur", "")),
            fin_support=_s(a.get("fin_support", "")),
            fin_vie=_s(a.get("fin_vie", "")),
            statut=_s(a.get("statut", "actif")),
            notes=_s(a.get("notes", "")),
            ip_address=_sanitize_ip(a.get("ip_address", "")),
            sources=a.get("sources") or {},
            depends_on=a.get("depends_on") or [],
            licence=a.get("licence") or {},
        ))

    # Groups
    for i, g in enumerate(data.get("groupes") or []):
        crit = g.get("criticite", 2)
        if isinstance(crit, str):
            try:
                crit = int(crit)
            except ValueError:
                crit = 2

        db.add(AssetGroup(
            project_id=project_id,
            id=g.get("id", ""),
            sort_order=i,
            nom=_s(g.get("nom", "")),
            principe=_s(g.get("principe", "")),
            criticite=crit,
            notes=_s(g.get("notes", "")),
            raci=g.get("raci") or [],
            politique_sauvegarde=g.get("politique_sauvegarde") or {},
            politique_supervision=g.get("politique_supervision") or {},
            politique_maj=g.get("politique_maj") or {},
            asset_ids=g.get("asset_ids") or [],
            depends_on_groups=g.get("depends_on_groups") or [],
        ))


# ── Routes ─────────────────────────────────────────────────────────

@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(
    body: ProjectCreate,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Asset uses a single shared inventory — block creation if one exists.
    existing = await db.execute(select(func.count()).select_from(Project))
    if (existing.scalar() or 0) > 0:
        raise HTTPException(status_code=409, detail="A project already exists. Asset uses a single shared inventory.")
    project = Project(
        name=body.name,
        organization=body.organization,
        owner_id=user.id if user else None,
    )
    db.add(project)
    await db.flush()

    if body.data:
        await _decompose_data(db, project.id, body.data)

    await db.commit()
    await db.refresh(project)

    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.get("", response_model=list[ProjectListItem])
async def list_projects(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Single-project modules boot on list[0]: the canonical project must
    # come first even if a stray (e.g. resurrected by an old restore)
    # was updated more recently (FEAT-30 P1bis).
    from src.default_project import DEFAULT_PROJECT_ID
    result = await db.execute(
        select(Project).order_by(
            (Project.id == DEFAULT_PROJECT_ID).desc(),
            Project.updated_at.desc())
    )
    projects = result.scalars().all()
    if not auth_enabled() or user is None or user.role == "admin":
        return projects
    return [p for p in projects if _can("read", p, user)]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", project, user):
        raise HTTPException(status_code=403, detail="Access denied")

    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    # FEAT-33 stale-tab guard: refuse the whole-blob overwrite when a
    # server-initiated writer bumped server_rev since this tab loaded.
    if body.expected_server_rev is not None and (project.server_rev or 0) > body.expected_server_rev:
        raise HTTPException(status_code=409,
                            detail="Données modifiées côté serveur depuis le chargement (Pilot/scheduler) — rechargez avant une sauvegarde globale.")
    if not _can("edit", project, user):
        raise HTTPException(status_code=403, detail="Access denied")

    if body.name is not None:
        project.name = body.name
    if body.organization is not None:
        project.organization = body.organization

    if body.data is not None:
        await _delete_children(db, project.id)
        await _decompose_data(db, project.id, body.data)

    project.updated_at = datetime.now(timezone.utc)
    from src.audit import log_write
    await log_write(db, user, None,
                    "project.blob_put" if body.data is not None else "project.update",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)

    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("delete", project, user):
        raise HTTPException(status_code=403, detail="Access denied")
    from src.audit import log_write
    await log_write(db, user, None, "project.delete",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/duplicate", response_model=ProjectResponse, status_code=201)
async def duplicate_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    original = await db.get(Project, project_id)
    if not original:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", original, user):
        raise HTTPException(status_code=403, detail="Access denied")

    original_data = await _reconstruct_data(db, original.id)

    duplicate = Project(
        name=original.name + " (copy)",
        organization=original.organization,
        owner_id=user.id if user else None,
    )
    db.add(duplicate)
    await db.flush()

    await _decompose_data(db, duplicate.id, original_data)
    await db.commit()
    await db.refresh(duplicate)

    data = await _reconstruct_data(db, duplicate.id)
    return _project_response(duplicate, data)


@router.post("/import", response_model=ProjectResponse, status_code=201)
async def import_project(
    file: UploadFile,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    import json

    content = await read_json_upload(file, 10 * 1024 * 1024)
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    # FEAT-36 — refuse future revs, normalize + replay schema migrations.
    from src.schema_migrations import FutureRevError, migrate_blob
    try:
        data = migrate_blob("asset", data)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    name = ""
    if isinstance(data, dict):
        meta = data.get("metadata", {})
        name = meta.get("organization", "") if isinstance(meta, dict) else ""

    project = Project(
        name=name,
        owner_id=user.id if user else None,
    )
    db.add(project)
    await db.flush()

    if isinstance(data, dict):
        await _decompose_data(db, project.id, data)

    from src.audit import log_write
    await log_write(db, user, None, "project.import",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)

    data_out = await _reconstruct_data(db, project.id)
    return _project_response(project, data_out)


@router.post("/{project_id}/import-csv")
async def import_csv(
    project_id: uuid.UUID,
    file: UploadFile,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import assets from a CSV file into an existing project.

    Supports both comma and semicolon delimiters (auto-detected).
    Columns mapped: nom, type, criticite, proprietaire, localisation, quantite,
    os, version, fournisseur, fin_support, fin_vie, statut, description, notes.
    Unknown columns are ignored. IDs are auto-generated.
    """
    import csv
    import io

    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("edit", project, user):
        raise HTTPException(status_code=403, detail="Access denied")

    content = await read_csv_upload(file, 5 * 1024 * 1024)

    # Decode with BOM handling
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = content.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise HTTPException(status_code=400, detail="Cannot decode file (try UTF-8 or Latin-1)")

    # Auto-detect delimiter
    first_line = text.split("\n")[0]
    delimiter = ";" if first_line.count(";") > first_line.count(",") else ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)

    # Normalize header names: strip, lowercase, replace spaces/dashes
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV has no header row")

    _COL_MAP = {
        "nom": "nom", "name": "nom", "asset": "nom", "actif": "nom",
        "type": "type", "categorie": "type", "category": "type",
        "criticite": "criticite", "criticality": "criticite", "crit": "criticite",
        "proprietaire": "proprietaire", "owner": "proprietaire", "responsable": "proprietaire",
        "localisation": "localisation", "location": "localisation", "site": "localisation",
        "quantite": "quantite", "quantity": "quantite", "qty": "quantite",
        "os": "os", "systeme": "os", "operating_system": "os",
        "version": "version",
        "fournisseur": "fournisseur", "vendor": "fournisseur", "supplier": "fournisseur",
        "fin_support": "fin_support", "end_of_support": "fin_support", "eos": "fin_support",
        "fin_vie": "fin_vie", "end_of_life": "fin_vie", "eol": "fin_vie",
        "statut": "statut", "status": "statut", "etat": "statut",
        "description": "description", "desc": "description",
        "notes": "notes", "remarques": "notes", "comments": "notes",
        "last_login": "last_login_at", "last_logon": "last_login_at",
        "lastlogin": "last_login_at", "lastlogon": "last_login_at",
        "derniere_connexion": "last_login_at", "last_login_at": "last_login_at",
        "ip": "ip_address", "ip_address": "ip_address",
        "adresse_ip": "ip_address", "ipv4": "ip_address",
    }

    # Valid asset types (built-ins). Custom types from project_metadata
    # are loaded below and added to the allowed set — a CSV row with a
    # custom type (matched by id or label) passes through as-is.
    _VALID_TYPES = {
        "terminal_mobile", "poste_physique", "poste_virtuel",
        "serveur_physique", "serveur_virtuel", "systeme_exploitation",
        "application", "donnees",
    }
    _TYPE_ALIASES = {
        "mobile": "terminal_mobile", "smartphone": "terminal_mobile", "tablet": "terminal_mobile", "tablette": "terminal_mobile",
        "desktop": "poste_physique", "pc": "poste_physique", "workstation": "poste_physique", "poste": "poste_physique",
        "vdi": "poste_virtuel", "vm_desktop": "poste_virtuel",
        "server": "serveur_physique", "serveur": "serveur_physique", "physical_server": "serveur_physique",
        "vm": "serveur_virtuel", "virtual_server": "serveur_virtuel", "virtual": "serveur_virtuel", "container": "serveur_virtuel",
        "os": "systeme_exploitation", "operating_system": "systeme_exploitation",
        "app": "application", "software": "application", "logiciel": "application", "saas": "application",
        "data": "donnees", "database": "donnees", "db": "donnees", "base_donnees": "donnees", "bdd": "donnees",
    }

    # Load project's custom types and build a combined id + label index.
    _meta_result = await db.execute(
        select(ProjectMetadata.custom_asset_types).where(ProjectMetadata.project_id == project_id)
    )
    _custom_types_raw = _meta_result.scalar() or []
    _custom_ids: set[str] = set()
    _custom_aliases: dict[str, str] = {}
    for _ct in _custom_types_raw if isinstance(_custom_types_raw, list) else []:
        if not isinstance(_ct, dict):
            continue
        _cid = str(_ct.get("id") or "").strip().lower()
        if not _cid:
            continue
        _custom_ids.add(_cid)
        for _lab in (_ct.get("label"), _ct.get("label_en")):
            if isinstance(_lab, str) and _lab:
                _custom_aliases[_lab.strip().lower().replace(" ", "_").replace("-", "_")] = _cid

    def _normalize_type(raw: str) -> str:
        val = raw.strip().lower().replace(" ", "_").replace("-", "_")
        if val in _VALID_TYPES or val in _custom_ids:
            return val
        if val in _custom_aliases:
            return _custom_aliases[val]
        return _TYPE_ALIASES.get(val, "application")

    def _normalize_crit(raw: str) -> int:
        try:
            v = int(float(raw.strip()))
            return max(1, min(5, v))
        except (ValueError, TypeError):
            return 2

    def _normalize_statut(raw: str) -> str:
        val = raw.strip().lower()
        mapping = {
            "actif": "actif", "active": "actif", "en_service": "actif",
            "inactif": "inactif", "inactive": "inactif",
            "en_cours": "en_cours", "deploiement": "en_cours", "in_progress": "en_cours",
            "retire": "retire", "retired": "retire", "decommissioned": "retire",
        }
        return mapping.get(val, "actif")

    def _parse_last_login(raw: str):
        """Parse a date/datetime string into an aware UTC datetime.
        Accepts ISO-8601 (`2026-04-19`, `2026-04-19T14:30:00Z`) AND the
        European `DD/MM/YYYY` format commonly produced by Excel when it
        re-saves a CSV. Returns None on empty / unparseable values."""
        if not raw:
            return None
        s = raw.strip()
        if not s:
            return None
        from datetime import date as _date
        # DD/MM/YYYY or DD-MM-YYYY (Excel FR / many corp exports)
        if len(s) == 10 and s[2] in "/-" and s[5] in "/-":
            try:
                dd, mm, yyyy = int(s[0:2]), int(s[3:5]), int(s[6:10])
                return datetime(yyyy, mm, dd, tzinfo=timezone.utc)
            except ValueError:
                return None
        # ISO 'YYYY-MM-DD'
        try:
            if len(s) == 10:
                return datetime.combine(_date.fromisoformat(s), datetime.min.time(), tzinfo=timezone.utc)
            # Tolerate trailing Z on full ISO datetimes
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None

    # Get current max asset ID to auto-increment
    existing_result = await db.execute(
        select(Asset).where(Asset.project_id == project_id)
    )
    existing_assets = existing_result.scalars().all()
    max_num = 0
    for a in existing_assets:
        try:
            n = int(re.sub(r'\D', '', a.id) or '0')
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    current_order = len(existing_assets)

    imported = []
    for row in reader:
        # Map columns
        mapped = {}
        for csv_col, csv_val in row.items():
            if csv_col is None:
                continue
            key = csv_col.strip().lower().replace(" ", "_").replace("-", "_")
            field = _COL_MAP.get(key)
            if field and csv_val is not None:
                mapped[field] = csv_val.strip()

        # Skip empty rows
        if not mapped.get("nom"):
            continue

        max_num += 1
        current_order += 1
        asset_id = f"A-{max_num:03d}"

        quant = 1
        if "quantite" in mapped:
            try:
                quant = max(1, int(float(mapped["quantite"])))
            except (ValueError, TypeError):
                quant = 1

        db.add(Asset(
            project_id=project_id,
            id=asset_id,
            sort_order=current_order,
            nom=mapped.get("nom", ""),
            type=_normalize_type(mapped.get("type", "application")),
            description=mapped.get("description", ""),
            criticite=_normalize_crit(mapped.get("criticite", "2")),
            proprietaire=mapped.get("proprietaire", ""),
            localisation=mapped.get("localisation", ""),
            quantite=quant,
            os=mapped.get("os", ""),
            version=mapped.get("version", ""),
            fournisseur=mapped.get("fournisseur", ""),
            fin_support=mapped.get("fin_support", ""),
            fin_vie=mapped.get("fin_vie", ""),
            statut=_normalize_statut(mapped.get("statut", "actif")),
            notes=mapped.get("notes", ""),
            ip_address=_sanitize_ip(mapped.get("ip_address")),
            depends_on=[],
            last_login_at=_parse_last_login(mapped.get("last_login_at", "")),
        ))
        imported.append(asset_id)

    project.updated_at = datetime.now(timezone.utc)
    from src.audit import log_write
    await log_write(db, user, None, "project.import_csv",
                    entity_type="project", entity_id=str(project.id),
                    target=project.name or "", details={"imported": len(imported)})
    await db.commit()
    await db.refresh(project)

    data = await _reconstruct_data(db, project.id)
    return {
        "imported": len(imported),
        "asset_ids": imported,
        "data": data,
    }


@router.get("/{project_id}/export")
async def export_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", project, user):
        raise HTTPException(status_code=403, detail="Access denied")

    data = await _reconstruct_data(db, project.id)
    filename = re.sub(r'[^a-zA-Z0-9_-]', '_', project.name or "export") + "_Asset.json"
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{project_id}/share", response_model=ProjectResponse)
async def share_project(
    project_id: uuid.UUID,
    body: ShareRequest,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("share", project, user):
        raise HTTPException(status_code=403, detail="No share permission")

    valid = {"read", "edit", "delete", "share"}
    perms = [p for p in body.permissions if p in valid]
    if not perms:
        raise HTTPException(status_code=400, detail="At least one valid permission required")

    result = await db.execute(select(User).where(User.email == body.email))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found with this email")

    shared = list(project.shared_with or [])
    found = False
    for entry in shared:
        if entry.get("user_id") == str(target.id):
            entry["permissions"] = perms
            entry["name"] = target.name
            found = True
            break
    if not found:
        shared.append({"user_id": str(target.id), "email": target.email, "name": target.name, "permissions": perms})

    project.shared_with = shared
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(project)

    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.delete("/{project_id}/share/{user_email}", response_model=ProjectResponse)
async def revoke_share(
    project_id: uuid.UUID,
    user_email: str,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("share", project, user):
        raise HTTPException(status_code=403, detail="No share permission")

    shared = [s for s in (project.shared_with or []) if s.get("email") != user_email]
    project.shared_with = shared
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(project)

    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


# ── Response builder ───────────────────────────────────────────────

def _project_response(project: Project, data: dict) -> dict:
    return {
        "id": project.id,
        "name": project.name,
        "organization": project.organization,
        "owner_id": project.owner_id,
        "shared_with": project.shared_with or [],
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "server_rev": project.server_rev or 0,
        "data": data,
    }
