"""Access reviews — CSV import, entry-by-entry decisions, auto-measures, close/archive."""

from __future__ import annotations

import csv
import io
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.crypto import decrypt_config
from src.database import get_db
from src.models import Application, Measure, PluginConfig, Review, ReviewEntry, ServiceAccount, SiUser, SyncJob, User
from src.plugins import PLUGIN_REGISTRY
from src.routes.auth_helpers import get_project_or_404
from src.upload_common import read_csv_upload, read_tabular_upload

router = APIRouter(prefix="/api/projects/{project_id}", tags=["reviews"])


# ── Helpers ────────────────────────────────────────────────────────

def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _gen_id(prefix: str, existing: list, max_num: int = 0) -> str:
    for item in existing:
        try:
            n = int(re.sub(r'\D', '', item.id) or '0')
            if n > max_num:
                max_num = n
        except (ValueError, AttributeError):
            pass
    return f"{prefix}{max_num + 1:03d}"


def _norm_name(nom: str, prenom: str) -> str:
    """Normalized 'lastname|firstname' key for name-based SI matching:
    accent-stripped, lower-cased, whitespace-collapsed. Empty if either
    part is missing (we never match on a half-identity)."""
    def _n(s: str) -> str:
        s = unicodedata.normalize("NFKD", s or "")
        s = "".join(c for c in s if not unicodedata.combining(c))
        return " ".join(s.lower().split())
    n, p = _n(nom), _n(prenom)
    return f"{n}|{p}" if n and p else ""


def _entry_to_dict(e: ReviewEntry) -> dict:
    return {
        "id": e.id, "type_compte": e.type_compte or "personnel",
        "email_or_login": e.email_or_login or "",
        "nom": e.nom or "", "prenom": e.prenom or "",
        "roles": e.roles or "", "groups": e.groups or "",
        "si_user_id": e.si_user_id or None,
        "decision": e.decision or "pending",
        "decided_by": e.decided_by or "", "decided_at": e.decided_at or "",
        "notes": e.notes or "",
        "last_login_at": e.last_login_at.isoformat() if e.last_login_at else "",
        "account_enabled": e.account_enabled,
    }


def _review_to_dict(r: Review, entries: list) -> dict:
    return {
        "id": r.id, "application_id": r.application_id or "",
        "status": r.status or "en_cours",
        "started_at": r.started_at or "", "closed_at": r.closed_at or "",
        "closed_by": r.closed_by or "",
        "entries": entries,
    }


# ── Routes ─────────────────────────────────────────────────────────

@router.get("/reviews")
async def list_reviews(project_id: uuid.UUID, status: str = None, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    q = select(Review).where(Review.project_id == project_id)
    if status:
        q = q.where(Review.status == status)
    result = await db.execute(q.order_by(Review.sort_order.desc()))
    reviews = result.scalars().all()

    entries_result = await db.execute(select(ReviewEntry).where(ReviewEntry.project_id == project_id))
    all_entries = entries_result.scalars().all()
    entries_by_review: dict[str, list] = {}
    for e in all_entries:
        entries_by_review.setdefault(e.review_id, []).append(_entry_to_dict(e))

    return [_review_to_dict(r, entries_by_review.get(r.id, [])) for r in reviews]


@router.post("/reviews", status_code=201)
async def create_review(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    app_id = body.get("application_id", "")
    if not app_id:
        raise HTTPException(status_code=400, detail="application_id required")

    app = await db.get(Application, (project_id, app_id))
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    existing = await db.execute(select(Review).where(Review.project_id == project_id))
    all_reviews = existing.scalars().all()
    max_order = await db.scalar(select(func.coalesce(func.max(Review.sort_order), 0)).where(Review.project_id == project_id))

    review = Review(
        project_id=project_id,
        id=_gen_id("REV-", all_reviews),
        sort_order=(max_order or 0) + 1,
        application_id=app_id,
        status="en_cours",
        started_at=_today(),
    )
    db.add(review)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(review)
    return _review_to_dict(review, [])


@router.get("/reviews/{review_id}")
async def get_review(project_id: uuid.UUID, review_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    entries_result = await db.execute(
        select(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id).order_by(ReviewEntry.sort_order)
    )
    entries = [_entry_to_dict(e) for e in entries_result.scalars().all()]
    return _review_to_dict(review, entries)


@router.post("/reviews/{review_id}/import-csv")
async def import_csv(project_id: uuid.UUID, review_id: str, file: UploadFile, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Import access rights from CSV into a review."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Review is closed")

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
        "type_compte": "type_compte", "type": "type_compte", "account_type": "type_compte",
        "email": "email_or_login", "email_or_login": "email_or_login", "login": "email_or_login",
        "mail": "email_or_login", "identifiant": "email_or_login", "user": "email_or_login",
        "roles": "roles", "role": "roles", "profil": "roles", "profils": "roles",
        "groups": "groups", "groupe": "groups", "groupes": "groups", "group": "groups",
    }

    # Load SI users for email matching
    si_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    si_users = si_result.scalars().all()
    email_to_si: dict[str, str] = {u.email.lower(): u.id for u in si_users if u.email}

    # Get existing entries to compute next ID
    existing_result = await db.execute(
        select(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id)
    )
    existing_entries = existing_result.scalars().all()
    max_num = 0
    for e in existing_entries:
        try:
            n = int(re.sub(r'\D', '', e.id.replace(review_id + "-", "")) or '0')
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    current_order = len(existing_entries)

    matched = 0
    unmatched = 0
    imported_ids = []

    for row in reader:
        mapped = {}
        for csv_col, csv_val in row.items():
            if csv_col is None:
                continue
            key = csv_col.strip().lower().replace(" ", "_").replace("-", "_")
            field = _COL_MAP.get(key)
            if field and csv_val is not None:
                mapped[field] = csv_val.strip()

        email_login = mapped.get("email_or_login", "")
        if not email_login:
            continue

        max_num += 1
        current_order += 1
        entry_id = f"{review_id}-E{max_num:03d}"

        si_user_id = email_to_si.get(email_login.lower())
        if si_user_id:
            matched += 1
        else:
            unmatched += 1

        type_compte = mapped.get("type_compte", "personnel").lower()
        if type_compte not in ("personnel", "service"):
            type_compte = "service" if "service" in type_compte else "personnel"

        db.add(ReviewEntry(
            project_id=project_id, review_id=review_id, id=entry_id,
            sort_order=current_order,
            type_compte=type_compte,
            email_or_login=email_login,
            roles=mapped.get("roles", ""),
            groups=mapped.get("groups", ""),
            si_user_id=si_user_id,
            decision="pending",
        ))
        imported_ids.append(entry_id)

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "imported": len(imported_ids),
        "matched": matched,
        "unmatched": unmatched,
        "entry_ids": imported_ids,
    }


def _resolve_connector_class(pc: PluginConfig):
    cls = PLUGIN_REGISTRY.get(pc.plugin_type)
    if not cls:
        raise HTTPException(
            status_code=400,
            detail=f"Plugin type '{pc.plugin_type}' not available in this deployment",
        )
    return cls


async def _resolve_review_connector(project_id, review, plugin_id, db):
    """Pick the connector linked to the review's application.
    Prefers an enabled plugin; honours an explicit plugin_id when given."""
    app = await db.get(Application, (project_id, review.application_id))
    if not app:
        raise HTTPException(status_code=404, detail="Application linked to review not found")
    plugins_result = await db.execute(
        select(PluginConfig).where(
            PluginConfig.project_id == project_id,
            PluginConfig.application_id == app.id,
        )
    )
    candidates = plugins_result.scalars().all()
    if plugin_id:
        candidates = [p for p in candidates if p.id == plugin_id]
    if not candidates:
        raise HTTPException(
            status_code=400,
            detail="No connector linked to this application. Link a plugin first.",
        )
    enabled = [p for p in candidates if p.enabled]
    return enabled[0] if enabled else candidates[0]


def _connector_config(pc: PluginConfig) -> dict:
    config: dict = {}
    if pc.config_enc:
        try:
            config = decrypt_config(pc.config_enc)
        except Exception as e:
            import logging
            logging.getLogger("access-backend").exception("Cannot decrypt connector config: %s", e)
            raise HTTPException(status_code=500, detail="Cannot decrypt connector config — check server logs")
    return config


@router.post("/reviews/{review_id}/import-connector")
async def import_from_connector(
    project_id: uuid.UUID,
    review_id: str,
    body: Optional[dict] = Body(default=None),
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Populate review entries from the API connector linked to the
    application this review belongs to.

    Body (optional): { "plugin_id": "PLG-001" } to pick a specific
    connector when the application has several. Otherwise uses the
    first enabled plugin linked to the application.

    File-based connectors (``accepts_file``) are NOT served here — the
    file is uploaded at sync time via ``import-connector-file``.
    """
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Review is closed")

    plugin_id = (body or {}).get("plugin_id") if isinstance(body, dict) else None
    pc = await _resolve_review_connector(project_id, review, plugin_id, db)
    cls = _resolve_connector_class(pc)
    if getattr(cls, "accepts_file", False):
        raise HTTPException(
            status_code=400,
            detail="This connector imports a file — upload it via import-connector-file.",
        )
    config = _connector_config(pc)
    return await _run_connector_import(project, review, pc, cls, config, db)


@router.post("/reviews/{review_id}/import-connector-file")
async def import_from_connector_file(
    project_id: uuid.UUID,
    review_id: str,
    file: UploadFile = File(...),
    plugin_id: Optional[str] = Form(default=None),
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Populate review entries from a file uploaded at sync time, parsed
    by the file-based connector (``accepts_file``) linked to the review's
    application. The file is never stored — it is parsed in-request and
    injected into the connector config as ``file_b64``."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Review is closed")

    pc = await _resolve_review_connector(project_id, review, plugin_id, db)
    cls = _resolve_connector_class(pc)
    if not getattr(cls, "accepts_file", False):
        raise HTTPException(
            status_code=400,
            detail="This connector does not accept a file upload.",
        )

    content = await read_tabular_upload(file, 5 * 1024 * 1024)

    import base64
    config = _connector_config(pc)
    config = {
        **config,
        "file_b64": base64.b64encode(content).decode(),
        "file_b64_name": file.filename or "",
    }
    return await _run_connector_import(project, review, pc, cls, config, db)


async def _run_connector_import(project, review, pc, cls, config, db):
    """Shared connector import: run sync(), match SI users, create review
    entries, purge disabled accounts, finalise the SyncJob. Returns the
    UI result summary."""
    project_id = project.id
    review_id = review.id

    # Track the sync via SyncJob so it shows up in the plugin's history modal.
    job = SyncJob(project_id=project_id, plugin_id=pc.id, status="running")
    db.add(job)
    await db.flush()

    try:
        sync_result = await cls().sync(config, pc.group_filters or [])
    except Exception as e:
        import logging
        logging.getLogger("access-backend").exception("Connector sync failed: %s", e)
        job.status = "error"
        # Store a short, sanitised marker in the audit trail (no hostnames / creds).
        job.error_message = (type(e).__name__)[:200]
        job.completed_at = datetime.now(timezone.utc)
        pc.last_sync_at = datetime.now(timezone.utc)
        pc.last_sync_status = "error"
        await db.commit()
        raise HTTPException(status_code=502, detail="Connector sync failed — check server logs")

    # Load SI users for email matching
    si_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    si_users = si_result.scalars().all()
    email_to_si: dict[str, str] = {u.email.lower(): u.id for u in si_users if u.email}
    # Keep handles by email so we can refresh their last_login_at from
    # the connector payload when they match a review user below.
    si_by_email: dict[str, SiUser] = {u.email.lower(): u for u in si_users if u.email}

    # Name-based fallback index (nom+prenom). Only UNAMBIGUOUS names are
    # usable: a name shared by several SI users is dropped so we never bind
    # a homonym to the wrong person.
    _name_counts: dict[str, int] = {}
    _name_first: dict[str, SiUser] = {}
    for u in si_users:
        k = _norm_name(u.nom, u.prenom)
        if not k:
            continue
        _name_counts[k] = _name_counts.get(k, 0) + 1
        _name_first.setdefault(k, u)
    name_to_si: dict[str, SiUser] = {k: u for k, u in _name_first.items() if _name_counts[k] == 1}

    # Load declared service accounts: if a connector user matches an
    # existing ServiceAccount (by identifier OR name), tag it as
    # "service" — overriding the connector's default "personnel".
    sa_result = await db.execute(select(ServiceAccount).where(ServiceAccount.project_id == project_id))
    sa_identifiers: set[str] = set()
    for sa in sa_result.scalars().all():
        if sa.identifier:
            sa_identifiers.add(sa.identifier.strip().lower())
        if sa.name:
            sa_identifiers.add(sa.name.strip().lower())

    # Existing entries — detect duplicates so we don't import the same
    # user twice into the same review
    existing_result = await db.execute(
        select(ReviewEntry).where(
            ReviewEntry.project_id == project_id,
            ReviewEntry.review_id == review_id,
        )
    )
    existing_entries = existing_result.scalars().all()
    existing_emails = {e.email_or_login.lower() for e in existing_entries if e.email_or_login}
    max_num = 0
    for e in existing_entries:
        try:
            n = int(re.sub(r"\D", "", e.id.replace(review_id + "-", "")) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    current_order = len(existing_entries)

    imported_ids: list[str] = []
    skipped_duplicates = 0
    matched = 0
    unmatched = 0
    removed_disabled = 0

    # Build a set of disabled emails from the connector so we can
    # purge review entries for accounts that are now disabled.
    disabled_emails: set[str] = set()
    for ur in sync_result.users:
        if (ur.type_compte or "").lower() == "desactive":
            e = (ur.email or "").strip().lower()
            if e:
                disabled_emails.add(e)

    # Remove existing entries whose account is now disabled in the
    # connector (imported before the filter was added, or disabled
    # since the last import).
    if disabled_emails:
        for entry in existing_entries:
            if (entry.email_or_login or "").strip().lower() in disabled_emails:
                await db.delete(entry)
                existing_emails.discard((entry.email_or_login or "").strip().lower())
                removed_disabled += 1

    # Index existing entries by email to backfill last_login_at on
    # re-imports (entries predating this column have last_login_at NULL).
    entry_by_email: dict[str, ReviewEntry] = {}
    for entry in existing_entries:
        k = (entry.email_or_login or "").strip().lower()
        if k:
            entry_by_email[k] = entry

    for ur in sync_result.users:
        # Skip disabled accounts — no point reviewing revoked access
        if (ur.type_compte or "").lower() == "desactive":
            continue
        email_key = (ur.email or "").strip().lower()
        if not email_key:
            continue

        # Resolve the SI user: email first, then unambiguous nom+prenom
        # (covers connectors whose reconstructed email differs from the
        # directory's real address but whose name matches).
        name_key = _norm_name(ur.nom, ur.prenom)
        # Always refresh the matched SiUser's last_login_at from the
        # connector payload, BEFORE the duplicate check. This way
        # re-running the import on an existing review refreshes the
        # last-login column even if all entries already exist.
        matched_su = si_by_email.get(email_key) or (name_to_si.get(name_key) if name_key else None)
        if matched_su is not None and ur.last_login_at is not None:
            matched_su.last_login_at = ur.last_login_at
            matched_su.updated_at = datetime.now(timezone.utc)
        # Same for the IdP account-enabled state (False is a valid value, so
        # guard on `is not None`, not truthiness).
        if matched_su is not None and ur.account_enabled is not None:
            matched_su.account_enabled = ur.account_enabled
            matched_su.updated_at = datetime.now(timezone.utc)

        # Also refresh last_login_at + account_enabled + names on the existing
        # review entry (covers entries that have no matching SiUser — orphans),
        # and backfill the SI binding when a name match now resolves it.
        existing_entry = entry_by_email.get(email_key)
        if existing_entry is not None:
            if ur.last_login_at is not None:
                existing_entry.last_login_at = ur.last_login_at
            if ur.account_enabled is not None:
                existing_entry.account_enabled = ur.account_enabled
            if ur.nom and not existing_entry.nom:
                existing_entry.nom = ur.nom
            if ur.prenom and not existing_entry.prenom:
                existing_entry.prenom = ur.prenom
            if matched_su is not None and not existing_entry.si_user_id:
                existing_entry.si_user_id = matched_su.id

        if email_key in existing_emails:
            skipped_duplicates += 1
            continue

        max_num += 1
        current_order += 1
        entry_id = f"{review_id}-E{max_num:03d}"

        si_user_id = matched_su.id if matched_su is not None else None
        if si_user_id:
            matched += 1
        else:
            unmatched += 1

        # Override type_compte if the identifier matches a declared
        # ServiceAccount — prevents the entry from being flagged as
        # an orphan "personnel" account when it's actually a tracked
        # service account.
        resolved_type = ur.type_compte or "personnel"
        if email_key in sa_identifiers:
            resolved_type = "service"

        db.add(ReviewEntry(
            project_id=project_id, review_id=review_id, id=entry_id,
            sort_order=current_order,
            type_compte=resolved_type,
            email_or_login=ur.email,
            nom=ur.nom or "",
            prenom=ur.prenom or "",
            roles=", ".join(ur.roles) if ur.roles else "",
            groups=", ".join(ur.groups) if ur.groups else "",
            si_user_id=si_user_id,
            decision="pending",
            last_login_at=ur.last_login_at,
            account_enabled=ur.account_enabled,
        ))
        imported_ids.append(entry_id)
        existing_emails.add(email_key)

    # Finalise the job record so it appears in the history modal
    job.status = "success" if not sync_result.errors else "partial"
    job.completed_at = datetime.now(timezone.utc)
    job.users_found = len(sync_result.users)
    # For review imports we don't create SiUsers, so users_created = 0;
    # users_updated + entries_created track what the UI actually cares about.
    job.users_created = 0
    job.users_updated = 0
    job.entries_created = len(imported_ids)
    # Cap error messages: the audit trail stores a short summary only.
    # Full exception traces go to the server log (done in the except block).
    if sync_result.errors:
        import logging
        logging.getLogger("access-backend").warning("Connector partial errors: %s", sync_result.errors)
    job.error_message = (f"{len(sync_result.errors)} connector error(s)" if sync_result.errors else "")[:2000]

    pc.last_sync_at = datetime.now(timezone.utc)
    pc.last_sync_status = job.status

    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "plugin_id": pc.id,
        "plugin_type": pc.plugin_type,
        "plugin_label": pc.label or pc.plugin_type,
        "imported": len(imported_ids),
        "matched": matched,
        "unmatched": unmatched,
        "skipped_duplicates": skipped_duplicates,
        "removed_disabled": removed_disabled,
        # Only expose a count — raw LDAP error strings may leak bind DNs.
        "connector_errors_count": len(sync_result.errors or []),
    }


_DECISION_VALUES = {"pending", "conforme", "non_conforme", "a_investiguer"}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$")


class ReviewEntryPatch(BaseModel):
    decision: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    notes: Optional[str] = None


def _clean_single_line(value: Optional[str], max_len: int = 255) -> str:
    """Strip CRLF/NUL, cap length. Returns empty string on None."""
    if value is None:
        return ""
    v = str(value).replace("\r", " ").replace("\n", " ").replace("\x00", "")
    return v[:max_len]


@router.patch("/reviews/{review_id}/entries/{entry_id}")
async def patch_entry(
    project_id: uuid.UUID,
    review_id: str,
    entry_id: str,
    body: ReviewEntryPatch,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a review entry decision. Auto-creates measure on non_conforme."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Review is closed")

    entry = await db.get(ReviewEntry, (project_id, review_id, entry_id))
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    old_decision = entry.decision

    if body.decision is not None:
        if body.decision not in _DECISION_VALUES:
            raise HTTPException(status_code=400, detail=f"Invalid decision (allowed: {sorted(_DECISION_VALUES)})")
        entry.decision = body.decision
    if body.decided_by is not None:
        entry.decided_by = _clean_single_line(body.decided_by)
    if body.decided_at is not None:
        if body.decided_at and not _DATE_RE.match(body.decided_at):
            raise HTTPException(status_code=400, detail="Invalid decided_at format (expected YYYY-MM-DD or ISO8601)")
        entry.decided_at = _clean_single_line(body.decided_at, max_len=40)
    if body.notes is not None:
        entry.notes = (body.notes or "").replace("\x00", "")[:2000]

    # Measure creation on non_conforme is now driven by the UI via the
    # unified ct_measure_modal (POST /measures). This endpoint only
    # updates the entry decision — no silent measure creation here.

    entry.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(entry)
    return _entry_to_dict(entry)


@router.post("/reviews/{review_id}/close")
async def close_review(project_id: uuid.UUID, review_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Close a review. All entries must have a decision."""
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Review already closed")

    entries_result = await db.execute(
        select(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id)
    )
    entries = entries_result.scalars().all()

    pending = [e for e in entries if e.decision == "pending"]
    if pending:
        raise HTTPException(status_code=400, detail=f"{len(pending)} entries still pending")

    review.status = "cloturee"
    review.closed_at = _today()
    review.closed_by = user.name or user.email if user else ""
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    entries_dicts = [_entry_to_dict(e) for e in entries]
    return _review_to_dict(review, entries_dicts)


@router.get("/reviews/{review_id}/export")
async def export_review(project_id: uuid.UUID, review_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Export a review as JSON for compliance evidence."""
    await get_project_or_404(project_id, user, db)
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    app = await db.get(Application, (project_id, review.application_id))

    entries_result = await db.execute(
        select(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id).order_by(ReviewEntry.sort_order)
    )
    entries = entries_result.scalars().all()

    # Enrich entries with SI user info
    si_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    si_map = {u.id: {"nom": u.nom, "prenom": u.prenom, "email": u.email, "fonction": u.fonction} for u in si_result.scalars().all()}

    export_entries = []
    for e in entries:
        d = _entry_to_dict(e)
        if e.si_user_id and e.si_user_id in si_map:
            d["si_user"] = si_map[e.si_user_id]
        export_entries.append(d)

    # Get related measures
    measures_result = await db.execute(select(Measure).where(Measure.project_id == project_id))
    entry_ids = {e.id for e in entries}
    related_measures = [
        {"id": m.id, "title": m.title, "statut": m.statut, "responsable": m.responsable, "echeance": m.echeance}
        for m in measures_result.scalars().all()
        if m.review_entry_id in entry_ids
    ]

    from fastapi.responses import JSONResponse
    export_data = {
        "review_id": review.id,
        "application": {"id": app.id, "nom": app.nom, "url": app.url} if app else {},
        "status": review.status,
        "started_at": review.started_at,
        "closed_at": review.closed_at,
        "closed_by": review.closed_by,
        "entries": export_entries,
        "measures": related_measures,
        "summary": {
            "total": len(entries),
            "conforme": sum(1 for e in entries if e.decision == "conforme"),
            "non_conforme": sum(1 for e in entries if e.decision == "non_conforme"),
        },
    }
    filename = f"review_{review.id}_{app.nom if app else 'export'}.json".replace(" ", "_")
    return JSONResponse(content=export_data, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.delete("/reviews/{review_id}", status_code=204)
async def delete_review(project_id: uuid.UUID, review_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    review = await db.get(Review, (project_id, review_id))
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.status != "en_cours":
        raise HTTPException(status_code=400, detail="Cannot delete closed review")
    await db.execute(
        select(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id)
    )
    from sqlalchemy import delete
    await db.execute(delete(ReviewEntry).where(ReviewEntry.project_id == project_id, ReviewEntry.review_id == review_id))
    await db.delete(review)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
