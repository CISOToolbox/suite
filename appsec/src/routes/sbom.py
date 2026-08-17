from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.csv_common import csv_safe_row
from src.database import get_db
from src.models import Application, Finding, SBOMEntry, User
from src.schemas import SBOMResponse

router = APIRouter(prefix="/api/sbom", tags=["sbom"])


@router.get("")
async def list_sbom(
    app_id: uuid.UUID | None = Query(None),
    ecosystem: str | None = Query(None),
    q: str | None = Query(None),
    vulnerable_only: bool = Query(False),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(SBOMEntry).order_by(SBOMEntry.package_name)
    if app_id:
        query = query.where(SBOMEntry.application_id == app_id)
    if ecosystem:
        query = query.where(SBOMEntry.ecosystem == ecosystem)
    if q:
        query = query.where(SBOMEntry.package_name.ilike(f"%{q}%"))

    total_q = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_q.scalar() or 0

    result = await db.execute(query.offset(offset).limit(limit))
    entries = result.scalars().all()

    app_ids = list(set(e.application_id for e in entries))
    app_names = {}
    if app_ids:
        apps_q = await db.execute(select(Application.id, Application.name).where(Application.id.in_(app_ids)))
        app_names = {row[0]: row[1] for row in apps_q}

    # Build pkg→[{cve_id, status}] map from ALL CVE findings regardless
    # of triage status. The SBOM is an inventory of known vulns — even
    # false_positive / fixed CVEs are shown (with their status) so the
    # operator sees the full picture. The "vulnerable_only" filter uses
    # this map; the frontend can grey out triaged CVEs if desired.
    vuln_map: dict[str, list[dict]] = {}
    if entries:
        vuln_q = await db.execute(
            select(Finding.target, Finding.cve_id, Finding.status)
            .where(Finding.type == "cve")
        )
        for target, cve_id, status in vuln_q:
            key = (target or "").lower()
            if cve_id:
                vuln_map.setdefault(key, []).append({"id": cve_id, "status": status})

    # Collect distinct ecosystems from full (unfiltered) SBOM for dynamic dropdown.
    eco_q = await db.execute(
        select(SBOMEntry.ecosystem).distinct().order_by(SBOMEntry.ecosystem)
    )
    ecosystems = [r[0] for r in eco_q if r[0]]

    # Aggregate by (package_name, version) — merge app names + keep
    # one representative entry for ecosystem/license/direct/parents.
    aggregated: dict[str, dict] = {}  # key = "pkg@ver"
    for e in entries:
        pkg_key = f"{e.package_name}@{e.version}"
        agg_key = pkg_key.lower()
        app_name = app_names.get(e.application_id, "")
        if agg_key not in aggregated:
            d = SBOMResponse.model_validate(e).model_dump()
            d["application_names"] = [app_name] if app_name else []
            d["application_name"] = app_name  # backwards compat
            aggregated[agg_key] = d
        else:
            existing = aggregated[agg_key]
            if app_name and app_name not in existing["application_names"]:
                existing["application_names"].append(app_name)
            # Keep the broadest info: if any entry is direct, mark as direct
            if e.direct:
                existing["direct"] = True

    # Enrich with CVE data
    items = []
    for agg_key, d in sorted(aggregated.items(), key=lambda x: x[0]):
        pkg_key = f"{d['package_name']}@{d['version']}".lower()
        matched: list[dict] = []
        for vk, entries_list in vuln_map.items():
            if pkg_key in vk or vk in pkg_key:
                matched.extend(entries_list)
        by_id: dict[str, str] = {}
        for m in matched:
            cid = m["id"]
            if cid not in by_id or m["status"] in ("new", "to_fix"):
                by_id[cid] = m["status"]
        d["vulnerable"] = len(by_id) > 0
        d["cve_ids"] = sorted(by_id.keys())
        d["cve_details"] = [{"id": k, "status": v} for k, v in sorted(by_id.items())]
        d["application_name"] = ", ".join(d["application_names"])  # display string
        if vulnerable_only and not d["vulnerable"]:
            continue
        items.append(d)

    return {
        "items": items,
        "total": len(items),
        "ecosystems": ecosystems,
    }


@router.get("/export")
async def export_sbom(
    app_id: uuid.UUID | None = Query(None),
    format: str = Query("csv"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(SBOMEntry).order_by(SBOMEntry.package_name)
    if app_id:
        query = query.where(SBOMEntry.application_id == app_id)

    result = await db.execute(query)
    entries = result.scalars().all()

    app_ids = list(set(e.application_id for e in entries))
    app_names = {}
    if app_ids:
        apps_q = await db.execute(select(Application.id, Application.name).where(Application.id.in_(app_ids)))
        app_names = {row[0]: row[1] for row in apps_q}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Application", "Package", "Version", "Ecosystem", "License", "Direct"])
    for e in entries:
        # csv_safe_row neutralises leading =/+/-/@ so a package name or
        # license string cannot become a formula in Excel/LibreOffice.
        writer.writerow(csv_safe_row([
            app_names.get(e.application_id, ""),
            e.package_name, e.version, e.ecosystem, e.license,
            "yes" if e.direct else "no",
        ]))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sbom.csv"},
    )
