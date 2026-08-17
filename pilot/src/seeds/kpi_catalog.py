"""Idempotent seed of the built-in KPI catalogue.

Reads ``src/data/kpi_catalog.json`` and upserts each entry into
``kpi_definition`` + ``kpi_framework_mapping``. Designed to run on every
Pilot startup — it must be safe to re-run.

Upsert rules
------------
On INSERT (KPI not yet in DB) the full payload is written, including
``target`` / ``threshold_amber`` / ``threshold_red`` / ``active`` taken
from the catalogue.

On UPDATE (KPI already in DB) only the "immutable" fields are refreshed
(names, descriptions, category, unit, direction, source_type,
source_module, source_metric). The user-tunable knobs
(``target``, ``threshold_amber``, ``threshold_red``, ``active``) are
**preserved** so a CISO who lowered a target in the UI doesn't see it
reset every time Pilot restarts.

Mappings are simpler: for each KPI the existing rows in
``kpi_framework_mapping`` are deleted and the catalogue's mappings are
re-inserted. The catalogue is the source of truth for framework anchors.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import KpiDefinition, KpiFrameworkMapping, KpiTombstone

logger = logging.getLogger("pilot.seeds.kpi")

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "kpi_catalog.json"

# Fields refreshed on every seed run (definition shape — not user knobs).
_IMMUTABLE_FIELDS = (
    "name_fr",
    "name_en",
    "description_fr",
    "description_en",
    "category_primary",
    "unit",
    "direction",
    "source_type",
    "source_module",
    "source_metric",
)


def _load_catalog() -> dict[str, Any]:
    with _CATALOG_PATH.open(encoding="utf-8") as f:
        return json.load(f)


async def seed_kpi_catalog(db: AsyncSession) -> dict[str, int]:
    """Apply the catalogue. Returns counts for logging/tests."""
    catalog = _load_catalog()
    kpis = catalog.get("kpis", [])

    # Codes an admin deleted on purpose — never resurrect them.
    tombstoned = set(
        (await db.execute(select(KpiTombstone.code))).scalars().all()
    )

    inserted = 0
    updated = 0
    skipped = 0
    mappings_written = 0

    for entry in kpis:
        code = entry["code"]
        if code in tombstoned:
            skipped += 1
            continue
        existing = (
            await db.execute(
                select(KpiDefinition).where(KpiDefinition.code == code)
            )
        ).scalar_one_or_none()

        if existing is None:
            # Opt-in for auto KPIs: a CISO should explicitly enable the
            # ones they care about before the scheduler starts computing
            # them. External (manual / plugin) KPIs start active so the
            # user can immediately enter or push data.
            active_default = entry["source_type"] != "auto"
            kpi = KpiDefinition(
                code=code,
                name_fr=entry["name_fr"],
                name_en=entry["name_en"],
                description_fr=entry.get("description_fr"),
                description_en=entry.get("description_en"),
                category_primary=entry["category_primary"],
                unit=entry["unit"],
                direction=entry["direction"],
                source_type=entry["source_type"],
                source_module=entry.get("source_module"),
                source_metric=entry.get("source_metric"),
                target=entry.get("target"),
                threshold_amber=entry.get("threshold_amber"),
                threshold_red=entry.get("threshold_red"),
                active=active_default,
            )
            db.add(kpi)
            await db.flush()  # populate kpi.id for mappings below
            inserted += 1
        else:
            for field in _IMMUTABLE_FIELDS:
                setattr(existing, field, entry.get(field))
            kpi = existing
            updated += 1

        # Replace mappings for this KPI: delete existing, then insert fresh.
        await db.execute(
            delete(KpiFrameworkMapping).where(
                KpiFrameworkMapping.kpi_id == kpi.id
            )
        )
        for m in entry.get("mappings", []):
            db.add(
                KpiFrameworkMapping(
                    kpi_id=kpi.id,
                    framework_code=m["framework"],
                    ref_code=m["ref"],
                    ref_label_fr=m.get("label_fr"),
                    ref_label_en=m.get("label_en"),
                )
            )
            mappings_written += 1

    await db.commit()
    logger.info(
        "KPI catalogue seeded: %d inserted, %d updated, %d skipped (deleted), %d mappings",
        inserted,
        updated,
        skipped,
        mappings_written,
    )
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "mappings": mappings_written,
    }
