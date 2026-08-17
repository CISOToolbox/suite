"""Audit backend — SQLAlchemy models.

Blob-first model (phase 1): each stored audit is one Project row whose
`data` JSONB carries the full frontend `D` object (meta, findings per
control, planning, doc review…). The frontend file format and this blob
are identical, which is what makes the frontend-file import trivial.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Auth & Settings ────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(500), nullable=True)
    provider = Column(String(50), nullable=False)
    provider_id = Column(String(255), nullable=False)
    role = Column(String(50), default="user", server_default=text("'user'"))
    ai_enabled = Column(String(5), default="false", server_default=text("'false'"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False, default="")


# ── Stored audits ──────────────────────────────────────────────

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    name = Column(String(255), nullable=False, default="")
    organization = Column(String(255), nullable=True)
    audit_date = Column(String(50), nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    data = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    # FEAT-33 — bumped ONLY by server-initiated writers (Pilot write-back,
    # restore, schedulers). Guards the blob PUT against stale-tab overwrite.
    server_rev = Column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    measures = relationship("Measure", back_populates="project", cascade="all, delete-orphan", order_by="Measure.sort_order")



# ── Corrective actions (mesures) ───────────────────────────────
# One measure per remediation action, optionally linked to the audited
# control (control_id = the finding key, e.g. "A.8.24") that raised it.

class Measure(Base):
    __tablename__ = "measures"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    title = Column(String(500), nullable=False, default="")
    description = Column(Text, nullable=True, default="")
    statut = Column(String(50), nullable=False, default="a_faire")
    responsable = Column(String(255), nullable=True, default="")
    echeance = Column(String(20), nullable=True, default="")
    control_id = Column(String(50), nullable=True, default="")

    progress_log = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="measures")

    __table_args__ = (
        Index("ix_audit_measures_project_statut", "project_id", "statut"),
    )



# ── Append-only server-side write journal (FEAT-30 P1.6) ──────────────
# Created by Base.metadata.create_all at startup (no migration needed for
# a new table). Written via src.audit.log_write — see audit_common master.
class AuditLog(Base):
    """Append-only: never UPDATEd/DELETEd (retention purge excepted).
    entity_type/entity_id tie a line to the exact restorable object."""
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    logged_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"), index=True)
    user_email = Column(String(255), nullable=False, default="")
    user_name = Column(String(255), nullable=False, default="")
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(500), nullable=False, default="")
    entity_type = Column(String(50), nullable=False, default="")
    entity_id = Column(String(64), nullable=False, default="", index=True)
    details = Column(Text, nullable=False, default="")
    ip_address = Column(String(64), nullable=False, default="")
