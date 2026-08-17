"""Baseline: users, app_settings, applications, scan_jobs, findings, measures, sbom_entries

Revision ID: 001_baseline
Revises:
Create Date: 2026-04-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), unique=True, nullable=False),
        sa.Column("name", sa.String(255), server_default=""),
        sa.Column("picture", sa.String(500), server_default=""),
        sa.Column("provider", sa.String(50), server_default=""),
        sa.Column("provider_id", sa.String(255), server_default=""),
        sa.Column("role", sa.String(20), server_default="user"),
        sa.Column("ai_enabled", sa.String(5), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text, server_default=""),
    )
    op.create_table(
        "applications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("repo_url", sa.String(500), server_default=""),
        sa.Column("repo_branch", sa.String(100), server_default="main"),
        sa.Column("repo_token_encrypted", sa.Text, server_default=""),
        sa.Column("docker_images", postgresql.JSONB, server_default="[]"),
        sa.Column("scan_frequency_hours", sa.Integer, server_default="24"),
        sa.Column("enabled_scanners", postgresql.JSONB, server_default='["trivy_fs","gitleaks","semgrep","trivy_image"]'),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("criticality", sa.String(20), server_default="medium"),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_commit", sa.String(64), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("diff", postgresql.JSONB, server_default="{}"),
        sa.Column("error", sa.Text, server_default=""),
        sa.Column("triggered_by", sa.String(255), server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner", sa.String(100), nullable=False),
        sa.Column("type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("target", sa.String(500), server_default=""),
        sa.Column("evidence", postgresql.JSONB, server_default="{}"),
        sa.Column("status", sa.String(30), server_default="new"),
        sa.Column("dedup_key", sa.String(500), unique=True, nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=True),
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("triaged_by", sa.String(255), nullable=True),
        sa.Column("triage_notes", sa.Text, server_default=""),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_findings_dedup_key", "findings", ["dedup_key"])
    op.create_index("ix_findings_status_severity", "findings", ["status", "severity"])
    op.create_index("ix_findings_scanner", "findings", ["scanner"])
    op.create_index("ix_findings_app", "findings", ["application_id"])
    op.create_index("ix_findings_created", "findings", ["created_at"])

    op.create_table(
        "measures",
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), unique=True, nullable=True),
        sa.Column("sort_order", sa.Integer, server_default="0"),
        sa.Column("title", sa.String(500), server_default=""),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("statut", sa.String(30), server_default="a_faire"),
        sa.Column("responsable", sa.String(255), server_default=""),
        sa.Column("echeance", sa.String(50), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "sbom_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100), server_default=""),
        sa.Column("ecosystem", sa.String(50), server_default=""),
        sa.Column("license", sa.String(100), server_default=""),
        sa.Column("direct", sa.Boolean, server_default="true"),
        sa.Column("parent_packages", postgresql.JSONB, server_default="[]"),
        sa.Column("depends_on", postgresql.JSONB, server_default="[]"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_sbom_app_pkg", "sbom_entries", ["application_id", "package_name", "version"], unique=True)


def downgrade() -> None:
    op.drop_table("sbom_entries")
    op.drop_table("measures")
    op.drop_table("findings")
    op.drop_table("scan_jobs")
    op.drop_table("applications")
    op.drop_table("app_settings")
    op.drop_table("users")
