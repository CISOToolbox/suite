"""Track WHEN an alert became KEV-listed, not just that it is.

Revision ID: 014_alerts_kev_listed_at
Revises: 013_digest_body_html
Create Date: 2026-08-16

Why
---
The vuln digest must distinguish "newly exploited" from "exploited for
years": a scope created today over vmware/fortinet keywords matches the
whole historical KEV backlog, and a blanket kev_listed exception in the
digest filter would email decades of old-but-exploited CVEs as if they
were this week's news. Recording the flip date lets the digest keep only
KEV additions that happened inside the send window.

Schema change
-------------
* Add ``alerts.kev_listed_at`` TIMESTAMPTZ NULL.

Backfill policy: existing kev_listed rows keep NULL — "listed since
before we started tracking" — which the digest treats as historical
(suppressed when the match itself is backfill/stale). New flips stamp
the timestamp from the scheduler.
"""
from alembic import op
import sqlalchemy as sa

revision = "014_alerts_kev_listed_at"
down_revision = "013_digest_body_html"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("kev_listed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("alerts", "kev_listed_at")
