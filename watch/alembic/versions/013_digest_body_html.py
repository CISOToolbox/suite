"""Persist sent digest body for replay/audit.

Revision ID: 013_digest_body_html
Revises: 012_free_prompt_threat_digest
Create Date: 2026-05-14

Why
---
The frontend now exposes:
  * an admin "force send" button per scope (vuln / threat),
  * a digest history page that can re-open the exact HTML email body
    that was sent.

Both features need the email body to be persisted alongside the
``digest_runs`` row instead of being thrown away after the SMTP send.
A NULL/empty ``body_html`` is acceptable for legacy rows (pre-013) and
for terminal statuses where no body was produced (skipped_empty,
some failures before render).

Schema change
-------------
* Add ``digest_runs.body_html`` TEXT NOT NULL DEFAULT ''.
"""
from alembic import op
import sqlalchemy as sa


revision = "013_digest_body_html"
down_revision = "012_free_prompt_threat_digest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "digest_runs",
        sa.Column(
            "body_html",
            sa.Text(),
            nullable=False,
            server_default=sa.text("''"),
        ),
    )


def downgrade() -> None:
    op.drop_column("digest_runs", "body_html")
