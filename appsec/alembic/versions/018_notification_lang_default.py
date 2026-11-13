"""A notification language nobody chose is English

Revision ID: 018_notification_lang_default
Revises: 017_redact_gitleaks_match
Create Date: 2026-11-12

`notification_prefs.lang` was created with French as its default. English is
the product default: a row written without a language now gets English. Rows
already stored keep the language they hold.
"""
from alembic import op
import sqlalchemy as sa

revision = "018_notification_lang_default"
down_revision = "017_redact_gitleaks_match"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("notification_prefs", "lang", server_default=sa.text("'en'"))


def downgrade() -> None:
    op.alter_column("notification_prefs", "lang", server_default=sa.text("'fr'"))
