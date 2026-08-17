"""drop projects.shared_with — project sharing removed

The column backed a binary share model: anyone listed in `shared_with` got
edit, delete AND re-share on the project, with no way to grant less (Risk and
Compliance store a per-entry `permissions[]` for exactly that reason). Rather
than add share levels, the concept is dropped: a project belongs to its owner,
and administrators see everything.

Downgrade recreates the column empty. The membership lists themselves are not
recoverable — nothing else in the schema records who a project was shared with,
so this migration is one-way as far as data goes. It was applied when no
deployment had a single non-empty list.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "009_drop_project_shared_with"
down_revision = "008_measure_cache_jsonb_idx"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("projects", "shared_with")


def downgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "shared_with",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
