"""Dissociate threat digest from vuln digest + LLM relevance scoring.

Revision ID: 010_threat_split
Revises: 009_threat_topics
Create Date: 2026-05-14

Three orthogonal additions, kept in one revision so the deploy can roll
them back as a unit if the redesign is reverted.

A) ``scopes`` gains an independent threat-digest schedule + a free-text
   LLM context. The existing ``digest_*`` columns continue to drive the
   *vulnerability* digest (unchanged semantics). The new ``threat_digest_*``
   columns drive the *threat* digest, which can run on a daily-or-weekly
   cadence independently of the vuln digest. ``threat_llm_context`` holds
   the operator's free-text description of their environment, used by
   the LLM scorer (M17) to assess relevance per alert.

B) ``threat_topics`` gains ``theme_id`` (a stable string referring to
   the in-code catalogue in ``src/threat_themes.py`` — not a FK so the
   catalogue can evolve without DB migrations) and ``extra_keywords``
   (JSONB list — preserves the legacy free-text keywords for backwards
   compat / migration period). The old ``keywords`` column is kept for
   the M20 soft migration window and removed in a later revision.

C) ``threat_matches`` gains the LLM relevance fields. ``relevance_score``
   stays NULL until the scorer has processed the row; the scorer only
   ever writes rows where it is NULL (idempotence rule #1 from the
   design discussion). ``relevance_context_hash`` records the sha256 of
   the scope.threat_llm_context that was *in effect at scoring time* —
   used for transparency ("scoré avec contexte précédent" in the UI)
   but never to auto-invalidate.

D) ``digest_runs`` gains a ``kind`` column ("vuln" | "threat") so the
   per-day idempotence key becomes (user_email, scope_id, kind,
   calendar_date). Both digest types can fire on the same day without
   colliding on the unique constraint.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "010_threat_split"
down_revision = "009_threat_topics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── A) Scope: independent threat digest schedule + LLM context ────
    op.add_column("scopes", sa.Column(
        "threat_digest_enabled", sa.Boolean(),
        nullable=False, server_default=sa.text("true"),
    ))
    # frequency: "daily" | "weekly" | "off"
    op.add_column("scopes", sa.Column(
        "threat_digest_frequency", sa.String(20),
        nullable=False, server_default=sa.text("'weekly'"),
    ))
    # 0=Monday..6=Sunday, only used when frequency='weekly'
    op.add_column("scopes", sa.Column(
        "threat_digest_weekday", sa.Integer(),
        nullable=False, server_default=sa.text("0"),
    ))
    op.add_column("scopes", sa.Column(
        "threat_digest_hour", sa.Integer(),
        nullable=False, server_default=sa.text("8"),
    ))
    op.add_column("scopes", sa.Column(
        "threat_digest_minute", sa.Integer(),
        nullable=False, server_default=sa.text("0"),
    ))
    op.add_column("scopes", sa.Column(
        "threat_digest_timezone", sa.String(64),
        nullable=False, server_default=sa.text("'Europe/Paris'"),
    ))
    # Free-text context fed to the LLM relevance scorer (M17).
    # Empty string = scorer is off for this scope (deterministic-only mode).
    op.add_column("scopes", sa.Column(
        "threat_llm_context", sa.Text(),
        nullable=False, server_default=sa.text("''"),
    ))

    # ── B) ThreatTopic: theme_id + extra_keywords (compat) ────────────
    # theme_id references the in-code THREAT_THEMES catalogue.
    # NULL = "legacy / custom topic" → only extra_keywords are matched.
    op.add_column("threat_topics", sa.Column(
        "theme_id", sa.String(100), nullable=True,
    ))
    op.add_column("threat_topics", sa.Column(
        "extra_keywords", postgresql.JSONB,
        nullable=False, server_default=sa.text("'[]'::jsonb"),
    ))
    op.create_index(
        "ix_threat_topics_theme_id", "threat_topics", ["theme_id"],
    )

    # M20 soft migration — copy existing keywords into extra_keywords so
    # legacy topics keep firing the day after deploy. The old ``keywords``
    # column is left in place for one release; a follow-up migration will
    # drop it once the UI has converted all live topics.
    op.execute(
        "UPDATE threat_topics SET extra_keywords = keywords "
        "WHERE jsonb_typeof(keywords) = 'array' "
        "  AND jsonb_array_length(keywords) > 0 "
        "  AND jsonb_array_length(extra_keywords) = 0"
    )

    # ── C) ThreatMatch: LLM relevance fields ──────────────────────────
    op.add_column("threat_matches", sa.Column(
        "relevance_score", sa.SmallInteger(), nullable=True,
    ))
    op.add_column("threat_matches", sa.Column(
        "relevance_reason", sa.Text(),
        nullable=False, server_default=sa.text("''"),
    ))
    op.add_column("threat_matches", sa.Column(
        "relevance_scored_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("threat_matches", sa.Column(
        "relevance_model", sa.String(100),
        nullable=False, server_default=sa.text("''"),
    ))
    op.add_column("threat_matches", sa.Column(
        "relevance_context_hash", sa.String(64),
        nullable=False, server_default=sa.text("''"),
    ))
    # Partial index speeds up "rows still to score" queries the scorer
    # runs on every tick.
    op.create_index(
        "ix_threat_matches_unscored", "threat_matches",
        ["scope_id", "matched_at"],
        postgresql_where=sa.text("relevance_score IS NULL"),
    )
    # Surfaces the top-N by relevance for the threat digest render.
    op.create_index(
        "ix_threat_matches_relevance",
        "threat_matches", ["scope_id", "relevance_score"],
    )

    # ── D) DigestRun: kind discriminator ──────────────────────────────
    # Add column nullable first, backfill existing rows to "vuln" (the
    # only kind that existed before this migration), then set NOT NULL.
    op.add_column("digest_runs", sa.Column(
        "kind", sa.String(10), nullable=True,
    ))
    op.execute("UPDATE digest_runs SET kind = 'vuln' WHERE kind IS NULL")
    op.alter_column("digest_runs", "kind", nullable=False,
                    server_default=sa.text("'vuln'"))

    # Replace the (user_email, scope_id, calendar_date) unique with one
    # that includes kind. Postgres lets us drop+create in a single tx.
    op.drop_constraint("uq_digest_user_scope_date", "digest_runs", type_="unique")
    op.create_unique_constraint(
        "uq_digest_user_scope_kind_date",
        "digest_runs",
        ["user_email", "scope_id", "kind", "calendar_date"],
    )


def downgrade() -> None:
    # D)
    op.drop_constraint("uq_digest_user_scope_kind_date", "digest_runs", type_="unique")
    op.create_unique_constraint(
        "uq_digest_user_scope_date",
        "digest_runs",
        ["user_email", "scope_id", "calendar_date"],
    )
    op.drop_column("digest_runs", "kind")

    # C)
    op.drop_index("ix_threat_matches_relevance", table_name="threat_matches")
    op.drop_index("ix_threat_matches_unscored", table_name="threat_matches")
    op.drop_column("threat_matches", "relevance_context_hash")
    op.drop_column("threat_matches", "relevance_model")
    op.drop_column("threat_matches", "relevance_scored_at")
    op.drop_column("threat_matches", "relevance_reason")
    op.drop_column("threat_matches", "relevance_score")

    # B)
    op.drop_index("ix_threat_topics_theme_id", table_name="threat_topics")
    op.drop_column("threat_topics", "extra_keywords")
    op.drop_column("threat_topics", "theme_id")

    # A)
    op.drop_column("scopes", "threat_llm_context")
    op.drop_column("scopes", "threat_digest_timezone")
    op.drop_column("scopes", "threat_digest_minute")
    op.drop_column("scopes", "threat_digest_hour")
    op.drop_column("scopes", "threat_digest_weekday")
    op.drop_column("scopes", "threat_digest_frequency")
    op.drop_column("scopes", "threat_digest_enabled")
