"""Free-prompt threat digest (M22): drop ThreatTopic / ThreatMatch,
rename Scope.threat_llm_context → threat_prompt, add threat_search_window_days.

Revision ID: 012_free_prompt_threat_digest
Revises: 011_digest_runs_partial_unique
Create Date: 2026-05-14

Background
----------
The threat-digest section of Watch used to rely on a keyword-matching
pipeline (ThreatTopic with curated themes + extra_keywords → matcher →
LLM relevance scorer). Empirical comparison against the equivalent
hand-written claude.ai prompt showed Watch's output was substantially
less useful, primarily because:

  1. Source corpus is too narrow (8 feeds vs. dozens consulted by
     Claude with web search).
  2. Long-tail product coverage is impossible (niche business software,
     vendor SaaS) — no public feed exists for these.
  3. The user already has to declare context in pieces (topics +
     keywords + targets) when one paragraph of natural-language
     context would suffice.

Replacement design
------------------
The scope keeps its vuln pipeline (deterministic CPE→CVE matching).
The threat section now stores a single free-form prompt and a search
window; at digest time the scope's prompt is sent to Claude with the
Anthropic ``web_search`` tool enabled, and Claude produces a synthesized
brief covering the requested window. Citations are appended.

Schema change
-------------
* Drop ``threat_matches`` (cascade) and ``threat_topics``.
* Rename ``scopes.threat_llm_context`` → ``scopes.threat_prompt``.
* Add ``scopes.threat_search_window_days`` INT NOT NULL DEFAULT 7.
"""
from alembic import op
import sqlalchemy as sa


revision = "012_free_prompt_threat_digest"
down_revision = "011_digest_runs_partial_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ThreatMatch references threat_topics + alerts; drop it first.
    op.execute("DROP TABLE IF EXISTS threat_matches CASCADE")
    op.execute("DROP TABLE IF EXISTS threat_topics CASCADE")

    # Rename context → prompt for semantic clarity. Existing rows keep
    # their content (the field was free-text already).
    op.alter_column(
        "scopes",
        "threat_llm_context",
        new_column_name="threat_prompt",
        existing_type=sa.Text(),
        existing_nullable=False,
        existing_server_default=sa.text("''"),
    )

    # New: configurable lookback window for the web_search-driven brief.
    # Default 7 days matches the default ``threat_digest_frequency`` of
    # ``weekly`` so first-time scopes get a full week's view without
    # tuning.
    op.add_column(
        "scopes",
        sa.Column(
            "threat_search_window_days",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("7"),
        ),
    )


def downgrade() -> None:
    # The old keyword pipeline is gone for good; the downgrade is best-
    # effort to keep the schema reversible, but no data can be restored
    # (threat_topics / threat_matches are dropped permanently).
    op.drop_column("scopes", "threat_search_window_days")
    op.alter_column(
        "scopes",
        "threat_prompt",
        new_column_name="threat_llm_context",
        existing_type=sa.Text(),
        existing_nullable=False,
        existing_server_default=sa.text("''"),
    )

    # Recreate empty threat_topics / threat_matches shells so the older
    # codepath does not crash if it tries to query them. Data is NOT
    # restored.
    op.create_table(
        "threat_topics",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("scope_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("theme_id", sa.String(100), nullable=True),
        sa.Column("extra_keywords", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "threat_matches",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("topic_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("matched_terms", sa.JSON(), nullable=True),
        sa.Column("relevance_score", sa.Integer(), nullable=True),
        sa.Column("relevance_reason", sa.Text(), nullable=True),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
    )
