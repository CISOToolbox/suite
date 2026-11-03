"""Gitleaks findings no longer carry the secret in their description

Revision ID: 017_redact_gitleaks_match
Revises: 016_sast_scanner
Create Date: 2026-11-02

The description of a gitleaks finding ended with ``Match: <matched text>``,
the secret included: every AppSec viewer read it, and it was sent to the AI
provider with the finding. The scanner now writes the match with the secret
replaced. The secret of an existing row is not known here, so its whole
``Match:`` part is replaced.

A measure raised from such a finding copied its description, and its owner
may have written more after it. Where the measure still holds the finding's
description, that copy is replaced by the redacted one and the rest of the
text stays. Otherwise only the ``Match:`` line is cut, up to the end of that
line: what follows stays, which keeps the owner's text but may keep the
further lines of a multi-line match (a private key).

The finding's identity (``secret_id``, a digest) is untouched: triage stays.
Not reversible: the removed text is not kept anywhere.
"""
from alembic import op

revision = "017_redact_gitleaks_match"
down_revision = "016_sast_scanner"
branch_labels = None
depends_on = None

_MARK = "chr(10) || 'Match: '"
_REDACTED = "chr(10) || 'Match: REDACTED'"


def _cut_to_end(col: str) -> str:
    """`col` with everything from its "Match:" line to the end replaced: in a
    finding the match is always last and may span several lines."""
    return f"substr({col}, 1, strpos({col}, {_MARK}) - 1) || {_REDACTED}"


def _cut_line(col: str) -> str:
    """`col` with its "Match:" line replaced, the lines after it kept."""
    rest = f"substr({col}, strpos({col}, {_MARK}) + 1)"
    return (f"substr({col}, 1, strpos({col}, {_MARK}) - 1) || {_REDACTED} || "
            f"CASE WHEN strpos({rest}, chr(10)) > 0 "
            f"THEN substr({rest}, strpos({rest}, chr(10))) ELSE '' END")


def upgrade() -> None:
    # Measures first: they are matched against the findings' descriptions as
    # they still are.
    op.execute(f"""
        UPDATE measures SET description = replace(measures.description, f.description, {_cut_to_end('f.description')})
          FROM findings f
         WHERE measures.finding_id = f.id AND f.scanner = 'gitleaks'
           AND strpos(f.description, {_MARK}) > 0
           AND strpos(measures.description, f.description) > 0
    """)
    op.execute(f"""
        UPDATE measures SET description = {_cut_line('description')}
         WHERE strpos(description, {_MARK}) > 0
           AND strpos(description, {_REDACTED}) = 0
           AND finding_id IN (SELECT id FROM findings WHERE scanner = 'gitleaks')
    """)
    op.execute(f"""
        UPDATE findings SET description = {_cut_to_end('description')}
         WHERE scanner = 'gitleaks' AND strpos(description, {_MARK}) > 0
    """)


def downgrade() -> None:
    # Nothing to restore: the secrets are gone, on purpose.
    pass
