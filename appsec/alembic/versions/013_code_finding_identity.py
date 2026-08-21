"""Code findings are keyed on the matched code, not on file:line — clean slate.

Revision ID: 013_code_finding_identity
Revises: 012_findings_notifications
Create Date: 2026-08-21

Semgrep and gitleaks findings used to be identified by ``file:line``. Adding
or removing a line ABOVE a finding changed its key, so the finding lost its
identity: a false-positive verdict stopped applying and the same issue came
back as new on the next scan. Triage evaporated every time the file was
touched. Identity is now ``file + rule + digest of the matched code``.

Rows written under the old scheme can never match the new keys. Left alone
they would not be re-categorised — nothing marks an unseen finding as fixed
— they would simply sit there for ever, duplicating every finding the next
scan re-creates. So they are deleted.

**This deletes remediation work, deliberately and on an explicit decision.**
``Finding.measure`` cascades (``all, delete-orphan``), so the measures raised
from these findings go too, and with them the corresponding actions in
Pilot's consolidated plan — including any already attached to a project. The
alternative (keeping a legacy-key fallback that re-keys rows in place, losing
nothing) was considered and rejected in favour of not carrying compatibility
code.

After deploying: run a scan per application to repopulate, then a Pilot sync
so its measure cache drops what no longer exists. SCA findings (trivy) are
untouched — their key carries the package and the CVE, never a line.
"""
from alembic import op

revision = "013_code_finding_identity"
down_revision = "012_findings_notifications"
branch_labels = None
depends_on = None

_CODE_SCANNERS = ("semgrep", "gitleaks")


def upgrade() -> None:
    # measures.finding_id carries ON DELETE CASCADE in the database (verified:
    # confdeltype = 'c'), not just the ORM `cascade="all, delete-orphan"` —
    # which a raw DELETE would bypass. So measures anchored on a code finding
    # go with it, as intended.
    op.execute(
        "DELETE FROM findings WHERE scanner IN "
        f"({', '.join(repr(s) for s in _CODE_SCANNERS)})"
    )
    # A bulk triage measure lists every finding it covers in `finding_ids`
    # (JSONB) while being anchored on one of them. If its anchor was an SCA
    # finding it survives the delete above, still listing code findings that
    # no longer exist — the UI would count coverage against ghosts. Drop the
    # ids that no longer resolve.
    op.execute("""
        UPDATE measures m
           SET finding_ids = COALESCE((
                 SELECT jsonb_agg(x)
                   FROM jsonb_array_elements_text(m.finding_ids) AS x
                  WHERE EXISTS (SELECT 1 FROM findings f WHERE f.id::text = x)
               ), '[]'::jsonb)
         WHERE m.finding_ids <> '[]'::jsonb
    """)


def downgrade() -> None:
    # Nothing to restore: the rows are gone and their keys are not
    # reconstructible. A scan repopulates the findings, not the triage.
    pass
