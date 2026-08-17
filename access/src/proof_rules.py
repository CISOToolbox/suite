"""Compliance-proof evidence rule (FEAT-15 Lot 3).

A proof may only be marked validated when BOTH a date and a justification
(comment) are present. Otherwise it stays unchecked. This is the single
source of truth for the server-side invariant, applied on every write that
touches an SiUser (REST create/patch in routes/si_users.py and the blob
write path in routes/projects.py).
"""
from __future__ import annotations

# (boolean field, date field, justification field) per proof.
PROOFS: list[tuple[str, str, str]] = [
    ("politique_validee", "politique_date", "politique_justification"),
    ("mfa_active", "mfa_date", "mfa_justification"),
    ("sensibilisation", "sensibilisation_date", "sensibilisation_justification"),
    ("background_check", "background_check_date", "background_check_justification"),
    ("nda_signed", "nda_date", "nda_justification"),
]


def enforce_proof_evidence(su) -> None:
    """Coerce any validated proof without a date AND a justification back to
    unchecked. Mutates the SiUser-like object in place."""
    for bool_f, date_f, just_f in PROOFS:
        if getattr(su, bool_f, False):
            date_ok = bool((getattr(su, date_f, "") or "").strip())
            just_ok = bool((getattr(su, just_f, "") or "").strip())
            if not (date_ok and just_ok):
                setattr(su, bool_f, False)
