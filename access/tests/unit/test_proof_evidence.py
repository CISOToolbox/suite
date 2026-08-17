import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from proof_rules import enforce_proof_evidence


class _Obj:
    def __init__(self, **kw):
        # default every known proof field so getattr never misses
        for b, d, j in __import__("proof_rules").PROOFS:
            setattr(self, b, False); setattr(self, d, ""); setattr(self, j, "")
        self.__dict__.update(kw)


class TestEnforceProofEvidence:
    def test_checked_without_evidence_is_unchecked(self):
        o = _Obj(politique_validee=True, politique_date="", politique_justification="")
        enforce_proof_evidence(o)
        assert o.politique_validee is False

    def test_checked_missing_comment_is_unchecked(self):
        o = _Obj(mfa_active=True, mfa_date="2026-01-01", mfa_justification="")
        enforce_proof_evidence(o)
        assert o.mfa_active is False

    def test_checked_missing_date_is_unchecked(self):
        o = _Obj(nda_signed=True, nda_date="   ", nda_justification="signed")
        enforce_proof_evidence(o)
        assert o.nda_signed is False

    def test_checked_with_full_evidence_stays(self):
        o = _Obj(sensibilisation=True, sensibilisation_date="2026-02-02",
                 sensibilisation_justification="session done")
        enforce_proof_evidence(o)
        assert o.sensibilisation is True

    def test_unchecked_untouched(self):
        o = _Obj(background_check=False)
        enforce_proof_evidence(o)
        assert o.background_check is False
