import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from routes.si_users import _validate_contract_end


class TestContractEndValidation:
    """FEAT-15 Lot 1: date_fin_contrat is required for every type_compte
    except 'salarie'. The helper returns the stripped value or raises 422."""

    def test_salarie_without_date_ok(self):
        assert _validate_contract_end("salarie", "") == ""

    def test_salarie_with_date_ok(self):
        assert _validate_contract_end("salarie", "2026-12-31") == "2026-12-31"

    def test_prestataire_without_date_rejected(self):
        with pytest.raises(HTTPException) as exc:
            _validate_contract_end("prestataire", "")
        assert exc.value.status_code == 422

    def test_stagiaire_whitespace_only_rejected(self):
        """Whitespace must not satisfy the requirement."""
        with pytest.raises(HTTPException) as exc:
            _validate_contract_end("stagiaire", "   ")
        assert exc.value.status_code == 422

    def test_alternant_with_date_ok(self):
        assert _validate_contract_end("alternant", "2026-09-01") == "2026-09-01"

    def test_value_is_stripped(self):
        assert _validate_contract_end("prestataire", "  2026-06-30  ") == "2026-06-30"
