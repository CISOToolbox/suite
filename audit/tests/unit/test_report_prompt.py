"""Unit tests for the audit report prompt.

`_build_report_prompt()` composes, server-side, the prompt of the AI audit
report from structured figures: the frontend never sends a prompt, the
client and the auditor are never named, and the report follows the language
of the interface. The request model bounds what the browser may send.
"""
import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

from routes.ai import AuditReportRequest, _build_report_prompt  # noqa: E402


def _body(**kw):
    base = {
        "lang": "fr", "ref": "AUD-2026-001", "date": "2026-09-30",
        "scope": "Siège\net plateforme", "hds": "oui",
        "stats": {"total": 117, "audited": 100, "c": 60, "ncmaj": 2, "ncmin": 5,
                  "ps": 10, "pp": 8, "na": 15, "score": 72, "grade": "B"},
        "domains": [{"label": "A.5 Organisationnels", "score": 70, "audited": 30, "total": 37}],
        "nonconformities": [{"status": "ncmaj", "control_id": "A.5.19",
                             "control_title": "Relations fournisseurs",
                             "finding": "Pas de clause", "cause": "", "action": "Ajouter"}],
    }
    base.update(kw)
    return AuditReportRequest(**base)


def test_the_report_follows_the_interface_language():
    sys_fr, user_fr = _build_report_prompt(_body(lang="fr"))
    sys_en, user_en = _build_report_prompt(_body(lang="en"))
    assert "en français" in sys_fr and "NON-CONFORMITÉS" in user_fr
    assert "in English" in sys_en and "NON-CONFORMITIES" in user_en


def test_client_and_auditor_are_never_named():
    system, user = _build_report_prompt(_body())
    assert "[CLIENT]" in user and "[AUDITOR]" in user
    # The model has no field that could carry them.
    fields = set(AuditReportRequest.model_fields)
    assert not fields & {"name", "client", "auditor", "organization", "organisation"}
    # An extra field sent by a client is ignored, never forwarded.
    extra = AuditReportRequest(**{**_body().model_dump(), "client": "MedSecure SA"})
    assert "MedSecure SA" not in "".join(_build_report_prompt(extra))


def test_figures_and_nonconformities_are_rendered():
    _, user = _build_report_prompt(_body())
    assert "Score: 72% (Niveau B)" in user
    assert "- A.5 Organisationnels: 70% (30/37 audités)" in user
    assert "- [NCMAJ] A.5.19 Relations fournisseurs" in user
    assert "Constat: Pas de clause" in user and "Action: Ajouter" in user
    assert "Cause:" not in user              # empty fields are omitted
    assert "Siège et plateforme" in user     # single-line fields


def test_audit_data_is_framed_as_untrusted():
    _, user = _build_report_prompt(_body())
    opened, closed = user.index("BEGIN UNTRUSTED DATA"), user.index("END UNTRUSTED DATA")
    assert opened < user.index("A.5.19") < closed
    assert opened < user.index("Siège") < closed


def test_hds_is_worded_in_the_report_language():
    _, user = _build_report_prompt(_body(lang="en", hds="oui"))
    assert "HDS: yes" in user


def test_the_request_is_bounded_in_total():
    long_nc = {"status": "ncmin", "control_id": "A.5.1", "finding": "x" * 2000,
               "cause": "y" * 2000, "action": "z" * 2000}
    with pytest.raises(ValidationError):
        _body(nonconformities=[long_nc] * 40)


def test_an_empty_nonconformity_list_says_so():
    _, user = _build_report_prompt(_body(nonconformities=[]))
    assert "Aucune non-conformité identifiée." in user


@pytest.mark.parametrize("bad", [
    {"lang": "de"},
    {"nonconformities": [{"status": "c", "control_id": "A.5.1"}]},
    {"stats": {"score": 101}},
    {"stats": {"total": -1}},
    {"scope": "x" * 2001},
    {"domains": [{"label": "d"}] * 61},
])
def test_the_request_is_bounded(bad):
    with pytest.raises(ValidationError):
        _body(**bad)
