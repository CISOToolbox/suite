"""Semgrep severity: the rule level tempered by likelihood and confidence.

A rule with confidence LOW and a likelihood no better than MEDIUM is a lead,
not a defect: it rates low whatever its level. Everything else keeps the
level mapping (ERROR → high, WARNING → medium, INFO → low)."""
import pytest

from src.scanners import sast_finding, sast_severity


def extra(severity, likelihood=None, confidence=None):
    meta = {}
    if likelihood is not None:
        meta["likelihood"] = likelihood
    if confidence is not None:
        meta["confidence"] = confidence
    return {"severity": severity, "metadata": meta, "lines": "x = eval(y)"}


@pytest.mark.parametrize("severity,likelihood,confidence,expected", [
    ("ERROR", "MEDIUM", "LOW", "low"),        # the requested case
    ("WARNING", "MEDIUM", "LOW", "low"),
    ("ERROR", "LOW", "LOW", "low"),
    ("INFO", "MEDIUM", "LOW", "low"),
    ("ERROR", "HIGH", "LOW", "high"),         # likelihood HIGH keeps the level
    ("ERROR", "MEDIUM", "MEDIUM", "high"),    # confidence MEDIUM keeps the level
    ("WARNING", "MEDIUM", "HIGH", "medium"),
    ("ERROR", None, None, "high"),            # no metadata: the level alone
    ("WARNING", None, "LOW", "medium"),       # confidence alone is not enough
    ("error", "medium", "low", "low"),        # case-insensitive
    ("", "MEDIUM", "MEDIUM", "medium"),       # unknown level defaults to medium
])
def test_sast_severity(severity, likelihood, confidence, expected):
    assert sast_severity(extra(severity, likelihood, confidence)) == expected


@pytest.mark.parametrize("metadata", [None, [], "LOW", 3])
def test_malformed_metadata_keeps_the_level(metadata):
    assert sast_severity({"severity": "ERROR", "metadata": metadata}) == "high"


def test_values_with_spaces_are_tolerated():
    assert sast_severity({"severity": "WARNING", "metadata": {"likelihood": " MEDIUM ", "confidence": "low "}}) == "low"


def test_sast_finding_uses_the_tempered_severity():
    match = {"check_id": "python.lang.security.eval", "path": "app/x.py",
             "start": {"line": 3}, "extra": extra("ERROR", "MEDIUM", "LOW")}
    f = sast_finding(match, "app/x.py", "python.lang.security.eval", 3, {})
    assert f["severity"] == "low"
    assert f["evidence"]["metadata"] == {"likelihood": "MEDIUM", "confidence": "LOW"}
