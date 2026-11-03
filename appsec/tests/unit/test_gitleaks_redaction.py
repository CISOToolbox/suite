"""Regression: gitleaks findings never store the secret they found.

The description ended with `Match: <matched text>`, the secret included:
every AppSec viewer read it and it was sent to the AI provider. Locks:
  - the scanner writes the match with the secret replaced, and keeps the
    secret's digest as the finding's identity;
  - migration 017 redacts the descriptions already stored, on findings and
    on the measures raised from them, and nothing else.
"""
import importlib.util
import json
import os
import pathlib
import sqlite3
import sys
import types

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import src.scanners as scanners  # noqa: E402

SECRET = "medsecure-deploy-token-0123456789"
MULTILINE = "key material line 1\nMIIEpmedsecure line 2"
MIGRATION = pathlib.Path(__file__).resolve().parents[2] / "alembic" / "versions" / "017_redact_gitleaks_match.py"


def _scan(monkeypatch, leaks):
    def _fake_run(cmd, **kw):
        with open(cmd[cmd.index("--report-path") + 1], "w") as f:
            json.dump(leaks, f)
        return types.SimpleNamespace(returncode=0, stderr="", stdout="")
    monkeypatch.setattr(scanners, "_run_scanner", _fake_run)
    return scanners.run_gitleaks("/repo", "app")


def test_description_carries_no_secret(monkeypatch):
    [f] = _scan(monkeypatch, [{
        "RuleID": "aws-access-token", "File": "/repo/deploy/config.py", "StartLine": 12,
        "Match": f'aws_key = "{SECRET}"', "Secret": SECRET,
    }])
    assert SECRET not in json.dumps(f)
    assert f["description"].endswith('Match: aws_key = "REDACTED"')
    assert f["evidence"]["secret_id"] == scanners._code_id(SECRET)


def test_match_without_its_secret_is_fully_redacted(monkeypatch):
    [f] = _scan(monkeypatch, [{
        "RuleID": "private-key", "File": "/repo/keys/id_rsa", "StartLine": 1,
        "Match": MULTILINE, "Secret": "",
    }])
    assert "MIIE" not in f["description"]
    assert f["description"].endswith("Match: REDACTED")


def _migration():
    spec = importlib.util.spec_from_file_location("m017", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    statements: list[str] = []
    fake_alembic = types.ModuleType("alembic")
    fake_alembic.op = types.SimpleNamespace(execute=statements.append)
    sys.modules["alembic"] = fake_alembic
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("alembic", None)
    return mod, statements


def _to_sqlite(sql: str) -> str:
    """The PostgreSQL text functions of the migration, in SQLite."""
    return sql.replace("strpos(", "instr(").replace("chr(10)", "char(10)")


def test_migration_chain():
    mod, _ = _migration()
    assert mod.down_revision == "016_sast_scanner"


def _migrate(findings: list, measures: list) -> tuple[dict, dict]:
    mod, statements = _migration()
    mod.upgrade()
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE findings (id TEXT, scanner TEXT, description TEXT)")
    db.execute("CREATE TABLE measures (id TEXT, finding_id TEXT, description TEXT)")
    db.executemany("INSERT INTO findings VALUES (?, ?, ?)", findings)
    db.executemany("INSERT INTO measures VALUES (?, ?, ?)", measures)
    for sql in statements:
        db.execute(_to_sqlite(sql))
    return (dict(db.execute("SELECT id, description FROM findings")),
            dict(db.execute("SELECT id, description FROM measures")))


LEAK = f"Rule: aws\nFile: a.py:3\nMatch: key = {SECRET}"
KEY = f"Rule: pk\nFile: id_rsa:1\nMatch: {MULTILINE}"
TRIVY = "Package x\nMatch: not a gitleaks finding"


def test_migration_redacts_findings_and_only_them():
    findings, _ = _migrate([
        ("f1", "gitleaks", LEAK), ("f2", "gitleaks", KEY), ("f3", "trivy", TRIVY),
        ("f4", "gitleaks", "Rule: x\nFile: b.py:1"),
    ], [])
    assert findings["f1"] == "Rule: aws\nFile: a.py:3\nMatch: REDACTED"
    assert findings["f2"] == "Rule: pk\nFile: id_rsa:1\nMatch: REDACTED"
    assert findings["f3"] == TRIVY and findings["f4"] == "Rule: x\nFile: b.py:1"


def test_migration_redacts_measures_and_keeps_their_owners_text():
    _, measures = _migrate([("f1", "gitleaks", LEAK), ("f2", "gitleaks", KEY), ("f3", "trivy", TRIVY)], [
        ("m1", "f1", LEAK),
        ("m2", "f1", LEAK + "\n\nRotate the key, then purge the history."),
        ("m3", "f2", KEY + "\nOwner: platform team"),
        ("m4", "f3", TRIVY),
        ("m5", "f1", "Rotate the key"),
    ])
    assert measures["m1"] == "Rule: aws\nFile: a.py:3\nMatch: REDACTED"
    assert measures["m2"] == "Rule: aws\nFile: a.py:3\nMatch: REDACTED\n\nRotate the key, then purge the history."
    # The multi-line key goes whole: the measure still holds the finding's text.
    assert measures["m3"] == "Rule: pk\nFile: id_rsa:1\nMatch: REDACTED\nOwner: platform team"
    assert measures["m4"] == TRIVY and measures["m5"] == "Rotate the key"


def test_migration_cuts_the_match_line_of_a_measure_that_drifted():
    # The finding moved (its line changed) after the measure copied it: only
    # the Match line of the measure is cut, the owner's text after it stays.
    moved = LEAK.replace("a.py:3", "a.py:9")
    _, measures = _migrate([("f1", "gitleaks", moved)], [
        ("m1", "f1", LEAK + "\nRotate the key"),
    ])
    assert measures["m1"] == "Rule: aws\nFile: a.py:3\nMatch: REDACTED\nRotate the key"


class TestPilotWriteBack:
    """Pilot writes a measure's description back from its cache: a copy taken
    before the redaction must not put the secret back."""

    def _patch(self, monkeypatch, scanner: str, stored: str, incoming: str) -> str:
        import asyncio
        import uuid

        import src.audit_common as audit_common
        import src.routes.internal as internal
        from src.models import Finding, Measure

        async def _no_log(*a, **k):
            return None
        monkeypatch.setattr(internal, "_check_service_token", lambda request: None)
        monkeypatch.setattr(audit_common, "log_write", _no_log)
        f = Finding(id=uuid.uuid4(), scanner=scanner)
        m = Measure(id="MES-0001", finding_id=f.id, description=stored)

        class _DB:
            async def get(self, model, key):
                return {Measure: m, Finding: f}[model]

            async def commit(self):
                return None

        class _Request:
            async def json(self):
                return {"description": incoming}

        asyncio.run(internal.patch_measure("MES-0001", _Request(), db=_DB()))
        return m.description

    def test_stale_copy_does_not_restore_the_secret(self, monkeypatch):
        stored = "Rule: aws\nFile: a.py:3\nMatch: REDACTED"
        out = self._patch(monkeypatch, "gitleaks", stored, LEAK + "\nEdited in Pilot")
        assert SECRET not in out
        assert out == "Rule: aws\nFile: a.py:3\nMatch: REDACTED\nEdited in Pilot"

    def test_other_scanners_are_written_as_sent(self, monkeypatch):
        out = self._patch(monkeypatch, "trivy", "x", "Package x\nMatch: as sent")
        assert out == "Package x\nMatch: as sent"
