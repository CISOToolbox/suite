"""FEAT-52 — Semgrep-era SAST findings are carried over, not duplicated.

Semgrep OSS returned "requires login" as the fingerprint, so its findings
were keyed `semgrep|sast|<file>|<rule>|requires login<n>`. Opengrep findings
are keyed `sast|<file>|<rule>|<digest of the matched lines>`. The first scan
after the engine change carries each former row over — status, triage and
links kept — instead of closing it and opening a new twin; the ones it
cannot are closed, marked, and kept 30 days (no purge, no reopening)."""
import os
import sys
import uuid

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from datetime import datetime, timedelta, timezone  # noqa: E402

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.findings_dedup import upsert_findings  # noqa: E402
from src.models import Application, Base, Finding  # noqa: E402
from src.scanners import sast_finding, sast_rule_id  # noqa: E402
import src.scanners as scanners  # noqa: E402
from src.scheduler import _close_unseen_findings, _purgeable, _reopen_fixed  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

APP_ID = uuid.uuid4()
RULE = "python.lang.security.audit.eval-detected"
FILE = "app/main.py"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add(Application(id=APP_ID, name="Patient portal"))
        await session.commit()
        yield session
    await engine.dispose()


def _legacy(n: int, line: int, status: str) -> Finding:
    suffix = "" if n == 1 else f"#{n}"
    return Finding(id=uuid.uuid4(), application_id=APP_ID, scanner="sast", type="sast",
                   severity="high", title=RULE, target=f"{FILE}:{line}", status=status,
                   dedup_key=f"semgrep|sast|{FILE}|{RULE}|requires login{suffix}".lower(),
                   evidence={}, triage_notes="reviewed" if status != "new" else "")


def _raw(code: str, line: int, seen: dict) -> dict:
    match = {"extra": {"lines": "requires login", "fingerprint": "requires login",
                       "severity": "ERROR", "message": ""}, "start": {"line": line}}
    return sast_finding(match, FILE, RULE, line, seen, code=code)


async def _rows(db) -> list[Finding]:
    return list((await db.execute(select(Finding).where(Finding.application_id == APP_ID)
                                  .order_by(Finding.target))).scalars().all())


@pytest.mark.asyncio
async def test_each_former_row_is_adopted_at_its_place(db):
    db.add_all([_legacy(1, 3, "false_positive"), _legacy(2, 9, "to_fix")])
    await db.commit()
    seen: dict = {}
    stats = await upsert_findings(db, APP_ID, [_raw("eval(a)", 3, seen), _raw("eval(b)", 9, seen)])
    await db.commit()
    rows = await _rows(db)
    assert len(rows) == 2, "former rows were duplicated instead of adopted"
    by_target = {r.target: r for r in rows}
    assert by_target[f"{FILE}:3"].status == "false_positive"
    assert by_target[f"{FILE}:9"].status == "to_fix"
    assert all("requires login" not in r.dedup_key for r in rows)
    assert stats.get("rekeyed") == 2 and stats["inserted"] == 0


@pytest.mark.asyncio
async def test_later_scans_keep_identity_when_an_earlier_match_goes(db):
    db.add_all([_legacy(1, 3, "false_positive"), _legacy(2, 9, "to_fix")])
    await db.commit()
    seen: dict = {}
    await upsert_findings(db, APP_ID, [_raw("eval(a)", 3, seen), _raw("eval(b)", 9, seen)])
    await db.commit()
    # A is fixed; B moves up to line 3 — it must keep ITS status, not A's.
    await upsert_findings(db, APP_ID, [_raw("eval(b)", 3, {})])
    await db.commit()
    b = next(r for r in await _rows(db) if r.status == "to_fix")
    assert b.target == f"{FILE}:3", "B lost its own row"
    fp = next(r for r in await _rows(db) if r.status == "false_positive")
    assert fp.target == f"{FILE}:3" and fp.id != b.id  # A's row left behind, closed by the scan


@pytest.mark.asyncio
async def test_ambiguous_former_rows_are_not_guessed(db):
    db.add_all([_legacy(1, 3, "false_positive"), _legacy(2, 9, "to_fix")])
    await db.commit()
    # Lines changed and two former rows remain: no guess, a new finding.
    stats = await upsert_findings(db, APP_ID, [_raw("eval(c)", 20, {})])
    await db.commit()
    assert stats["inserted"] == 1 and not stats.get("rekeyed")


@pytest.mark.asyncio
async def test_other_scanners_are_untouched(db):
    db.add(_legacy(1, 3, "false_positive"))
    await db.commit()
    stats = await upsert_findings(db, APP_ID, [{
        "scanner": "gitleaks", "type": "secret", "title": "x", "target": f"{FILE}:3",
        "dedup_key": "gitleaks|secret|app/main.py|aws|abc", "evidence": {"file": FILE, "rule_id": RULE}}])
    assert stats["inserted"] == 1 and not stats.get("rekeyed")


@pytest.mark.asyncio
async def test_a_new_match_above_does_not_take_the_verdict(db):
    """A former false positive at line 10; a NEW eval appears at line 2 and the
    reviewed code moves to 13. The new match is first in the scan output: it
    must not take the former row — its verdict would stick to it for good."""
    db.add(_legacy(1, 10, "false_positive"))
    await db.commit()
    seen: dict = {}
    await upsert_findings(db, APP_ID, [_raw("eval(user)", 2, seen), _raw("eval(old)", 13, seen)])
    await db.commit()
    status = {r.target: r.status for r in await _rows(db) if "requires login" not in r.dedup_key}
    assert status.get(f"{FILE}:2") == "new", "the new match inherited the false positive"


@pytest.mark.asyncio
async def test_same_place_wins_over_the_sole_former_row(db):
    """Same, but the reviewed code stays at line 10: the match AT line 10 is the
    one that takes the row, even though the line-2 match is processed first."""
    db.add(_legacy(1, 10, "false_positive"))
    await db.commit()
    seen: dict = {}
    await upsert_findings(db, APP_ID, [_raw("eval(user)", 2, seen), _raw("eval(old)", 10, seen)])
    await db.commit()
    status = {r.target: r.status for r in await _rows(db)}
    assert status[f"{FILE}:10"] == "false_positive"
    assert status[f"{FILE}:2"] == "new"


@pytest.mark.asyncio
async def test_the_sole_match_takes_the_sole_former_row(db):
    """The code moved (line 10 → 14) and nothing else matches that rule in the
    file: the one match takes the one former row."""
    db.add(_legacy(1, 10, "false_positive"))
    await db.commit()
    stats = await upsert_findings(db, APP_ID, [_raw("eval(old)", 14, {})])
    await db.commit()
    rows = await _rows(db)
    assert len(rows) == 1 and rows[0].status == "false_positive" and stats.get("rekeyed") == 1


@pytest.mark.asyncio
async def test_a_former_row_not_carried_over_is_closed_and_marked(db):
    old = _legacy(1, 3, "false_positive")
    db.add(old)
    await db.commit()
    started = datetime.now(timezone.utc) + timedelta(seconds=1)
    closed = await _close_unseen_findings(db, APP_ID, "sast", started)
    await db.commit()
    await db.refresh(old)
    assert closed == 1 and old.status == "fixed" and old.migration_closed_at is not None


@pytest.mark.asyncio
async def test_marked_rows_are_kept_then_purged_after_30_days(db):
    now = datetime.now(timezone.utc)
    fresh, aged, plain = _legacy(1, 3, "fixed"), _legacy(2, 4, "fixed"), _legacy(3, 5, "fixed")
    fresh.migration_closed_at = now - timedelta(days=2)
    aged.migration_closed_at = now - timedelta(days=31)
    plain.dedup_key = "sast|app/main.py|r|abc"
    db.add_all([fresh, aged, plain])
    await db.commit()
    ids = set((await db.execute(select(Finding.id).where(_purgeable(now)))).scalars().all())
    assert fresh.id not in ids, "a fresh migration row would be purged"
    assert aged.id in ids and plain.id in ids


@pytest.mark.asyncio
async def test_no_new_commit_does_not_reopen_marked_rows(db):
    now = datetime.now(timezone.utc)
    marked, plain = _legacy(1, 3, "fixed"), _legacy(2, 4, "fixed")
    marked.migration_closed_at = now
    plain.dedup_key = "sast|app/main.py|r|abc"
    db.add_all([marked, plain])
    await db.commit()
    assert await _reopen_fixed(db, APP_ID, now) == 1
    await db.commit()
    await db.refresh(marked)
    await db.refresh(plain)
    assert marked.status == "fixed" and plain.status == "new"


def test_rule_ids_keep_their_registry_name(monkeypatch):
    """Opengrep reports a local rule as `<dirs>.<rule id>`; the registry name
    (the one former findings carry) is `<dirs>.<file>.<rule id>`."""
    monkeypatch.setattr(scanners, "_SAST_INDEX", {
        "rules.python.lang.security.audit.logging.python-logger-credential-disclosure":
        "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure"})
    assert sast_rule_id("rules.python.lang.security.audit.logging.python-logger-credential-disclosure") \
        == "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure"
    assert sast_rule_id("house.unknown.rule") == "house.unknown.rule"


def test_the_former_scanner_id_is_still_accepted():
    from src.schemas import ApplicationCreate
    app = ApplicationCreate(name="x", enabled_scanners=["trivy_fs", "semgrep"])
    assert app.enabled_scanners == ["trivy_fs", "sast"]


@pytest.mark.asyncio
async def test_a_former_row_left_aside_never_goes_to_later_code(db):
    """B1 — first scan: the former row is ambiguous (code moved, a second
    occurrence), so it is closed and marked. Second scan, after a commit: new
    code appears at its old place. It must NOT take the former row."""
    db.add(_legacy(1, 10, "false_positive"))
    await db.commit()
    seen: dict = {}
    started = datetime.now(timezone.utc)
    await upsert_findings(db, APP_ID, [_raw("eval(old)", 12, seen), _raw("eval(other)", 40, seen)])
    await _close_unseen_findings(db, APP_ID, "sast", started)
    await db.commit()
    stats = await upsert_findings(db, APP_ID, [_raw("eval(brand_new)", 10, {})])
    await db.commit()
    assert not stats.get("rekeyed"), "a later scan handed the former verdict to new code"
    old = next(r for r in await _rows(db) if r.dedup_key.startswith("semgrep|"))
    assert old.status == "fixed" and old.migration_prev_status == "false_positive"


@pytest.mark.asyncio
async def test_a_former_derogation_not_carried_over_is_closed_too(db):
    """B1 — a derogated former row left aside must not stay a candidate."""
    db.add(_legacy(1, 10, "derogated"))
    await db.commit()
    started = datetime.now(timezone.utc)
    await upsert_findings(db, APP_ID, [_raw("eval(a)", 12, {}), _raw("eval(b)", 40, {"x": 1})])
    await _close_unseen_findings(db, APP_ID, "sast", started)
    await db.commit()
    old = next(r for r in await _rows(db) if r.dedup_key.startswith("semgrep|"))
    assert old.status == "fixed" and old.migration_closed_at is not None
    assert old.migration_prev_status == "derogated"
    stats = await upsert_findings(db, APP_ID, [_raw("eval(c)", 10, {})])
    assert not stats.get("rekeyed")


@pytest.mark.asyncio
async def test_former_rows_with_a_real_fingerprint_are_carried_over(db):
    """C1 — a Semgrep-era key ending with a real fingerprint (not the OSS
    placeholder) is recognised at the same place."""
    row = _legacy(1, 7, "false_positive")
    row.dedup_key = f"semgrep|sast|{FILE}|{RULE}|4acd5eb091c3".lower()
    db.add(row)
    await db.commit()
    stats = await upsert_findings(db, APP_ID, [_raw("eval(a)", 7, {})])
    await db.commit()
    await db.refresh(row)
    assert stats.get("rekeyed") == 1 and row.status == "false_positive" and row.dedup_key.startswith("sast|")
