"""Restore actions name their session; a promotion is a background task.

An admin's screen left open must not restore an object from, promote, or
close a session another admin has reopened since at another instant: every
action carries the session id the agent gave, and a changed one is refused
before anything is written. A promotion answers at once and is followed by
polling — no gateway timeout on a long one, no second export and safety
backup on a retry, and its journal entry whatever its length.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.routes import restore

pytestmark = pytest.mark.asyncio


class Agent:
    """The backup agent's recovery API, as far as Pilot uses it."""

    def __init__(self):
        self.session = {"module": "risk", "status": "ready", "session": "s1",
                        "time": "2026-10-26 17:00:00+00"}
        self.promotion: dict | None = None
        self.polls_before_done = 3
        self.fail_with = ""
        self.calls: list = []
        # Accepted, but the answer never reaches Pilot (timeout).
        self.post_lost = False
        # The agent cannot be reached for status while this is set.
        self.unreachable = False
        # The POST is refused (4xx), or never reaches the agent (5xx).
        self.post_refused = False
        self.post_never_arrives = False
        self.timeouts: dict = {}

    async def __call__(self, method, path, body=None, timeout=30):
        self.calls.append((method, path, body))
        self.timeouts[(method, path)] = timeout
        await asyncio.sleep(0)   # a real call yields to the event loop
        if path == "/recover/risk" and method == "GET":
            return dict(self.session)
        if path.startswith("/recover/risk") and method == "DELETE":
            return {"ok": True}
        if path == "/recover/risk/promote" and method == "POST":
            if self.post_refused:
                raise restore.HTTPException(status_code=409, detail="restore session changed")
            if self.post_never_arrives:
                raise restore.HTTPException(status_code=502, detail="Agent unreachable: timed out")
            self.promotion = {"module": "risk", "state": "running", "session": (body or {}).get("session"),
                              "time": self.session["time"], "started_at": time.time()}
            if self.post_lost:
                raise restore.HTTPException(status_code=502, detail="Agent unreachable: timed out")
            return dict(self.promotion)
        if path == "/recover/risk/promote" and method == "GET":
            if self.unreachable:
                raise restore.HTTPException(status_code=502, detail="Agent unreachable: refused")
            if self.promotion is None:
                raise restore.HTTPException(status_code=404, detail="no promotion")
            if self.promotion["state"] == "running":
                self.polls_before_done -= 1
                if self.polls_before_done <= 0:
                    self.promotion.update(
                        {"state": "failed", "error": self.fail_with} if self.fail_with
                        else {"state": "done", "result": {"ok": True, "size_bytes": 42}})
            return dict(self.promotion)
        raise AssertionError(f"unexpected agent call {method} {path}")


class _Db:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def env(monkeypatch):
    from src.auth import get_current_user
    from src.database import get_db
    from src.routes import backups, measures

    agent = Agent()
    seen = {"backups": [], "journal": [], "module": []}

    async def run_backup(module_id, user, db):
        seen["backups"].append(module_id)
        await asyncio.sleep(seen.get("backup_s", 0))
        if seen.get("during_backup"):
            seen.pop("during_backup")()

    async def sync_measures(user, db):
        return None

    async def log_write(db, user, request, action, **kw):
        await asyncio.sleep(0.01)   # a real write yields to the event loop
        seen["journal"].append((action, kw))
        if seen.get("journal_breaks"):
            raise RuntimeError("journal unavailable")

    async def module_get(db, module, path):
        seen["module"].append(path)
        return {"id": "r1", "name": "MedSecure risks", "data": {}}

    async def module_put(db, module, path, body):
        seen["module"].append(("PUT", path))
        return {"ok": True}

    async def journal(db, module, entity_id="", limit=30):
        return []

    monkeypatch.setattr(restore, "_agent", agent)
    monkeypatch.setattr(restore, "require_admin", lambda user: None)
    monkeypatch.setattr(restore, "log_write", log_write)
    monkeypatch.setattr(restore, "_module_get", module_get)
    monkeypatch.setattr(restore, "_module_put", module_put)
    monkeypatch.setattr(restore, "_module_journal", journal)
    monkeypatch.setattr(restore, "async_session", lambda: _Db(), raising=False)
    monkeypatch.setattr(restore, "_PROMOTE_POLL_S", 0.01, raising=False)
    monkeypatch.setattr(restore, "_promotions", {}, raising=False)
    monkeypatch.setattr(restore, "_object_restores", {}, raising=False)
    monkeypatch.setattr(backups, "run_backup", run_backup)
    monkeypatch.setattr(measures, "sync_measures", sync_measures)

    app = FastAPI()
    app.include_router(restore.router)

    async def user():
        return SimpleNamespace(id=1, email="admin@medsecure.example", role="admin")
    app.dependency_overrides[get_current_user] = user
    app.dependency_overrides[get_db] = lambda: None
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
    return SimpleNamespace(agent=agent, seen=seen, client=client)


async def _settled(env, tries=200):
    for _ in range(tries):
        r = await env.client.get("/api/restore/sessions/risk/promote")
        if r.status_code == 200 and r.json()["state"] != "running":
            return r.json()
        await asyncio.sleep(0.01)
    raise AssertionError("the promotion never settled")


# ── the session an action names ──────────────────────────────────────────


async def test_an_object_restore_on_a_reopened_session_is_refused_before_any_write(env):
    env.agent.session.update(session="s2", time="2026-10-27 09:00:00+00")   # reopened by another admin
    r = await env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"})
    assert r.status_code == 409 and "session changed" in r.json()["detail"]
    assert env.seen["backups"] == [] and env.seen["module"] == []


async def test_an_object_restore_on_its_own_session_goes_through(env):
    r = await env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"})
    assert r.status_code == 200
    assert env.seen["backups"] == ["risk"] and ("PUT", "/api/internal/restore/r1") in env.seen["module"]


async def test_a_diff_on_a_reopened_session_is_refused(env):
    env.agent.session["session"] = "s2"
    r = await env.client.get("/api/restore/sessions/risk/objects/r1/diff?session=s1")
    assert r.status_code == 409 and env.seen["module"] == []


async def test_closing_names_the_session_this_screen_opened(env):
    r = await env.client.delete("/api/restore/sessions/risk?session=s1")
    assert r.status_code == 200
    assert ("DELETE", "/recover/risk?session=s1", None) in env.agent.calls


async def test_a_promotion_on_a_reopened_session_is_refused_before_the_backup(env):
    env.agent.session["session"] = "s2"
    r = await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    assert r.status_code == 409 and "session changed" in r.json()["detail"]
    await asyncio.sleep(0.05)
    assert env.seen["backups"] == [] and env.agent.promotion is None


# ── promotion as a background task ───────────────────────────────────────


async def test_a_promotion_answers_at_once_and_is_followed_to_its_end(env):
    r = await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    assert r.status_code == 202 and r.json()["state"] == "running"
    assert r.json()["time"] == "2026-10-26 17:00:00+00"
    done = await _settled(env)
    assert done["state"] == "done" and done["result"]["size_bytes"] == 42
    # Journaled once it ends, with the instant it went back to.
    [(action, kw)] = [j for j in env.seen["journal"] if j[0] == "restore.module"]
    assert kw["details"]["time"] == "2026-10-26 17:00:00+00"


async def test_a_retry_while_it_runs_returns_it_without_a_second_backup(env):
    env.agent.polls_before_done = 30
    body = {"confirm": "risk", "session": "s1"}
    first = await env.client.post("/api/restore/sessions/risk/promote", json=body)
    again = await env.client.post("/api/restore/sessions/risk/promote", json=body)
    assert again.status_code == 202 and again.json()["state"] == "running"
    assert again.json()["started_at"] == first.json()["started_at"]
    await _settled(env)
    assert env.seen["backups"] == ["risk"]
    assert [c for c in env.agent.calls if c[:2] == ("POST", "/recover/risk/promote")] == [
        ("POST", "/recover/risk/promote", {"session": "s1"})]


async def test_a_failed_promotion_shows_its_reason(env):
    env.agent.fail_with = "live database untouched — loading the restored data failed: boom"
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    failed = await _settled(env)
    assert failed["state"] == "failed" and "boom" in failed["error"]
    assert not [j for j in env.seen["journal"] if j[0] == "restore.module"]


async def test_a_session_being_promoted_cannot_be_closed_or_replaced(env):
    env.agent.polls_before_done = 30
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    assert (await env.client.delete("/api/restore/sessions/risk?session=s1")).status_code == 409
    assert (await env.client.post("/api/restore/sessions", json={"module": "risk"})).status_code == 409
    await _settled(env)


# ── a promotion Pilot loses track of ─────────────────────────────────────


async def test_an_accepted_promotion_whose_answer_was_lost_is_not_reported_failed(env):
    env.agent.post_lost = True
    env.agent.polls_before_done = 3
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    # The status requests ask the agent, follow it, and finish the job.
    done = await _settled(env)
    assert done["state"] == "done"
    assert [j for j in env.seen["journal"] if j[0] == "restore.module"]


async def test_an_unreachable_agent_leaves_the_state_unknown_and_blocks_a_retry(env, monkeypatch):
    env.agent.polls_before_done = 1000
    monkeypatch.setattr(restore, "_PROMOTE_POLL_MISSES", 2)
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    await asyncio.sleep(0.05)
    env.agent.unreachable = True
    out = await _settled(env)
    assert out["state"] == "unknown" and "check the module's data" in out["error"]
    again = await env.client.post("/api/restore/sessions/risk/promote",
                                  json={"confirm": "risk", "session": "s1"})
    assert again.status_code == 409 and env.seen["backups"] == ["risk"]
    # Nothing else on the module while it is unknown.
    assert (await env.client.get("/api/restore/sessions/risk/objects/r1/diff?session=s1")).status_code == 409
    env.agent.unreachable = False
    env.agent.polls_before_done = 1
    assert (await _settled(env))["state"] == "done"


async def test_a_journal_failure_after_the_switch_is_not_a_failed_promotion(env):
    env.seen["journal_breaks"] = True
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    assert (await _settled(env))["state"] == "done"


async def test_the_session_is_kept_alive_during_a_long_safety_backup(env, monkeypatch):
    monkeypatch.setattr(restore, "_KEEPALIVE_S", 0.01, raising=False)
    env.seen["backup_s"] = 0.2
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    await _settled(env)
    touches = [c for c in env.agent.calls if c[:2] == ("GET", "/recover/risk")]
    assert len(touches) >= 5   # one session check, then the touches during the backup


async def test_object_restore_and_diff_are_refused_while_promoting(env):
    env.agent.polls_before_done = 30
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    r = await env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"})
    assert r.status_code == 409 and "being promoted" in r.json()["detail"]
    r = await env.client.get("/api/restore/sessions/risk/objects/r1/diff?session=s1")
    assert r.status_code == 409
    await _settled(env)


def _unknown(env, **agent_record):
    """A promotion Pilot lost track of, as left in its registry."""
    rec = {"module": "risk", "state": "unknown", "phase": "promote", "session": "s1",
           "time": "2026-10-26 17:00:00+00", "started_at": 0, "finished_at": None, "by": None,
           "result": None, "error": "Pilot lost track of the promotion (timed out)",
           "requested_at": time.time() - 60,
           "_user": SimpleNamespace(id=1, email="admin@medsecure.example")}
    restore._promotions["risk"] = rec
    env.agent.promotion = {"module": "risk", "session": "s1", "time": rec["time"],
                           "started_at": rec["requested_at"] + 1, **agent_record}
    return rec


async def test_a_retry_that_resolves_an_unknown_promotion_starts_nothing(env):
    _unknown(env, state="done", result={"ok": True})
    r = await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    assert r.status_code == 200 and r.json()["state"] == "done"
    await asyncio.sleep(0.05)
    assert env.seen["backups"] == []
    assert not [c for c in env.agent.calls if c[:2] == ("POST", "/recover/risk/promote")]


async def test_concurrent_reads_finish_a_resolved_promotion_once(env):
    _unknown(env, state="done", result={"ok": True})
    views = await asyncio.gather(*(env.client.get("/api/restore/sessions/risk/promote")
                                   for _ in range(3)))
    assert all(v.status_code == 200 for v in views)
    assert len([j for j in env.seen["journal"] if j[0] == "restore.module"]) == 1


async def test_an_interrupted_finalisation_gives_its_claim_back(env, monkeypatch):
    rec = _unknown(env, state="done", result={"ok": True})

    async def cancelled(*a, **kw):
        raise asyncio.CancelledError
    monkeypatch.setattr(restore, "log_write", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await restore._reconcile("risk", rec)
    assert rec["state"] == "unknown"


@pytest.mark.parametrize("offset, ours", [(-600, False), (-6, False), (-4, True), (1, True)])
async def test_an_agent_record_counts_as_this_promotion_only_within_the_clock_margin(env, offset, ours):
    rec = _unknown(env, state="done", result={"ok": True})
    env.agent.promotion["started_at"] = rec["requested_at"] + offset
    out = (await env.client.get("/api/restore/sessions/risk/promote")).json()
    assert out["state"] == ("done" if ours else "failed")
    assert bool([j for j in env.seen["journal"] if j[0] == "restore.module"]) is ours


async def test_a_promote_the_agent_refuses_is_a_definite_failure(env):
    env.agent.post_refused = True
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    for _ in range(100):
        rec = restore._promotions["risk"]
        if rec["state"] != "running":
            break
        await asyncio.sleep(0.01)
    # Failed at once, without going through "unknown": nothing started.
    assert rec["state"] == "failed" and rec["error"] == "restore session changed"


async def test_a_promote_that_may_have_reached_the_agent_is_unknown(env):
    env.agent.post_never_arrives = True
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    for _ in range(100):
        rec = restore._promotions["risk"]
        if rec["state"] != "running":
            break
        await asyncio.sleep(0.01)
    assert rec["state"] == "unknown" and "check the module's data" in rec["error"]


async def test_a_failure_after_the_switch_is_never_a_failed_promotion(env, monkeypatch):
    opened = []

    class Breaks(_Db):
        async def __aenter__(self):
            opened.append(1)
            if len(opened) > 1:     # the one after the switch
                raise RuntimeError("connection pool exhausted")
            return self
    monkeypatch.setattr(restore, "async_session", lambda: Breaks())
    await env.client.post("/api/restore/sessions/risk/promote", json={"confirm": "risk", "session": "s1"})
    out = await _settled(env)
    assert out["state"] == "done" and "journal entry could not be written" in out["error"]


async def test_closing_waits_for_the_instance_to_stop(env):
    await env.client.delete("/api/restore/sessions/risk?session=s1")
    assert env.agent.timeouts[("DELETE", "/recover/risk?session=s1")] >= 60


# ── a session promotes once ──────────────────────────────────────────────

_PROMOTE = {"confirm": "risk", "session": "s1"}


def _agent_promotions(env):
    return [c for c in env.agent.calls if c[:2] == ("POST", "/recover/risk/promote")]


async def test_a_session_already_promoted_is_not_promoted_again(env):
    await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert (await _settled(env))["state"] == "done"
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and "already restored from this session" in r.json()["detail"]
    assert env.seen["backups"] == ["risk"] and len(_agent_promotions(env)) == 1
    # Pilot's own record is enough, even when the agent has forgotten it.
    env.agent.promotion = None
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and env.seen["backups"] == ["risk"]


async def test_a_promotion_resolved_by_a_read_is_not_promoted_again(env):
    _unknown(env, state="done", result={"ok": True})
    assert (await env.client.get("/api/restore/sessions/risk/promote")).json()["state"] == "done"
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and "already restored from this session" in r.json()["detail"]
    assert env.seen["backups"] == [] and _agent_promotions(env) == []


async def test_a_promotion_the_agent_finished_while_pilot_restarted_is_not_redone(env):
    # Pilot remembers nothing; the agent has promoted this session.
    env.agent.promotion = {"module": "risk", "state": "done", "session": "s1",
                           "time": env.agent.session["time"], "started_at": time.time() - 30,
                           "result": {"ok": True}}
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and "already restored from this session" in r.json()["detail"]
    await asyncio.sleep(0.05)
    assert env.seen["backups"] == [] and _agent_promotions(env) == []


async def test_a_retry_that_finds_the_previous_one_failed_starts_nothing(env):
    _unknown(env, state="failed", error="live database untouched — boom")
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and "boom" in r.json()["detail"]
    await asyncio.sleep(0.05)
    assert env.seen["backups"] == [] and _agent_promotions(env) == []


# ── object restore and promotion exclude each other ──────────────────────


async def test_actions_on_a_promoted_session_are_refused(env):
    env.agent.session["status"] = "promoted"
    r = await env.client.get("/api/restore/sessions/risk/objects/r1/diff?session=s1")
    assert r.status_code == 409 and "already restored from this session" in r.json()["detail"]
    r = await env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"})
    assert r.status_code == 409 and env.seen["backups"] == []


async def test_a_promotion_waits_for_an_object_restore_under_way(env):
    env.seen["backup_s"] = 0.2
    restoring = asyncio.ensure_future(
        env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"}))
    await asyncio.sleep(0.05)
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 409 and "being restored" in r.json()["detail"]
    assert (await restoring).status_code == 200
    env.seen["backup_s"] = 0
    r = await env.client.post("/api/restore/sessions/risk/promote", json=_PROMOTE)
    assert r.status_code == 202      # free once it is over
    await _settled(env)


async def test_an_object_restore_does_not_write_once_a_promotion_has_started(env):
    # A promotion appears while the object's safety backup runs.
    env.seen["during_backup"] = lambda: restore._promotions.update(
        risk={"module": "risk", "state": "running", "session": "s1"})
    r = await env.client.post("/api/restore/sessions/risk/objects/r1/restore", json={"session": "s1"})
    assert r.status_code == 409 and "being promoted" in r.json()["detail"]
    assert ("PUT", "/api/internal/restore/r1") not in env.seen["module"]
    assert restore._object_restores == {}
