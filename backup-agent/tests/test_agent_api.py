"""Lock the recovery API behaviours that silently broke restores.

pgBackRest, pg_ctl, pg_dump and psql are never run: subprocess calls are
faked, and a tiny in-memory "cluster" stands in for the databases so the
promotion is checked on what it leaves behind, not on the SQL it sends.
The HTTP checks go through the real handler on a local port.
"""
import json
import os
import pathlib
import re
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault("BACKUP_AGENT_TOKEN", "t" * 40)

import agent_api  # noqa: E402

TOKEN = "t" * 40


class _Done:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


@pytest.fixture(autouse=True)
def _clean_sessions(monkeypatch):
    monkeypatch.setattr(agent_api, "TOKEN", TOKEN)
    registries = [getattr(agent_api, n) for n in ("_sessions", "_workers", "_promoting")
                  if hasattr(agent_api, n)]
    for registry in registries:
        registry.clear()
    yield
    for registry in registries:
        registry.clear()


# ── promotion ────────────────────────────────────────────────────────────


class Cluster:
    """Databases by name -> content; psql/pg_dump answered from it."""

    def __init__(self, fail_load=False, fail_rename=False):
        self.dbs = {"postgres": "", "risk": "live data"}
        self.fail_load, self.fail_rename = fail_load, fail_rename

    def run(self, cmd, input=None, **kw):
        if cmd[0] == "pg_dump":
            return _Done(out="restored data")
        target = cmd[cmd.index("-d") + 1]
        if "-tAc" in cmd:
            sql = cmd[cmd.index("-tAc") + 1]
            assert ";" not in sql, "one statement per command: no implicit transaction"
            if m := re.fullmatch(r"SELECT 1 FROM pg_database WHERE datname = '(\w+)'", sql):
                return _Done(out="1" if m.group(1) in self.dbs else "")
            if m := re.fullmatch(r"DROP DATABASE (IF EXISTS )?(\w+) WITH \(FORCE\)", sql):
                if m.group(2) not in self.dbs and not m.group(1):
                    return _Done(rc=1, err=f'database "{m.group(2)}" does not exist')
                self.dbs.pop(m.group(2), None)
                return _Done()
            if m := re.fullmatch(r"CREATE DATABASE (\w+) OWNER \w+", sql):
                self.dbs[m.group(1)] = ""
                return _Done()
            if m := re.fullmatch(r"ALTER DATABASE (\w+) RENAME TO (\w+)", sql):
                if self.fail_rename:
                    return _Done(rc=1, err="rename refused")
                self.dbs[m.group(2)] = self.dbs.pop(m.group(1))
                return _Done()
            raise AssertionError(f"unexpected SQL: {sql}")
        # Loading a dump: all or nothing, as with --single-transaction.
        assert "--single-transaction" in cmd
        if self.fail_load:
            return _Done(rc=3, err="ERROR: syntax error")
        self.dbs[target] = input
        return _Done()


def test_promote_replaces_the_live_database_with_the_restored_data(monkeypatch):
    c = Cluster()
    monkeypatch.setattr(agent_api.subprocess, "run", c.run)
    agent_api._do_promote("risk")
    assert c.dbs["risk"] == "restored data" and "risk_restore" not in c.dbs


def test_a_failed_load_leaves_the_live_database_untouched(monkeypatch):
    c = Cluster(fail_load=True)
    monkeypatch.setattr(agent_api.subprocess, "run", c.run)
    with pytest.raises(RuntimeError, match="live database untouched"):
        agent_api._do_promote("risk")
    assert c.dbs["risk"] == "live data" and "risk_restore" not in c.dbs


def test_an_interrupted_swap_is_reported_and_finished_by_the_next_promote(monkeypatch):
    c = Cluster(fail_rename=True)
    monkeypatch.setattr(agent_api.subprocess, "run", c.run)
    with pytest.raises(RuntimeError, match="LIVE DATABASE DROPPED.*risk_restore"):
        agent_api._do_promote("risk")
    c.fail_rename = False
    agent_api._do_promote("risk")
    assert c.dbs["risk"] == "restored data" and "risk_restore" not in c.dbs


# ── restore workers ──────────────────────────────────────────────────────


@pytest.fixture
def worker(monkeypatch):
    """A restore worker whose instance answers `answer` and whose pg_ctl
    status reports `alive`; records what it cleans up."""
    state = {"answer": "t", "alive": True, "cleaned": []}
    monkeypatch.setattr(agent_api, "_cleanup", lambda m: state["cleaned"].append(m))
    monkeypatch.setattr(agent_api.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(agent_api, "_pgbackrest", lambda *a: _Done())
    monkeypatch.setattr(agent_api, "_pg_ctl",
                        lambda m, *a: _Done(rc=0 if state["alive"] or "start" in a else 3))
    monkeypatch.setattr(agent_api.subprocess, "run", lambda cmd, **kw: _Done(out=state["answer"]))
    # A clock that moves 5 s per reading, without sleeping: any wait in the
    # worker ends quickly, whichever deadline it uses.
    clock = {"now": 0.0}

    def now():
        clock["now"] += 5
        return clock["now"]
    monkeypatch.setattr(agent_api, "_time", types.SimpleNamespace(time=now, sleep=lambda s: None))
    return state


def test_a_late_worker_leaves_a_newer_session_alone(worker):
    newer = {"status": "ready", "id": object(), "started_at": 0}
    agent_api._sessions["risk"] = newer
    # Its own session was closed, a newer one took the module: the instance
    # answering on the socket is the newer one's, and must survive.
    agent_api._do_recover("risk", None, 1, session_id=object())
    assert agent_api._sessions["risk"] is newer and newer["status"] == "ready"
    assert worker["cleaned"] == ["risk"]        # only its own start-up cleanup


def test_a_late_worker_cleans_up_when_no_session_is_left(worker):
    agent_api._do_recover("risk", None, 1, session_id=object())
    assert worker["cleaned"] == ["risk", "risk"]  # start-up, then what it left


def test_a_failing_late_worker_writes_nothing(worker, monkeypatch):
    monkeypatch.setattr(agent_api, "_pgbackrest", lambda *a: _Done(rc=1, err="ERROR: [058] boom"))
    newer = {"status": "preparing", "id": object(), "started_at": 0}
    agent_api._sessions["risk"] = newer
    agent_api._do_recover("risk", None, 1, session_id=object())
    assert newer["status"] == "preparing" and "error" not in newer


def test_an_instance_that_dies_during_recovery_fails_the_session(worker):
    worker["answer"], worker["alive"] = "", False
    sid = object()
    agent_api._sessions["risk"] = {"status": "preparing", "id": sid, "started_at": 0}
    agent_api._do_recover("risk", "2026-10-26 17:00:00+00", 1, session_id=sid)
    s = agent_api._sessions["risk"]
    assert s["status"] == "error" and "stopped during recovery" in s["error"]


def test_the_reason_an_instance_stopped_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_api, "_scratch", lambda m: str(tmp_path))
    noise = "\n".join(f"LOG:  restored log file {i:024X}" for i in range(50))
    (tmp_path / "startup.log").write_text(
        "LOG:  starting point-in-time recovery\n" + noise +
        "\nFATAL:  recovery ended before configured recovery target was reached\n"
        "LOG:  startup process (PID 317) exited with exit code 1\n" + noise)
    assert "recovery ended before configured recovery target" in agent_api._startup_tail("risk")


# ── HTTP ─────────────────────────────────────────────────────────────────


@pytest.fixture
def api(monkeypatch):
    """The real handler on a local port; restore workers are not started."""
    started = []
    monkeypatch.setattr(agent_api, "_window", lambda repo=1: {})
    # The agent's own view of threading only: the HTTP server needs the real one.
    # A started worker is taken as finished at once (it frees its module).
    fake = type("T", (), {"__init__": lambda self, target, args, daemon: setattr(self, "a", args),
                          "start": lambda self: (started.append(self.a),
                                                 agent_api._workers.discard(self.a[0]))})
    monkeypatch.setattr(agent_api, "threading", types.SimpleNamespace(Thread=fake))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), agent_api.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def call(method, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Agent-Token": TOKEN, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    yield call, started
    srv.shutdown()


@pytest.mark.parametrize("given", ["2026-10-26 17:12:53", "2026-10-26T17:12:53Z",
                                   "2026-10-26 17:12:53+0000", "2026-10-26 17:12:53+00:00"])
def test_times_without_or_with_any_utc_offset_are_accepted(api, given):
    call, started = api
    assert call("POST", "/recover", {"module": "risk", "time": given})[0] == 202
    assert started[-1][1].startswith("2026-10-26 17:12:53")


def test_an_impossible_time_is_refused(api):
    call, _ = api
    assert call("POST", "/recover", {"module": "risk", "time": "2026-13-45 99:99:99"})[0] == 400


def test_a_time_without_offset_is_compared_with_the_window(api, monkeypatch):
    call, _ = api
    monkeypatch.setattr(agent_api, "_window",
                        lambda repo=1: {"risk": {"from": "2026-10-27 00:00:00+00:00"}})
    for given in ("2026-10-26 17:12:53", "2026-10-26 17:12:53+0000"):
        status, body = call("POST", "/recover", {"module": "risk", "time": given})
        assert status == 400 and "predates" in body["detail"], given


def test_a_second_module_session_is_refused_while_one_is_open(api):
    call, _ = api
    assert call("POST", "/recover", {"module": "risk"})[0] == 202
    status, body = call("POST", "/recover", {"module": "vendor"})
    assert status == 409 and "risk" in body["detail"]
    assert call("DELETE", "/recover/risk")[0] == 200
    assert call("POST", "/recover", {"module": "vendor"})[0] == 202


def test_a_module_is_not_restored_again_while_its_previous_worker_runs(api):
    call, _ = api
    agent_api._workers.add("risk")          # a closed session's worker, still running
    status, body = call("POST", "/recover", {"module": "risk"})
    assert status == 409 and "still stopping" in body["detail"]
    status, body = call("POST", "/recover", {"module": "vendor"})   # it holds the port too
    assert status == 409 and "risk" in body["detail"]
    agent_api._workers.discard("risk")
    assert call("POST", "/recover", {"module": "risk"})[0] == 202


def test_a_worker_frees_its_module_when_it_ends(worker):
    agent_api._workers.add("risk")
    agent_api._do_recover("risk", None, 1, session_id=object())
    assert "risk" not in agent_api._workers


def test_a_module_is_not_promoted_twice_at_once(api, monkeypatch):
    call, _ = api
    agent_api._sessions["risk"] = {"status": "ready", "id": object(), "started_at": 0}
    entered, release = threading.Event(), threading.Event()

    def slow_promote(module):
        entered.set()
        release.wait(5)
        return {"ok": True, "dumped_bytes": 1}

    monkeypatch.setattr(agent_api, "_do_promote", slow_promote)
    monkeypatch.setattr(agent_api, "_promote_rate_limited", lambda: False)
    first = {}
    threading.Thread(target=lambda: first.update(r=call("POST", "/recover/risk/promote", {}))).start()
    assert entered.wait(5)
    status, body = call("POST", "/recover/risk/promote", {})
    assert status == 409 and "already being promoted" in body["detail"]
    release.set()
    for _ in range(50):
        if "r" in first:
            break
        threading.Event().wait(0.1)
    assert first["r"][0] == 200
    assert call("POST", "/recover/risk/promote", {})[0] == 200   # free again afterwards


def test_a_closed_session_still_stopping_is_not_offered_for_closing(api):
    call, _ = api
    agent_api._workers.add("risk")          # closed, its worker not finished yet
    status, body = call("POST", "/recover", {"module": "vendor"})
    assert status == 409 and "still stopping" in body["detail"] and "close it" not in body["detail"]
