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
    registries = [getattr(agent_api, n) for n in ("_sessions", "_workers", "_stopping", "_promotions",
                                                  "_promote_history")
                  if isinstance(getattr(agent_api, n, None), (dict, set, list))]
    for registry in registries:
        registry.clear()
    yield
    for registry in registries:
        registry.clear()


# ── promotion ────────────────────────────────────────────────────────────


class _Pipe:
    def __init__(self, data):
        self.data = data

    def close(self):
        pass


class _Proc:
    def __init__(self, rc, stdout=None):
        self.returncode, self.stdout = rc, stdout

    def wait(self):
        return self.returncode


class Cluster:
    """Databases by name -> content (and comment); psql/pg_dump answered from it.

    Install with `cluster.install(monkeypatch)`: both the one-shot commands
    (subprocess.run) and the dump piped into psql (subprocess.Popen)."""

    def __init__(self, fail_load=False, fail_rename=False, fail_dump=False, fail_list=False,
                 fail_drop_side=False):
        self.dbs = {"postgres": "", "risk": "live data"}
        self.comments: dict = {}
        self.fail_load, self.fail_rename = fail_load, fail_rename
        self.fail_dump, self.fail_list = fail_dump, fail_list
        self.fail_drop_side = fail_drop_side
        self.drops = 0

    def install(self, monkeypatch):
        monkeypatch.setattr(agent_api.subprocess, "run", self.run)
        monkeypatch.setattr(agent_api.subprocess, "Popen", self.popen)

    def popen(self, cmd, stdin=None, stdout=None, stderr=None, **kw):
        if cmd[0] == "pg_dump":
            if self.fail_dump:   # stops half-way: psql still gets a complete-looking input
                stderr.write(b"pg_dump: error: connection to server lost")
                return _Proc(1, _Pipe("half of the restored data"))
            # psql stopping on an error closes the pipe: pg_dump dies of SIGPIPE.
            return _Proc(-13 if self.fail_load else 0, _Pipe("restored data"))
        assert "--single-transaction" in cmd
        if self.fail_load:
            stderr.write(b"ERROR: syntax error")
            return _Proc(3)
        self.dbs[cmd[cmd.index("-d") + 1]] = stdin.data
        return _Proc(0)

    def run(self, cmd, input=None, **kw):
        assert cmd[0] != "pg_dump", "the dump is streamed into psql, never held in memory"
        target = cmd[cmd.index("-d") + 1]
        if "-tAc" in cmd:
            sql = cmd[cmd.index("-tAc") + 1]
            assert ";" not in sql, "one statement per command: no implicit transaction"
            if m := re.fullmatch(r"SELECT 1 FROM pg_database WHERE datname = '(\w+)'", sql):
                if self.fail_list:
                    return _Done(rc=2, err="psql: error: connection to server failed")
                return _Done(out="1" if m.group(1) in self.dbs else "")
            if m := re.fullmatch(r"SELECT shobj_description\(oid, 'pg_database'\) FROM pg_database "
                                 r"WHERE datname = '(\w+)'", sql):
                return _Done(out=self.comments.get(m.group(1), ""))
            if m := re.fullmatch(r"COMMENT ON DATABASE (\w+) IS '([^']*)'", sql):
                self.comments[m.group(1)] = m.group(2)
                return _Done()
            if m := re.fullmatch(r"SELECT pg_database_size\('(\w+)'\)", sql):
                return _Done(out=str(len(self.dbs[m.group(1)])))
            if m := re.fullmatch(r"DROP DATABASE (IF EXISTS )?(\w+) WITH \(FORCE\)", sql):
                if m.group(2) not in self.dbs and not m.group(1):
                    return _Done(rc=1, err=f'database "{m.group(2)}" does not exist')
                if m.group(2) == "risk_restore" and self.fail_drop_side:
                    self.drops += 1
                    if self.drops > 1:   # the first, before creating it, succeeds
                        return _Done(rc=1, err="database is being accessed by other users")
                self.dbs.pop(m.group(2), None)
                self.comments.pop(m.group(2), None)
                return _Done()
            if m := re.fullmatch(r"CREATE DATABASE (\w+) OWNER \w+", sql):
                self.dbs[m.group(1)] = ""
                return _Done()
            if m := re.fullmatch(r"ALTER DATABASE (\w+) RENAME TO (\w+)", sql):
                if self.fail_rename:
                    return _Done(rc=1, err="rename refused")
                self.dbs[m.group(2)] = self.dbs.pop(m.group(1))
                if m.group(1) in self.comments:
                    self.comments[m.group(2)] = self.comments.pop(m.group(1))
                return _Done()
            raise AssertionError(f"unexpected SQL: {sql}")
        raise AssertionError(f"unexpected command on '{target}': {cmd}")


def test_promote_replaces_the_live_database_with_the_restored_data(monkeypatch):
    c = Cluster()
    c.install(monkeypatch)
    agent_api._do_promote("risk")
    assert c.dbs["risk"] == "restored data" and "risk_restore" not in c.dbs


def test_a_failed_load_leaves_the_live_database_untouched(monkeypatch):
    c = Cluster(fail_load=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="live database untouched"):
        agent_api._do_promote("risk")
    assert c.dbs["risk"] == "live data" and "risk_restore" not in c.dbs


def test_an_interrupted_swap_is_reported_and_finished_by_the_next_promote(monkeypatch):
    c = Cluster(fail_rename=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="LIVE DATABASE DROPPED.*risk_restore"):
        agent_api._do_promote("risk")
    c.fail_rename = False
    agent_api._do_promote("risk")
    assert c.dbs["risk"] == "restored data" and "risk_restore" not in c.dbs


def test_the_dump_is_streamed_into_the_side_database(monkeypatch):
    # Cluster.run refuses a pg_dump: its whole output would sit in memory.
    c = Cluster()
    c.install(monkeypatch)
    agent_api._do_promote("risk", "s1", "2026-10-26 17:00:00+00")
    assert c.dbs["risk"] == "restored data"


def test_a_dump_that_stops_half_way_is_never_promoted(monkeypatch):
    c = Cluster(fail_dump=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="live database untouched.*pg_dump failed.*connection"):
        agent_api._do_promote("risk", "s1", "2026-10-26 17:00:00+00")
    assert c.dbs["risk"] == "live data" and "risk_restore" not in c.dbs


def test_a_load_error_is_reported_rather_than_the_dump_it_cut_short(monkeypatch):
    c = Cluster(fail_load=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError) as e:
        agent_api._do_promote("risk", "s1", "2026-10-26 17:00:00+00")
    assert "syntax error" in str(e.value) and "pg_dump failed" not in str(e.value)


def test_an_incomplete_copy_is_never_labelled_as_the_restore(monkeypatch):
    c = Cluster(fail_dump=True, fail_drop_side=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="could not be dropped"):
        agent_api._do_promote("risk", "s1", "2026-10-26 17:00:00+00")
    # The incomplete copy stayed: it must not carry the label a later
    # promotion of the same instant would finish the swap with.
    assert "risk_restore" in c.dbs and "risk_restore" not in c.comments


def _interrupted(monkeypatch, session, time):
    """A promotion of (session, time) whose swap stopped after the drop."""
    c = Cluster(fail_rename=True)
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="LIVE DATABASE DROPPED"):
        agent_api._do_promote("risk", session, time)
    c.fail_rename = False
    return c


def test_a_swap_is_finished_only_for_the_restore_it_belongs_to(monkeypatch):
    c = _interrupted(monkeypatch, "s1", "2026-10-26 17:00:00+00")
    with pytest.raises(RuntimeError, match="holds another restore.*nothing was changed"):
        agent_api._do_promote("risk", "s2", "2026-10-26 18:00:00+00")
    assert "risk" not in c.dbs and c.dbs["risk_restore"] == "restored data"


def test_a_swap_is_finished_by_a_session_reopened_at_the_same_instant(monkeypatch):
    # The agent restarted after the interruption: a new session, same instant.
    c = _interrupted(monkeypatch, "s1", "2026-10-26 17:00:00+00")
    assert agent_api._do_promote("risk", "s2", "2026-10-26 17:00:00+00")["resumed"]
    assert c.dbs["risk"] == "restored data" and "risk_restore" not in c.dbs


def test_latest_is_not_an_instant_a_new_session_could_match(monkeypatch):
    c = _interrupted(monkeypatch, "s1", None)
    with pytest.raises(RuntimeError, match="holds another restore"):
        agent_api._do_promote("risk", "s2", None)
    assert agent_api._do_promote("risk", "s1", None)["resumed"]
    assert c.dbs["risk"] == "restored data"


def test_an_unreadable_database_list_is_not_taken_for_a_missing_database(monkeypatch):
    c = Cluster(fail_list=True)
    c.dbs["risk_restore"] = "an older restore"
    c.install(monkeypatch)
    with pytest.raises(RuntimeError, match="could not read the database list"):
        agent_api._do_promote("risk", "s1", "2026-10-26 17:00:00+00")
    assert c.dbs["risk"] == "live data" and c.dbs["risk_restore"] == "an older restore"


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


def test_the_reason_a_restore_failed_is_kept(worker, monkeypatch):
    # pgBackRest prints its progress before the error: the error must survive
    # the length limit of the session message.
    info = "\n".join(f"2026-11-03 10:00:{i % 60:02d}.000 P00   INFO: restore file /pg/risk/base/{i}"
                     for i in range(40))
    monkeypatch.setattr(agent_api, "_pgbackrest", lambda *a: _Done(
        rc=1, err="2026-11-03 10:00:00.000 P00   INFO: restore command begin\n"
                  "2026-11-03 10:00:00.100 P00  ERROR: [075]: no backup set found to restore\n",
        out=info))
    sid = object()
    agent_api._sessions["risk"] = {"status": "preparing", "id": sid, "started_at": 0}
    agent_api._do_recover("risk", None, 1, session_id=sid)
    s = agent_api._sessions["risk"]
    assert s["status"] == "error" and "no backup set found to restore" in s["error"]
    assert "INFO:" not in s["error"]


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
    """The real handler on a local port; restore workers are not started,
    promotion workers run (on whatever `_do_promote` the test installs)."""
    started = []
    monkeypatch.setattr(agent_api, "_window", lambda repo=1: {})
    real_thread = threading.Thread

    # The agent's own view of threading only: the HTTP server needs the real one.
    # A started restore worker is taken as finished at once (it frees its module).
    class Thread:
        def __init__(self, target, args, daemon):
            self.target, self.a = target, args

        def start(self):
            if self.target is agent_api._do_recover:
                started.append(self.a)
                agent_api._workers.discard(self.a[0])
            else:
                real_thread(target=self.target, args=self.a, daemon=True).start()
    monkeypatch.setattr(agent_api, "threading", types.SimpleNamespace(Thread=Thread))
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


def _wait_for(call, path, state, tries=50):
    for _ in range(tries):
        status, body = call("GET", path)
        if status == 200 and body["state"] == state:
            return body
        threading.Event().wait(0.1)
    raise AssertionError(f"{path} never reached {state}: {status} {body}")


@pytest.fixture
def slow_promote(monkeypatch):
    """A promotion that holds until released; the rate limit is out of the way."""
    entered, release = threading.Event(), threading.Event()

    def promote(module, session_id="", target_time=None):
        entered.set()
        release.wait(5)
        return {"ok": True, "size_bytes": 1}
    monkeypatch.setattr(agent_api, "_do_promote", promote)
    monkeypatch.setattr(agent_api, "_promote_rate_limited", lambda: False)
    yield entered, release
    release.set()


def test_a_module_is_not_promoted_twice_at_once(api, slow_promote, capsys):
    call, _ = api
    entered, release = slow_promote
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0}
    status, body = call("POST", "/recover/risk/promote", {"session": "s1"})
    assert status == 202 and body["state"] == "running"
    assert entered.wait(5)
    status, body = call("POST", "/recover/risk/promote", {"session": "s1"})
    assert status == 409 and "already being promoted" in body["detail"]
    assert "action=promote-concurrent module=risk" in capsys.readouterr().out
    release.set()
    assert _wait_for(call, "/recover/risk/promote", "done")["result"]["ok"]
    # Free again — for a new session: this one is spent.
    agent_api._sessions["risk"] = {"status": "ready", "id": "s2", "started_at": 0}
    assert call("POST", "/recover/risk/promote", {"session": "s2"})[0] == 202


def test_a_promotion_runs_in_the_background_and_reports_its_outcome(api, slow_promote, monkeypatch):
    call, _ = api
    entered, release = slow_promote
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "time": "2026-10-26 17:00:00+00",
                                   "started_at": 0}
    assert call("POST", "/recover/risk/promote", {"session": "s1"})[0] == 202
    assert entered.wait(5)
    status, body = call("GET", "/recover/risk/promote")
    assert status == 200 and body["state"] == "running" and body["time"] == "2026-10-26 17:00:00+00"
    release.set()
    _wait_for(call, "/recover/risk/promote", "done")

    def failing(module, session_id="", target_time=None):
        raise RuntimeError("live database untouched — loading the restored data failed: boom")
    monkeypatch.setattr(agent_api, "_do_promote", failing)
    agent_api._sessions["risk"] = {"status": "ready", "id": "s2", "started_at": 0}
    assert call("POST", "/recover/risk/promote", {"session": "s2"})[0] == 202
    assert "boom" in _wait_for(call, "/recover/risk/promote", "failed")["error"]
    # A failed promotion left the live database untouched: it may be retried.
    assert agent_api._sessions["risk"]["status"] == "ready"


def test_a_session_is_promoted_once(api, slow_promote):
    call, _ = api
    entered, release = slow_promote
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0}
    release.set()
    assert call("POST", "/recover/risk/promote", {"session": "s1"})[0] == 202
    _wait_for(call, "/recover/risk/promote", "done")
    assert call("GET", "/recover/risk")[1]["status"] == "promoted"
    for body in ({"session": "s1"}, {}):      # named or not
        status, out = call("POST", "/recover/risk/promote", body)
        assert status == 409 and "already restored from this session" in out["detail"]


def test_a_promotion_names_its_session_and_a_changed_one_is_refused(api, slow_promote):
    call, _ = api
    status, body = call("POST", "/recover", {"module": "risk", "time": "2026-10-26 17:00:00"})
    assert status == 202 and body["session"]
    mine = body["session"]
    agent_api._sessions["risk"]["status"] = "ready"
    assert call("GET", "/recover/risk")[1]["session"] == mine
    # Another admin reopens the module at another instant.
    agent_api._sessions["risk"]["id"] = "theirs"
    status, body = call("POST", "/recover/risk/promote", {"session": mine})
    assert status == 409 and "session changed" in body["detail"]
    assert "risk" not in agent_api._promotions


def test_closing_a_named_session_leaves_a_newer_one_open(api):
    call, _ = api
    agent_api._sessions["risk"] = {"status": "ready", "id": "theirs", "started_at": 0}
    status, body = call("DELETE", "/recover/risk?session=mine")
    assert status == 409 and "session changed" in body["detail"]
    assert agent_api._sessions["risk"]["id"] == "theirs"
    assert call("DELETE", "/recover/risk?session=theirs")[0] == 200
    assert "risk" not in agent_api._sessions


def test_a_session_being_promoted_is_neither_closed_nor_replaced(api, slow_promote):
    call, _ = api
    entered, _release = slow_promote
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0}
    assert call("POST", "/recover/risk/promote", {"session": "s1"})[0] == 202
    assert entered.wait(5)
    for method, path, body in (("DELETE", "/recover/risk", None),
                               ("POST", "/recover", {"module": "risk"})):
        status, out = call(method, path, body)
        assert status == 409 and "being promoted" in out["detail"], (method, path)
    assert agent_api._sessions["risk"]["id"] == "s1"


@pytest.mark.parametrize("given, expected", [("2026-10-26 23:58Z", "2026-10-26 23:58:00+00"),
                                             ("2026-10-26T23:58+02:00", "2026-10-26 23:58:00+02:00"),
                                             ("2026-10-26 23:58", "2026-10-26 23:58:00+00")])
def test_seconds_are_added_before_an_offset_too(api, given, expected):
    call, started = api
    assert call("POST", "/recover", {"module": "risk", "time": given})[0] == 202
    assert started[-1][1] == expected


# ── reaper and rate limit ────────────────────────────────────────────────


def _reap_once(monkeypatch, now):
    """One pass of the real reaper loop, at `now`."""
    ticks = iter([None])

    def sleep(_):
        if next(ticks, "stop") == "stop":
            raise StopIteration
    monkeypatch.setattr(agent_api, "_time", types.SimpleNamespace(time=lambda: now, sleep=sleep))
    with pytest.raises(StopIteration):
        agent_api._reaper()


def test_the_reaper_leaves_a_session_reopened_while_it_cleans_alone(monkeypatch):
    fresh = {"status": "preparing", "id": "fresh", "started_at": 10_000}

    def cleanup(module):        # the module is reopened while the expired one is cleaned
        agent_api._sessions[module] = fresh
    monkeypatch.setattr(agent_api, "_cleanup", cleanup)
    agent_api._sessions["risk"] = {"status": "ready", "id": "old", "started_at": 0, "touched_at": 0}
    _reap_once(monkeypatch, now=10_000)
    assert agent_api._sessions.get("risk") is fresh


def test_the_reaper_does_not_expire_a_session_being_promoted(monkeypatch):
    cleaned = []
    monkeypatch.setattr(agent_api, "_cleanup", cleaned.append)
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0, "touched_at": 0}
    monkeypatch.setattr(agent_api, "_promotions", {"risk": {
        "state": "running", "session": "s1", "time": None, "started_at": 0}}, raising=False)
    _reap_once(monkeypatch, now=10_000)
    assert "risk" in agent_api._sessions and cleaned == []


def test_the_promote_rate_limit_holds_the_lock(monkeypatch):
    held = []

    class Lock:
        def __enter__(self):
            held.append(True)

        def __exit__(self, *exc):
            return False
    monkeypatch.setattr(agent_api, "_lock", Lock())
    monkeypatch.setattr(agent_api, "_promote_history", [])
    assert agent_api._promote_rate_limited() is False
    assert held and len(agent_api._promote_history) == 1


def test_a_closed_session_still_stopping_is_not_offered_for_closing(api):
    call, _ = api
    agent_api._workers.add("risk")          # closed, its worker not finished yet
    status, body = call("POST", "/recover", {"module": "vendor"})
    assert status == 409 and "still stopping" in body["detail"] and "close it" not in body["detail"]


def test_a_throttled_promote_keeps_the_previous_outcome(api, monkeypatch):
    call, _ = api
    monkeypatch.setattr(agent_api, "_promote_rate_limited", lambda: True)
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0}
    agent_api._promotions["risk"] = {"state": "done", "session": "s1", "time": None,
                                     "started_at": 0, "finished_at": 1, "result": {"ok": True}}
    assert call("POST", "/recover/risk/promote", {"session": "s1"})[0] == 429
    status, body = call("GET", "/recover/risk/promote")
    assert status == 200 and body["state"] == "done"


def test_closing_does_not_hold_the_lock_while_the_instance_stops(api, monkeypatch):
    call, _ = api
    free = []

    def cleanup(module):
        got = agent_api._lock.acquire(blocking=False)
        free.append(got)
        if got:
            agent_api._lock.release()
    monkeypatch.setattr(agent_api, "_cleanup", cleanup)
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0}
    assert call("DELETE", "/recover/risk?session=s1")[0] == 200
    assert free == [True] and "risk" not in agent_api._sessions


def _lock_is_free() -> bool:
    got = agent_api._lock.acquire(blocking=False)
    if got:
        agent_api._lock.release()
    return got


def test_a_failed_worker_stops_its_instance_outside_the_lock(worker, monkeypatch):
    free = []
    # Outside the lock, and with the module still held by the worker.
    monkeypatch.setattr(agent_api, "_cleanup",
                        lambda m: free.append(_lock_is_free() and m in agent_api._workers))
    agent_api._workers.add("risk")
    monkeypatch.setattr(agent_api, "_pgbackrest", lambda *a: _Done(rc=1, err="ERROR: [058] boom"))
    agent_api._sessions["risk"] = {"status": "preparing", "id": "s1", "started_at": 0}
    agent_api._do_recover("risk", None, 1, session_id="s1")
    assert agent_api._sessions["risk"]["status"] == "error"
    assert free == [True, True]   # start-up cleanup, then the failed instance


def test_the_reaper_stops_instances_outside_the_lock(monkeypatch):
    free = []
    monkeypatch.setattr(agent_api, "_cleanup", lambda m: free.append(_lock_is_free()))
    agent_api._sessions["risk"] = {"status": "ready", "id": "s1", "started_at": 0, "touched_at": 0}
    _reap_once(monkeypatch, now=10_000)
    assert free == [True] and "risk" not in agent_api._sessions


def test_a_module_being_stopped_cannot_be_reopened_nor_closed_twice(api, monkeypatch):
    call, _ = api
    cleaned = []
    monkeypatch.setattr(agent_api, "_cleanup", cleaned.append)
    monkeypatch.setattr(agent_api, "_stopping", {"risk"}, raising=False)   # closed, still stopping
    status, body = call("POST", "/recover", {"module": "risk"})
    assert status == 409 and "still stopping" in body["detail"]
    status, body = call("POST", "/recover", {"module": "vendor"})   # it holds the port too
    assert status == 409 and "risk" in body["detail"]
    status, body = call("DELETE", "/recover/risk")
    assert status == 200 and body.get("gone") and cleaned == []


def test_a_promoted_session_expires_like_the_others(monkeypatch):
    cleaned = []
    monkeypatch.setattr(agent_api, "_cleanup", cleaned.append)
    agent_api._sessions["risk"] = {"status": "promoted", "id": "s1", "started_at": 0, "touched_at": 0}
    _reap_once(monkeypatch, now=10_000)
    assert "risk" not in agent_api._sessions and cleaned == ["risk"]


def test_a_promoted_session_still_holds_the_port(api):
    call, _ = api
    agent_api._sessions["risk"] = {"status": "promoted", "id": "s1", "started_at": 0}
    status, body = call("POST", "/recover", {"module": "vendor"})
    assert status == 409 and "already open for 'risk'" in body["detail"]
