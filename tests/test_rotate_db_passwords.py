"""Lock how tools/rotate-db-passwords.sh waits for a database and what it reports.

No container engine is used: `docker` and `sleep` are stubs placed first on
PATH. The `docker` stub answers the few calls the script makes from what the
test sets in its environment (when the database leaves recovery, when its
container restarts, whether it already takes the password) and records every
call, so each case is checked on what the script did, not on how it did it.
"""
import os
import pathlib
import subprocess

import pytest

SUITE = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = SUITE / "tools" / "rotate-db-passwords.sh"

DOCKER_STUB = r"""#!/usr/bin/env bash
d="$STUB_DIR"
printf '%s\n' "$*" >> "$d/calls"
count() { local n; n=$(( $(cat "$d/$1" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$d/$1"; echo "$n"; }
if [ "$1" = inspect ]; then
    n=$(count inspect)
    case " ${INSPECT_FAILS:-} " in *" $n "*) exit 1 ;; esac
    if [ "${RESTART_AFTER:--1}" -ge 0 ] && [ "$n" -gt "$RESTART_AFTER" ]; then
        echo "1 2026-11-03T10:01:00Z"
    else
        echo "0 2026-11-03T10:00:00Z"
    fi
    exit 0
fi
[ "$1" = compose ] || exit 1
shift
case "$1" in
    config) printf 'DB_PASSWORD=abc123\nDB_PASSWORD_RISK=abc123\n' ;;
    ps) case "$*" in
            *--status*)
                n=$(count running)
                case " ${NOT_RUNNING_AT:-} " in *" $n "*) ;; *) [ "${NOT_RUNNING:-0}" = 1 ] || echo cid123 ;; esac ;;
            *) echo cid123 ;;
        esac ;;
    # As a real one: the connections refused while the next life replays
    # (healthcheck, the script's own psql) log FATAL lines after the reason,
    # and the container keeps the log of an earlier restore attempt, which
    # only a call without --since gets back.
    logs)
        case "$*" in *--since*) ;; *) printf '%s\n' \
            'risk-db-1  | 2026-11-03 09:00:02.000 UTC [27] FATAL:  recovery ended before configured recovery target was reached' \
            'risk-db-1  | 2026-11-03 09:00:02.000 UTC [1] LOG:  startup process (PID 27) exited with exit code 1' ;;
        esac
        case "${REASON:-beyond}" in
            beyond) reason='FATAL:  recovery ended before configured recovery target was reached' ;;
            early) reason='FATAL:  requested recovery stop point is before consistent recovery point' ;;
            panic) reason='PANIC:  could not locate a valid checkpoint record' ;;
            none) reason='LOG:  received fast shutdown request' ;;
        esac
        printf '%s\n' \
            'risk-db-1  | 2026-11-03 10:00:01.000 UTC [1] LOG:  starting PostgreSQL 16' \
            'risk-db-1  | 2026-11-03 10:00:01.500 UTC [30] FATAL:  the database system is starting up' \
            "risk-db-1  | 2026-11-03 10:00:02.000 UTC [27] $reason" \
            'risk-db-1  | 2026-11-03 10:00:02.000 UTC [1] LOG:  startup process (PID 27) exited with exit code 1' \
            ${AFTER_REASON:+"risk-db-1  | 2026-11-03 10:00:02.500 UTC [33] $AFTER_REASON"} \
            'risk-db-1  | 2026-11-03 10:00:03.000 UTC [1] LOG:  starting PostgreSQL 16' \
            'risk-db-1  | 2026-11-03 10:00:04.000 UTC [41] FATAL:  the database system is starting up' \
            'risk-db-1  | 2026-11-03 10:00:05.000 UTC [44] FATAL:  the database system is not yet accepting connections' \
            'risk-db-1  | 2026-11-03 10:00:06.000 UTC [47] FATAL:  the database system is starting up' ;;
    up) ;;
    exec)
        svc="$3"; shift 3
        case "$svc:$*" in
            *-db:*pg_is_in_recovery*)
                n=$(count ready)
                if [ "${READY_AFTER:-0}" -ge 0 ] && [ "$n" -gt "${READY_AFTER:-0}" ]; then echo t; else echo f; fi ;;
            *-db:psql\ -q*) cat > "$d/alter" ;;
            *-db:sh\ -c*) cat > /dev/null; [ "${HAS_PW:-0}" = 1 ] ;;
            backup-agent:*) cat > /dev/null 2>&1; exit 0 ;;
            *) exit 1 ;;
        esac ;;
    *) exit 1 ;;
esac
"""


@pytest.fixture
def run(tmp_path):
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "docker").write_text(DOCKER_STUB)
    (stubs / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for f in stubs.iterdir():
        f.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()

    def call(*args, timeout=30, **env):
        full_env = {"PATH": f"{stubs}:{os.environ['PATH']}", "HOME": str(tmp_path),
                    "STUB_DIR": str(state), **{k: str(v) for k, v in env.items()}}
        try:
            r = subprocess.run(["bash", str(SCRIPT), "--project-dir", str(tmp_path), *args],
                               capture_output=True, text=True, env=full_env, timeout=timeout,
                               stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the script was still waiting after {timeout}s")
        calls = (state / "calls").read_text() if (state / "calls").exists() else ""
        return r, calls, (state / "alter").exists()
    return call


def test_a_database_restarting_during_the_replay_stops_the_wait(run):
    # Restored to a point beyond the archived WAL: PostgreSQL dies, its
    # restart policy starts it again, and it would replay forever.
    r, _, altered = run("--after-restore", "risk", READY_AFTER=-1, RESTART_AFTER=3, timeout=20)
    assert r.returncode == 1
    assert "restarted" in r.stderr
    assert "recovery ended before configured recovery target was reached" in r.stderr
    assert "earlier one" in r.stderr
    assert "starting up" not in r.stderr and "not yet accepting" not in r.stderr
    assert not altered


def test_an_earlier_attempt_s_reason_is_not_this_one(run):
    # First restore too late, second too early: the log still holds the
    # first one's line, and advising an even earlier point would be wrong.
    r, _, _ = run("--after-restore", "risk", READY_AFTER=-1, RESTART_AFTER=3, REASON="early", timeout=20)
    assert r.returncode == 1
    assert "requested recovery stop point is before consistent recovery point" in r.stderr
    assert "recovery ended" not in r.stderr and "earlier one" not in r.stderr


def test_another_reason_is_shown_past_the_refused_connections(run):
    r, _, _ = run("--after-restore", "risk", READY_AFTER=-1, RESTART_AFTER=3, REASON="panic", timeout=20)
    assert r.returncode == 1
    assert "PANIC:  could not locate a valid checkpoint record" in r.stderr
    assert "starting up" not in r.stderr and "earlier one" not in r.stderr


def test_the_recovery_target_reason_wins_over_a_later_fatal_line(run):
    # Hot standby lets clients in once consistent: an app on the old password
    # logs its failed login after the reason.
    r, _, _ = run("--after-restore", "risk", READY_AFTER=-1, RESTART_AFTER=3,
                  AFTER_REASON='FATAL:  password authentication failed for user "risk"', timeout=20)
    assert r.returncode == 1
    assert "recovery ended before configured recovery target was reached" in r.stderr
    assert "earlier one" in r.stderr and "password authentication" not in r.stderr


def test_a_log_without_reason_points_to_the_log(run):
    r, _, _ = run("--after-restore", "risk", READY_AFTER=-1, RESTART_AFTER=3, REASON="none", timeout=20)
    assert r.returncode == 1 and "docker compose logs risk-db" in r.stderr
    assert "its log:" not in r.stderr


def test_one_failed_running_check_does_not_stop_the_wait(run):
    r, _, altered = run("--after-restore", "risk", READY_AFTER=3, NOT_RUNNING_AT="1")
    assert r.returncode == 0, r.stderr
    assert "not running" not in r.stderr and altered


def test_a_database_found_stopped_says_why(run):
    # A poll between its death and its next life finds it stopped.
    r, _, altered = run("--after-restore", "risk", READY_AFTER=-1, NOT_RUNNING=1, timeout=20)
    assert r.returncode == 1 and "is not running" in r.stderr
    assert "recovery ended before configured recovery target was reached" in r.stderr
    assert not altered


def test_an_unreadable_container_state_is_not_a_restart(run):
    # docker inspect failing once (the engine busy) must not end the wait.
    r, _, altered = run("--after-restore", "risk", READY_AFTER=4, INSPECT_FAILS="1 3")
    assert r.returncode == 0, r.stderr
    assert "restarted" not in r.stderr and altered


def test_the_time_limit_counts_real_time_not_loop_turns(run):
    # Every turn here is instant: 200 turns of "5 s" are far from 900 s of
    # real waiting, and the rotation must go on once the database is ready.
    r, calls, altered = run("risk", READY_AFTER=200)
    assert "after 900s" not in r.stderr, r.stderr
    assert altered and "password changed" in r.stdout


@pytest.mark.parametrize("flags", [["--after-restore", "--recovery-session"],
                                   ["--recovery-session", "--after-restore"]])
def test_two_modes_at_once_are_refused(run, flags):
    r, calls, altered = run(*flags, "risk")
    assert r.returncode == 2 and "exclusive" in r.stderr
    assert calls == "" and not altered


def test_a_password_already_right_is_not_reported_as_set(run):
    # The Ansible restore playbook marks the task changed on "password set".
    r, _, altered = run("--after-restore", "risk", HAS_PW=1)
    assert r.returncode == 0, r.stderr
    assert "password set" not in r.stdout and "already" in r.stdout
    assert not altered


def test_a_different_password_is_set(run):
    r, _, altered = run("--after-restore", "risk", HAS_PW=0)
    assert r.returncode == 0, r.stderr
    assert "password set" in r.stdout and altered
