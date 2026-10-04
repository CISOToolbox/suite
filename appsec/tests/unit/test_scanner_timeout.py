"""A scanner that times out leaves no process behind (BUG-79).

Opengrep forks workers (opengrep-cli, several opengrep-core); on timeout,
subprocess.run killed only the process it started and the workers went on
scanning for minutes. _run_scanner kills the scanner's whole process group."""
import os
import pathlib
import subprocess
import sys
import time

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from src import scanners  # noqa: E402
from src.scanners import _run_scanner  # noqa: E402


def _alive(pid: int) -> bool:
    """Running — a zombie (killed, not yet reaped by PID 1) counts as dead."""
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError, IndexError):   # gone while being read
        return False
    return state != "Z"


def _dies(pid: int) -> bool:
    """The kill is delivered asynchronously: give the process a moment."""
    for _ in range(20):
        if not _alive(pid):
            return True
        time.sleep(0.1)
    return False


@pytest.fixture(autouse=True)
def _not_stopping(monkeypatch):
    monkeypatch.setattr(scanners, "_STOPPING", False)


def test_a_timed_out_scanner_takes_its_workers_with_it(tmp_path):
    pidfile = tmp_path / "child.pid"
    # A "scanner" that starts a long-running worker, then waits for it.
    script = f"sleep 300 & echo $! > {pidfile}; wait"
    with pytest.raises(subprocess.TimeoutExpired):
        _run_scanner(["sh", "-c", script], timeout=1)
    assert _dies(int(pidfile.read_text())), "the scanner's worker survived the timeout"


def test_a_finished_scanner_returns_its_output():
    r = _run_scanner(["sh", "-c", "echo out; echo err >&2; exit 3"], timeout=5)
    assert (r.returncode, r.stdout, r.stderr) == (3, "out\n", "err\n")


def test_a_process_holding_the_pipes_does_not_block_the_timeout(tmp_path):
    """A process that left the group and holds stdout must not keep the
    timeout path waiting (it used to wait for the pipes to close)."""
    pidfile = tmp_path / "detached.pid"
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run_scanner(["sh", "-c", f"setsid sleep 6 & echo $! > {pidfile}; sleep 100"], timeout=1)
    assert time.monotonic() - started < 4
    os.kill(int(pidfile.read_text()), 9)   # outside the group by design: not ours to leave behind


def test_shutdown_stops_the_running_scanners(tmp_path):
    import threading
    pidfile = tmp_path / "child.pid"
    cmd = ["sh", "-c", f"sleep 300 & echo $! > {pidfile}; wait"]
    t = threading.Thread(target=lambda: _run_scanner(cmd, timeout=60))
    t.start()
    for _ in range(50):
        if scanners._RUNNING_SCANNERS and pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.1)
    assert scanners.stop_running_scanners() == 1
    t.join(5)
    assert not t.is_alive(), "the scan did not return after the shutdown"
    assert _dies(int(pidfile.read_text()))


def test_a_scanner_started_after_shutdown_is_killed_at_once():
    """The shutdown hook cannot see a scanner started during or after it
    (the next scanner of a sequential scan): it is killed on start."""
    scanners.stop_running_scanners()
    started = time.monotonic()
    r = _run_scanner(["sh", "-c", "sleep 300"], timeout=60)
    assert r.returncode == -9 and time.monotonic() - started < 4


def test_any_other_exception_kills_the_group(tmp_path, monkeypatch):
    pidfile = tmp_path / "child.pid"
    def interrupted(self, timeout=None):
        for _ in range(50):
            if pidfile.exists() and pidfile.read_text().strip():
                break
            time.sleep(0.1)
        raise KeyboardInterrupt
    monkeypatch.setattr(subprocess.Popen, "communicate", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _run_scanner(["sh", "-c", f"sleep 300 & echo $! > {pidfile}; wait"], timeout=60)
    assert _dies(int(pidfile.read_text()))
