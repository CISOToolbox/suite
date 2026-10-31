"""ciso-backup-agent — internal recovery API (FEAT-30 phase 2, étage 3).

Stdlib-only HTTP server (no framework, no pip deps in an infra container).
Listens on :9090 INSIDE the compose network — never published by nginx.
Every request must carry X-Agent-Token == BACKUP_AGENT_TOKEN.

Endpoints (JSON):
  GET    /window                    PITR coverage per module (backups, oldest full)
  POST   /recover                   {module, time?} → start a recovery session
  GET    /recover/<module>          session status (preparing|ready|error)
  POST   /recover/<module>/promote  N2: replace the LIVE db with the scratch state
                                    (caller must have taken a safety backup)
  DELETE /recover/<module>          stop + clean the scratch instance

Design constraints (same as the runbook):
  - The scratch instance NEVER touches the live PGDATA. It runs inside this
    container on port 5433 and listens on the compose network so the module
    apps can read it back through their own export code (fidelity) using
    their own credentials (the restored cluster carries the origin's users).
  - One session per module, TTL 30 min (extended by any touch).
  - promote goes through the postgres protocol only (pg_dump | psql via the
    live socket) — no container orchestration, no volume swap.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time as _time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("BACKUP_AGENT_TOKEN", "")
REPO = os.environ.get("PGBACKREST_REPO1_PATH", "/var/lib/pgbackrest")
CONF = f"{REPO}/agent/pgbackrest.conf"
MODULES = os.environ.get(
    "BACKUP_MODULES",
    "pilot risk vendor compliance asset audit access surface appsec watch").split()
SESSION_TTL = int(os.environ.get("RECOVERY_TTL_SECONDS", "1800"))
MOD_RE = re.compile(r"^[a-z]+$")

# Minimum length for the recovery token. It is the ONLY thing standing between
# any container on the compose network and `promote`, which drops and recreates
# a live database.
_MIN_TOKEN_LEN = 32
# Values shipped in .env.example. `setup.sh` replaces them; a deployment that
# skipped setup would otherwise run with a secret published in the repo, and
# the `${VAR:?}` guard in the compose file is happy with any non-empty string.
_PLACEHOLDERS = frozenset({
    "change-me",
    "change-me-generate-with-openssl-rand-hex-32",
})


def _reject_placeholder(name: str, value: str, min_len: int) -> str | None:
    """Return why `value` is unusable as a secret, or None if it is fine."""
    v = (value or "").strip()
    if not v:
        return f"{name} is not set"
    if v in _PLACEHOLDERS or v.startswith("change-me"):
        return (
            f"{name} still holds the placeholder from .env.example. That value "
            f"is public — anyone reading the repository knows it. "
            f"Generate one with: openssl rand -hex 32"
        )
    if len(v) < min_len:
        return f"{name} is too short ({len(v)} chars): minimum {min_len}"
    return None

_sessions: dict = {}          # module -> {status, time, error, started_at, touched_at}
# Modules with a restore worker still running, even when its session was
# closed: a new restore of the module must wait for it (pgBackRest locks the
# stanza, and both would use the same scratch directory).
_workers: set = set()
# Modules being promoted: a second promote of the same module while one runs
# would drop the database the first has just swapped in.
_promoting: set = set()
_lock = threading.Lock()

# Audit trail + rate limit for the destructive operations. This API can drop and
# recreate a live database, so every state-changing call is logged (UTC, action,
# module, caller) to stdout — captured by the container log — and `promote` is
# throttled: more than a handful in a short window is either a stuck client or a
# compromised token hammering the destructive path, never legitimate use.
_PROMOTE_MAX = 3
_PROMOTE_WINDOW_S = 300
_promote_history: list = []   # recent promote timestamps (any module)


def _audit(action: str, module: str, client: str, extra: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[audit] {ts} action={action} module={module} client={client} {extra}".rstrip(),
          flush=True)


def _promote_rate_limited() -> bool:
    """True if the recent promote rate is over budget. Prunes old entries."""
    now = _time.time()
    _promote_history[:] = [t for t in _promote_history if now - t < _PROMOTE_WINDOW_S]
    if len(_promote_history) >= _PROMOTE_MAX:
        return True
    _promote_history.append(now)
    return False


def _scratch(module: str) -> str:
    return f"/tmp/restore-data-{module}"


def _sockdir(module: str) -> str:
    return f"/tmp/restore-{module}"


def _pgbackrest(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PGBACKREST_CONFIG=CONF)
    return subprocess.run(["pgbackrest", *args], capture_output=True, text=True, env=env)


def _pg_ctl(module: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["pg_ctl", "-D", _scratch(module), *args],
                          capture_output=True, text=True)


def _cleanup(module: str) -> None:
    if os.path.exists(f"{_scratch(module)}/postmaster.pid"):
        _pg_ctl(module, "stop", "-m", "fast")
    shutil.rmtree(_scratch(module), ignore_errors=True)
    shutil.rmtree(_sockdir(module), ignore_errors=True)


def _current(module: str, session_id: object) -> dict | None:
    """The session this worker belongs to, unless it was closed or replaced."""
    s = _sessions.get(module)
    return s if s is not None and s.get("id") is session_id else None


def _do_recover(module: str, target_time: str | None, repo: int = 1,
                session_id: object = None) -> None:
    try:
        _recover(module, target_time, repo, session_id)
    finally:
        with _lock:
            _workers.discard(module)


def _recover(module: str, target_time: str | None, repo: int, session_id: object) -> None:
    """Worker thread: pgbackrest restore into scratch + start on :5433.

    `repo` selects the repository (FEAT-29): 1 = local, 2 = off-site S3.
    After losing the host, only the second one still exists.
    """
    try:
        _cleanup(module)
        os.makedirs(_scratch(module), mode=0o700)
        os.makedirs(_sockdir(module), exist_ok=True)
        args = ["--stanza", module, f"--repo={repo}", f"--pg1-path={_scratch(module)}"]
        if target_time:
            args += ["--type=time", f"--target={target_time}", "--target-action=promote"]
        r = _pgbackrest(*args, "restore")
        if r.returncode != 0:
            out = ((r.stderr or "") + (r.stdout or "")).strip()
            raise RuntimeError(f"pgbackrest restore failed: {out[-400:]}")
        # Listen on the compose network so module apps can read the state at T
        # with their own credentials (pg_hba/users restored from the origin).
        # NOTE 1: no shell quoting inside -o (pg_ctl passes it through system()).
        # NOTE 2: never LOWER resource parameters (max_connections, ...) below
        # the primary's values — recovery aborts with "insufficient parameter
        # settings" because the WAL was generated with the higher ones.
        opts = (f"-p 5433 -k {_sockdir(module)} -c listen_addresses=* "
                f"-c archive_mode=off")
        # Start WITHOUT -w: WAL replay from the archive can exceed any fixed
        # pg_ctl timeout (one 16 MB segment per archive_timeout minute of
        # history). Readiness is established by the psql poll below only.
        r = _pg_ctl(module, "-l", f"{_scratch(module)}/startup.log", "-o", opts, "start")
        if r.returncode != 0 and "already" not in (r.stderr or ""):
            tail = ""
            try:
                with open(f"{_scratch(module)}/startup.log") as f:
                    tail = f.read()[-400:]
            except OSError:
                pass
            raise RuntimeError(f"scratch start failed: {(r.stderr or r.stdout).strip()[-200:]} LOG: {tail}")
        # Wait for recovery to replay up to the target and promote. Stop as
        # soon as this session is no longer the module's (closed or replaced:
        # whatever answers on the socket then belongs to another session), and
        # fail as soon as the instance dies — pg_ctl was started without -w,
        # so a recovery that aborts (target beyond the archived WAL, …) would
        # otherwise look like a slow one for the whole deadline.
        deadline = _time.time() + 900
        down = 0
        while _time.time() < deadline:
            with _lock:
                if _current(module, session_id) is None:
                    break
            q = subprocess.run(
                ["psql", "-h", _sockdir(module), "-p", "5433", "-U", module,
                 "-d", module, "-tAc", "SELECT NOT pg_is_in_recovery()"],
                capture_output=True, text=True)
            if q.returncode == 0 and q.stdout.strip() == "t":
                break
            down = down + 1 if _pg_ctl(module, "status").returncode != 0 else 0
            if down >= 3:
                raise RuntimeError(f"the restored instance stopped during recovery. {_startup_tail(module)}")
            _time.sleep(2)
        else:
            raise RuntimeError(f"scratch did not finish recovery in time. {_startup_tail(module)}")
        with _lock:
            s = _current(module, session_id)
            if s is not None:
                s["status"] = "ready"
                s["touched_at"] = _time.time()
            else:
                _release_if_unclaimed(module)
    except Exception as e:  # noqa: BLE001 — surfaced through the session status
        with _lock:
            s = _current(module, session_id)
            if s is not None:
                s["status"] = "error"
                s["error"] = str(e)
                _cleanup(module)
            else:
                _release_if_unclaimed(module)


def _startup_tail(module: str) -> str:
    """Why the instance stopped: its FATAL/ERROR lines first, else the tail."""
    try:
        with open(f"{_scratch(module)}/startup.log") as f:
            log = f.read()
    except OSError:
        return ""
    reasons = [ln for ln in log.splitlines() if "FATAL:" in ln or "ERROR:" in ln or "PANIC:" in ln]
    return ("\n".join(reasons[-3:]) or log)[-500:]


def _release_if_unclaimed(module: str) -> None:
    """Called under _lock by a worker whose session was closed or replaced.

    The scratch directory, socket and port belong to the module, not to a
    session: if a newer session for the module exists, they are its own, and
    must be left alone. Only with no session at all does the late worker
    remove what it may have left running.
    """
    if module not in _sessions:
        _cleanup(module)


def _do_promote(module: str) -> dict:
    """N2: replace the live database with the scratch state.

    Postgres protocol only. The restored data is loaded into a side database
    first, in a single transaction; the live database is only dropped once
    that has fully succeeded, and the side one then takes its name. A failure
    before the swap leaves the live database untouched; a failure during it
    leaves the restored data in <module>_restore and says so, and promoting
    again finishes the swap. The caller (Pilot) is responsible for the safety
    backup and the double confirmation."""
    live_sock = f"/sock/{module}"
    side = f"{module}_restore"

    def sql(statement: str) -> subprocess.CompletedProcess:
        # One statement per call: DROP/CREATE DATABASE refuse to run inside a
        # transaction, which several statements in a single -c amount to.
        return subprocess.run(
            ["psql", "-h", live_sock, "-U", module, "-d", "postgres", "-v", "ON_ERROR_STOP=1",
             "-tAc", statement], capture_output=True, text=True)

    def exists(db: str) -> bool:
        r = sql(f"SELECT 1 FROM pg_database WHERE datname = '{db}'")
        return r.returncode == 0 and r.stdout.strip() == "1"

    # A previous attempt that dropped the live database but did not rename the
    # side one: finish it rather than start over.
    if not exists(module) and exists(side):
        r = sql(f"ALTER DATABASE {side} RENAME TO {module}")
        if r.returncode != 0:
            raise RuntimeError(f"live database missing; the restored data is in '{side}' "
                               f"but could not be renamed: {r.stderr.strip()[-300:]}")
        return {"ok": True, "resumed": True}

    dump = subprocess.run(
        ["pg_dump", "-h", _sockdir(module), "-p", "5433", "-U", module, module],
        capture_output=True, text=True)
    if dump.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {dump.stderr.strip()[-400:]}")
    for step in (f"DROP DATABASE IF EXISTS {side} WITH (FORCE)",
                 f"CREATE DATABASE {side} OWNER {module}"):
        r = sql(step)
        if r.returncode != 0:
            raise RuntimeError(f"live database untouched — preparing '{side}' failed: "
                               f"{r.stderr.strip()[-300:]}")
    load = subprocess.run(
        ["psql", "-h", live_sock, "-U", module, "-d", side, "-v", "ON_ERROR_STOP=1",
         "--single-transaction"],
        input=dump.stdout, capture_output=True, text=True)
    if load.returncode != 0:
        sql(f"DROP DATABASE IF EXISTS {side} WITH (FORCE)")
        raise RuntimeError(f"live database untouched — loading the restored data failed: "
                           f"{load.stderr.strip()[-300:]}")
    r = sql(f"DROP DATABASE {module} WITH (FORCE)")
    if r.returncode != 0:
        raise RuntimeError(f"live database untouched — it could not be dropped: "
                           f"{r.stderr.strip()[-300:]}; the restored data is in '{side}'")
    r = sql(f"ALTER DATABASE {side} RENAME TO {module}")
    if r.returncode != 0:
        raise RuntimeError(f"LIVE DATABASE DROPPED, the restored data is in '{side}' but could "
                           f"not be renamed: {r.stderr.strip()[-300:]} — finish by hand: docker "
                           f"compose exec {module}-db psql -U {module} -d postgres -c "
                           f"'ALTER DATABASE {side} RENAME TO {module}' (or promote again from "
                           f"the agent API; Pilot cannot, its safety backup needs the live database)")
    return {"ok": True, "dumped_bytes": len(dump.stdout)}

S3_ENABLED = os.environ.get("BACKUP_S3_ENABLED", "0") == "1"


def _window(repo: int = 1) -> dict:
    """Recovery window per stanza, for one repository.

    Both repositories hold the same backups but age independently: the
    off-site one can lag without anything failing visibly. Reporting them
    separately is what lets Pilot say "local fresh, off-site behind" rather
    than averaging the two into a reassuring half-truth.
    """
    out = {}
    for m in MODULES:
        r = _pgbackrest("--stanza", m, f"--repo={repo}", "info", "--output=json")
        entry = {"status": "unknown", "from": None, "to": None, "backups": []}
        try:
            info = json.loads(r.stdout)[0]
            entry["status"] = info.get("status", {}).get("message", "?")
            backups = info.get("backup") or []
            entry["backups"] = [{
                "label": b.get("label"),
                "type": b.get("type"),
                "start": b.get("timestamp", {}).get("start"),
                "stop": b.get("timestamp", {}).get("stop"),
            } for b in backups]
            if backups:
                entry["from"] = datetime.fromtimestamp(
                    backups[0]["timestamp"]["start"], tz=timezone.utc).isoformat()
                entry["to"] = datetime.now(timezone.utc).isoformat()
                for b in entry["backups"]:
                    for k in ("start", "stop"):
                        if isinstance(b[k], (int, float)):
                            b[k] = datetime.fromtimestamp(b[k], tz=timezone.utc).isoformat()
        except Exception:
            pass
        out[m] = entry
    return out


def _health() -> dict:
    """Backup freshness + last restore-test per stanza — consumed by the
    Pilot dashboard ("a backup only exists once it has been restored")."""
    now = datetime.now(timezone.utc)
    stanzas = {}
    win = _window()
    for m, entry in win.items():
        backups = entry.get("backups") or []
        last = backups[-1] if backups else None
        age_h = None
        if last and last.get("stop"):
            try:
                age_h = round((now - datetime.fromisoformat(last["stop"])).total_seconds() / 3600, 1)
            except (ValueError, TypeError):
                pass
        stanzas[m] = {
            "status": entry.get("status"),
            "last_backup": (last or {}).get("stop"),
            "last_backup_type": (last or {}).get("type"),
            "age_hours": age_h,
            # daily diff expected: stale beyond 26 h (cron slack included)
            "stale": age_h is None or age_h > 26,
        }
    rtest = None
    try:
        with open(f"{REPO}/agent/restore-test.json") as f:
            rtest = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass
    return {"updated_at": now.isoformat(), "stanzas": stanzas, "restore_test": rtest}


def _reaper() -> None:
    while True:
        _time.sleep(60)
        now = _time.time()
        with _lock:
            stale = [m for m, s in _sessions.items()
                     if s["status"] in ("ready", "error")
                     and now - s.get("touched_at", s["started_at"]) > SESSION_TTL]
        for m in stale:
            _cleanup(m)
            with _lock:
                _sessions.pop(m, None)
            print(f"[api] session {m} expired (TTL)", flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "ciso-backup-agent"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        import hmac
        tok = self.headers.get("X-Agent-Token", "")
        if not TOKEN or not tok or not hmac.compare_digest(tok, TOKEN):
            self._send(403, {"detail": "invalid agent token"})
            return False
        return True

    def log_message(self, fmt, *args):  # quiet default access log
        pass

    def do_GET(self):
        if not self._auth():
            return
        if self.path == "/window/2":
            if not S3_ENABLED:
                return self._send(404, {"detail": "no off-site repository configured"})
            return self._send(200, _window(2))
        if self.path == "/window":
            return self._send(200, _window())
        if self.path == "/health":
            return self._send(200, _health())
        m = re.fullmatch(r"/recover/([a-z]+)", self.path)
        if m:
            mod = m.group(1)
            with _lock:
                s = _sessions.get(mod)
            if not s:
                return self._send(404, {"detail": "no session"})
            with _lock:
                s["touched_at"] = _time.time()
            return self._send(200, {"module": mod, "status": s["status"],
                                    "time": s.get("time"), "error": s.get("error"),
                                    "port": 5433, "host": os.environ.get("AGENT_HOSTNAME", "backup-agent")})
        self._send(404, {"detail": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        if self.path == "/recover":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"detail": "invalid JSON"})
            mod = body.get("module", "")
            target_time = body.get("time") or None
            # Repository selection (FEAT-29). Validated as an int in {1,2}
            # rather than passed through: it reaches a command line, and
            # "whatever the client sent" has no business there.
            repo = body.get("repo", 1)
            if repo not in (1, 2):
                return self._send(400, {"detail": "repo must be 1 (local) or 2 (off-site)"})
            if repo == 2 and not S3_ENABLED:
                return self._send(400, {"detail": "no off-site repository configured"})
            if mod not in MODULES or not MOD_RE.match(mod):
                return self._send(400, {"detail": f"unknown module '{mod}'"})
            if target_time is not None:
                if not re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?([+-]\d{2}(:?\d{2})?|Z)?",
                        str(target_time)):
                    return self._send(400, {"detail": "invalid time format"})
                # pgBackRest wants "YYYY-MM-DD HH:MM:SS+00" — no ISO 'T'/'Z'.
                target_time = str(target_time).replace("T", " ").replace("Z", "+00")
                if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", target_time):
                    target_time += ":00"
                # No offset given: UTC, as everywhere else in the suite. Left
                # naive, it could not be compared with the window below.
                if not re.search(r"[+-]\d{2}(:?\d{2})?$", target_time):
                    target_time += "+00"
                # A real date and time, with its offset in the +HH:MM form
                # Python reads (+00, +0000 and +00:00 all mean the same).
                iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", target_time)
                iso = re.sub(r"([+-]\d{2})$", r"\1:00", iso)
                try:
                    tgt = datetime.fromisoformat(iso)
                except ValueError:
                    return self._send(400, {"detail": "invalid time"})
                # Clear refusal when T predates the PITR window (first full
                # backup) — pgBackRest's own error is cryptic here.
                win = _window(repo).get(mod) or {}
                if win.get("from"):
                    try:
                        if tgt < datetime.fromisoformat(win["from"]):
                            return self._send(400, {"detail":
                                f"target predates the PITR window (first backup: {win['from']})"})
                    except (ValueError, TypeError):
                        pass
            with _lock:
                cur = _sessions.get(mod)
                if cur and cur["status"] == "preparing":
                    return self._send(409, {"detail": "session already preparing"})
                if mod in _workers:
                    return self._send(409, {"detail":
                        f"the previous restore of '{mod}' is still stopping — retry in a moment"})
                # Every restored instance listens on the same port: a second
                # module's session could not start. Refuse it plainly.
                busy = sorted(m for m in set(_sessions) | _workers if m != mod and (
                    m in _workers or _sessions[m]["status"] in ("preparing", "ready")))
                if busy and busy[0] not in _sessions:
                    return self._send(409, {"detail":
                        f"the restore of '{busy[0]}' is still stopping — retry in a moment"})
                if busy:
                    return self._send(409, {"detail":
                        f"a restore session is already open for '{busy[0]}' — close it first"})
                _sessions[mod] = {"status": "preparing", "time": target_time,
                                  "repo": repo, "id": object(),
                                  "error": None, "started_at": _time.time(),
                                  "touched_at": _time.time()}
                session_id = _sessions[mod]["id"]
                _workers.add(mod)
            _audit("recover", mod, self.client_address[0],
                   f"target={target_time or 'latest'} repo={repo}")
            threading.Thread(target=_do_recover, args=(mod, target_time, repo, session_id),
                             daemon=True).start()
            return self._send(202, {"module": mod, "status": "preparing", "repo": repo})
        m = re.fullmatch(r"/recover/([a-z]+)/promote", self.path)
        if m:
            mod = m.group(1)
            with _lock:
                s = _sessions.get(mod)
            if not s or s["status"] != "ready":
                return self._send(409, {"detail": "no ready session for this module"})
            with _lock:
                if mod in _promoting:
                    return self._send(409, {"detail":
                        f"'{mod}' is already being promoted — wait for it to finish"})
                _promoting.add(mod)
            try:
                # Destructive: replaces the live DB. Throttle before touching it.
                if _promote_rate_limited():
                    _audit("promote-throttled", mod, self.client_address[0])
                    return self._send(429, {"detail": "promote rate limit exceeded — too many in a short window"})
                _audit("promote", mod, self.client_address[0])
                try:
                    result = _do_promote(mod)
                except Exception as e:  # noqa: BLE001
                    _audit("promote-failed", mod, self.client_address[0], f"error={str(e)[:120]}")
                    return self._send(500, {"detail": str(e)})
            finally:
                with _lock:
                    _promoting.discard(mod)
            _audit("promote-ok", mod, self.client_address[0], f"dumped_bytes={result.get('dumped_bytes')}")
            return self._send(200, result)
        self._send(404, {"detail": "not found"})

    def do_DELETE(self):
        if not self._auth():
            return
        m = re.fullmatch(r"/recover/([a-z]+)", self.path)
        if m:
            mod = m.group(1)
            _audit("cleanup", mod, self.client_address[0])
            _cleanup(mod)
            with _lock:
                _sessions.pop(mod, None)
            return self._send(200, {"ok": True})
        self._send(404, {"detail": "not found"})


def main() -> None:
    if not TOKEN:
        print("[api] BACKUP_AGENT_TOKEN not set — API disabled", flush=True)
        return
    # Fail closed on a placeholder or a weak secret rather than serve a
    # destructive API. Refusing to listen is the safe failure here: backups
    # keep running (agent.sh is a separate process), only recovery is off.
    problem = _reject_placeholder("BACKUP_AGENT_TOKEN", TOKEN, _MIN_TOKEN_LEN)
    if problem:
        print(f"[api] REFUSING TO START: {problem}", flush=True)
        raise SystemExit(1)
    # The repo passphrase is not ours to enforce at request time — pgBackRest
    # reads it directly — but this is the one process that can see it and warn
    # before a backup is written under a passphrase everyone knows.
    cipher = os.environ.get("PGBACKREST_REPO1_CIPHER_PASS", "")
    cipher_problem = _reject_placeholder("BACKUP_CIPHER_PASS", cipher, _MIN_TOKEN_LEN)
    if cipher_problem:
        print(f"[api] REFUSING TO START: {cipher_problem}", flush=True)
        print("[api] backups written under this passphrase are NOT protected.", flush=True)
        raise SystemExit(1)
    threading.Thread(target=_reaper, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", 9090), Handler)
    print("[api] recovery API listening on :9090", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
