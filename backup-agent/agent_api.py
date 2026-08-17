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


def _do_recover(module: str, target_time: str | None) -> None:
    """Worker thread: pgbackrest restore into scratch + start on :5433."""
    try:
        _cleanup(module)
        os.makedirs(_scratch(module), mode=0o700)
        os.makedirs(_sockdir(module), exist_ok=True)
        args = ["--stanza", module, f"--pg1-path={_scratch(module)}"]
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
        # Wait for recovery to replay up to the target and promote.
        deadline = _time.time() + 900
        while _time.time() < deadline:
            q = subprocess.run(
                ["psql", "-h", _sockdir(module), "-p", "5433", "-U", module,
                 "-d", module, "-tAc", "SELECT NOT pg_is_in_recovery()"],
                capture_output=True, text=True)
            if q.returncode == 0 and q.stdout.strip() == "t":
                break
            _time.sleep(2)
        else:
            tail = ""
            try:
                with open(f"{_scratch(module)}/startup.log") as f:
                    tail = f.read()[-300:]
            except OSError:
                pass
            raise RuntimeError(f"scratch did not finish recovery in time. {tail}")
        with _lock:
            _sessions[module]["status"] = "ready"
            _sessions[module]["touched_at"] = _time.time()
    except Exception as e:  # noqa: BLE001 — surfaced through the session status
        _cleanup(module)
        with _lock:
            _sessions[module]["status"] = "error"
            _sessions[module]["error"] = str(e)


def _do_promote(module: str) -> dict:
    """N2: replace the live database with the scratch state.
    Postgres protocol only: pg_dump (scratch) → drop/create → psql (live
    socket). The caller (Pilot) is responsible for the safety backup and
    the double confirmation."""
    live_sock = f"/sock/{module}"
    dump = subprocess.run(
        ["pg_dump", "-h", _sockdir(module), "-p", "5433", "-U", module, module],
        capture_output=True, text=True)
    if dump.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {dump.stderr.strip()[-400:]}")
    drop = subprocess.run(
        ["psql", "-h", live_sock, "-U", module, "-d", "postgres", "-c",
         f'DROP DATABASE {module} WITH (FORCE); CREATE DATABASE {module} OWNER {module}'],
        capture_output=True, text=True)
    if drop.returncode != 0:
        raise RuntimeError(f"drop/create failed: {drop.stderr.strip()[-400:]}")
    load = subprocess.run(
        ["psql", "-h", live_sock, "-U", module, "-d", module, "-v", "ON_ERROR_STOP=1"],
        input=dump.stdout, capture_output=True, text=True)
    if load.returncode != 0:
        raise RuntimeError(f"reload failed: {load.stderr.strip()[-400:]}")
    return {"ok": True, "dumped_bytes": len(dump.stdout)}


def _window() -> dict:
    out = {}
    for m in MODULES:
        r = _pgbackrest("--stanza", m, "info", "--output=json")
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
                # Clear refusal when T predates the PITR window (first full
                # backup) — pgBackRest's own error is cryptic here.
                win = _window().get(mod) or {}
                if win.get("from"):
                    try:
                        tgt = datetime.fromisoformat(target_time.replace("+00", "+00:00"))
                        start = datetime.fromisoformat(win["from"])
                        if tgt < start:
                            return self._send(400, {"detail":
                                f"target predates the PITR window (first backup: {win['from']})"})
                    except ValueError:
                        pass
            with _lock:
                cur = _sessions.get(mod)
                if cur and cur["status"] == "preparing":
                    return self._send(409, {"detail": "session already preparing"})
                _sessions[mod] = {"status": "preparing", "time": target_time,
                                  "error": None, "started_at": _time.time(),
                                  "touched_at": _time.time()}
            _audit("recover", mod, self.client_address[0], f"target={target_time or 'latest'}")
            threading.Thread(target=_do_recover, args=(mod, target_time), daemon=True).start()
            return self._send(202, {"module": mod, "status": "preparing"})
        m = re.fullmatch(r"/recover/([a-z]+)/promote", self.path)
        if m:
            mod = m.group(1)
            with _lock:
                s = _sessions.get(mod)
            if not s or s["status"] != "ready":
                return self._send(409, {"detail": "no ready session for this module"})
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
