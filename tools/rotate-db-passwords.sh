#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  rotate-db-passwords.sh — apply the DB_PASSWORD_<MODULE> values to the
#  running databases, or to a restore session
# ─────────────────────────────────────────────────────────────────────────────
#
#  POSTGRES_PASSWORD only applies when a database is first created: changing a
#  value in .env does not change the password of an existing database, and the
#  module would then fail to connect. This script changes it in place, for each
#  module whose DB_PASSWORD_<MODULE> is set, then recreates the app and the
#  database containers so they pick the new value up.
#
#  The values are read the way docker compose resolves them. A value exported
#  in your shell wins over .env for compose too — but the stack's own start-up
#  (systemd, a later `docker compose up`) only sees .env, so the script refuses
#  a module whose shell value differs from the file.
#
#  Restoring a point in time later than the rotation brings the new password
#  back with it: the change is in the WAL. A point earlier than the rotation
#  comes back with the previous password, and the module cannot read it:
#  Pilot then says so, with this command to run:
#      bash tools/rotate-db-passwords.sh --recovery-session <module>
#  to set the module's current password on the restored instance (it waits for
#  the WAL replay to finish); Pilot then shows it ready, and export and
#  promotion work as usual. After a restore made in place, into the live
#  database (host recovery), run --after-restore for that module instead.
#  See RECOVERY.md.
#
#  As a precaution, a full backup is taken right after each rotation.
#
#  Usage, with the stack up:
#      bash tools/rotate-db-passwords.sh                  # every module set
#      bash tools/rotate-db-passwords.sh risk vendor
#      bash tools/rotate-db-passwords.sh --recovery-session risk
#      bash tools/rotate-db-passwords.sh --after-restore risk
#  --after-restore is for a database restored in place, straight into the live
#  one (host rebuild): it waits as long as the replay takes, sets the password
#  the module is given, and does nothing else — no container recreated, and no
#  backup, which would expire the very backups the restore just used.
#  The compose project is taken as the parent of tools/; where it lives
#  elsewhere (an Ansible deployment keeps the release in a subdirectory), add
#      --project-dir /path/to/the/directory/holding/docker-compose.yml
#
#  The password never appears on a command line or in this script's output:
#  it is handed to psql on standard input. (Should PostgreSQL reject the
#  statement, it logs it, password included, in that database's container log.)

set -euo pipefail

ALL="pilot risk vendor compliance asset audit access surface appsec watch"
MODE=rotate
PROJECT="$(dirname "${BASH_SOURCE[0]}")/.."
while [ $# -gt 0 ]; do
    case "$1" in
        --recovery-session) MODE=recovery; shift ;;
        --after-restore) MODE=after; shift ;;
        --project-dir) [ $# -ge 2 ] || { echo "--project-dir needs a directory" >&2; exit 2; }
                       PROJECT="$2"; shift 2 ;;
        --*) echo "unknown option: $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
if [ "$MODE" != rotate ] && [ $# -eq 0 ]; then
    echo "usage: $0 --recovery-session|--after-restore <module>..." >&2; exit 2
fi
cd "$PROJECT" || { echo "no such directory: $PROJECT" >&2; exit 2; }
MODULES="${*:-$ALL}"
for m in $MODULES; do
    case " $ALL " in *" $m "*) ;; *) echo "unknown module: $m" >&2; exit 2 ;; esac
done
DC="docker compose"
WAIT=300   # seconds; a container that never turns healthy must not hang us

# Resolved interpolation variables, kept in memory only: as compose sees them
# from this shell, and as the stack's own start-up will (.env alone).
RESOLVED="$($DC config --environment 2>/dev/null)" \
    || { echo "docker compose config failed — run it to see why" >&2; exit 2; }
FILE_ONLY="$(env -i PATH="$PATH" HOME="$HOME" DOCKER_HOST="${DOCKER_HOST:-}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" $DC config --environment 2>/dev/null)" \
    || { echo "docker compose config fails without your shell variables: the stack's" >&2
         echo "own start-up would fail too — fix .env first" >&2; exit 2; }
value() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | tail -1; }

# The password the module is given: its own, or the shared fallback.
module_password() {
    local var="DB_PASSWORD_$(echo "$1" | tr '[:lower:]' '[:upper:]')" pw
    pw="$(value "$2" "$var")"
    [ -n "$pw" ] || pw="$(value "$2" DB_PASSWORD)"
    printf '%s' "$pw"
}

# A value exported in this shell that .env does not hold would be lost at the
# stack's next start: the module would then be given another password.
same_as_file() {   # $1 module
    [ "$(module_password "$1" "$RESOLVED")" = "$(module_password "$1" "$FILE_ONLY")" ] && return
    echo "  ✗  $1: its password in your shell differs from .env — the stack's next" >&2
    echo "     start would give the module the .env value. Unset it or align .env." >&2
    return 1
}

usable() {   # $1 module, $2 variable name, $3 value
    case "$3" in
        change-me*) echo "  ✗  $1: $2 is still the placeholder" >&2; return 1 ;;
    esac
    if ! printf '%s' "$3" | grep -Eq '^[A-Za-z0-9]+$'; then
        # The value goes into a connection URL and into SQL below.
        echo "  ✗  $1: $2 must be alphanumeric (openssl rand -hex 16)" >&2; return 1
    fi
}

# pgBackRest in the agent reads its stanzas from the file agent.sh writes.
agent_pgbackrest() {
    $DC exec -T backup-agent sh -c \
        'PGBACKREST_CONFIG="$PGBACKREST_REPO1_PATH/agent/pgbackrest.conf" exec pgbackrest "$@"' _ "$@"
}

# Why a session is gone, from the agent itself (it holds the API token).
session_error() {
    local why
    why="$($DC exec -T backup-agent python3 -c '
import json, os, sys, urllib.request
r = urllib.request.Request("http://127.0.0.1:9090/recover/" + sys.argv[1],
                           headers={"X-Agent-Token": os.environ.get("BACKUP_AGENT_TOKEN", "")})
try:
    s = json.load(urllib.request.urlopen(r, timeout=5))
except Exception:
    sys.exit()
if s.get("status") == "error":
    print(" — the session failed: …" + str(s.get("error"))[-300:])
' "$1" 2>/dev/null || true)"
    printf '%s' "${why:- — start one from Pilot first}"
}

# A restored database replays its WAL before it accepts writes, and refuses
# connections while it starts up; its password can only be set afterwards.
wait_primary() {   # $1 module, $2 "unbounded" to wait as long as the replay takes
    local waited=0
    until [ "$($DC exec -T "$1-db" psql -U "$1" -d "$1" -tAc "SELECT NOT pg_is_in_recovery()" \
                2>/dev/null | tr -d '[:space:]')" = t ]; do
        if [ -z "$($DC ps -q --status running "$1-db" 2>/dev/null)" ]; then
            echo "  ✗  $1: $1-db is not running — nothing changed" >&2
            return 1
        fi
        if [ "${2:-}" != unbounded ] && [ "$waited" -ge 900 ]; then
            echo "  ✗  $1: the database is still starting or replaying after 900s — nothing changed" >&2
            return 1
        fi
        [ $((waited % 60)) -eq 0 ] && [ "$waited" -gt 0 ] \
            && printf '     %s: still replaying (%ss)…\n' "$1" "$waited"
        sleep 5; waited=$((waited + 5))
    done
}

rc=0
if [ "$MODE" = after ]; then
    for m in $MODULES; do
        same_as_file "$m" || { rc=1; continue; }
        pw="$(module_password "$m" "$RESOLVED")"
        usable "$m" "the password of $m" "$pw" || { rc=1; continue; }
        wait_primary "$m" unbounded || { rc=1; continue; }
        if printf "ALTER ROLE %s PASSWORD '%s';\n" "$m" "$pw" \
                | $DC exec -T "$m-db" psql -q -v ON_ERROR_STOP=1 -U "$m" -d "$m" >/dev/null; then
            echo "  ✓  $m: password set to the one the module is given"
        else
            echo "  ✗  $m: could not set the password" >&2; rc=1
        fi
    done
    exit "$rc"
fi

if [ "$MODE" = recovery ]; then
    for m in $MODULES; do
        same_as_file "$m" || { rc=1; continue; }
        pw="$(module_password "$m" "$RESOLVED")"
        usable "$m" "the password of $m" "$pw" || { rc=1; continue; }
        # The agent keeps /tmp/restore-data-<m> for exactly as long as a session
        # lives; the restored instance then listens on /tmp/restore-<m>.
        if ! $DC exec -T backup-agent test -d "/tmp/restore-data-$m"; then
            echo "  ✗  $m: no restore session running$(session_error "$m")" >&2
            rc=1; continue
        fi
        # Files are restored first, then the instance replays the WAL up to the
        # chosen time, read-only; only then can its password be set. The time
        # limit only counts once the instance is up: restoring the files of a
        # large database from off-site storage takes as long as it takes.
        printf '     %s: waiting for the restored instance to reach its point in time…\n' "$m"
        waited=0
        until [ "$($DC exec -T backup-agent psql -h "/tmp/restore-$m" -p 5433 -U "$m" -d "$m" \
                    -tAc "SELECT NOT pg_is_in_recovery()" 2>/dev/null | tr -d '[:space:]')" = t ]; do
            if ! $DC exec -T backup-agent test -d "/tmp/restore-data-$m"; then
                echo "  ✗  $m: the restore session ended$(session_error "$m")" >&2
                rc=1; continue 2
            fi
            if [ "$waited" -ge 900 ]; then
                echo "  ✗  $m: the restored instance is still replaying after 900s — check" >&2
                echo "     'docker compose logs backup-agent', then run this again" >&2
                rc=1; continue 2
            fi
            sleep 5
            $DC exec -T backup-agent test -S "/tmp/restore-$m/.s.PGSQL.5433" && waited=$((waited + 5))
        done
        if printf "ALTER ROLE %s PASSWORD '%s';\n" "$m" "$pw" \
                | $DC exec -T backup-agent psql -q -v ON_ERROR_STOP=1 \
                    -h "/tmp/restore-$m" -p 5433 -U "$m" -d "$m" >/dev/null; then
            echo "  ✓  $m: restored instance now takes the module's current password"
        else
            echo "  ✗  $m: could not set the password on the restored instance" >&2; rc=1
        fi
    done
    exit "$rc"
fi

for m in $MODULES; do
    var="DB_PASSWORD_$(echo "$m" | tr '[:lower:]' '[:upper:]')"
    pw="$(value "$RESOLVED" "$var")"
    if [ -z "$pw" ]; then
        echo "  -  $m: $var not set, left on DB_PASSWORD"
        continue
    fi
    same_as_file "$m" || { rc=1; continue; }
    usable "$m" "$var" "$pw" || { rc=1; continue; }

    wait_primary "$m" || { rc=1; continue; }
    # Local socket inside the database container: no password needed to log in.
    if ! printf "ALTER ROLE %s PASSWORD '%s';\n" "$m" "$pw" \
            | $DC exec -T "$m-db" psql -q -v ON_ERROR_STOP=1 -U "$m" -d "$m" >/dev/null; then
        echo "  ✗  $m: password change refused — nothing changed" >&2; rc=1; continue
    fi
    if ! $DC up -d --wait --wait-timeout "$WAIT" --no-deps --force-recreate "$m-db" "$m-app" >/dev/null 2>&1; then
        echo "  ✗  $m: PASSWORD CHANGED, but $m-db/$m-app did not come back healthy within ${WAIT}s." >&2
        echo "     The module cannot connect until they do: check 'docker compose ps' and" >&2
        echo "     'docker compose logs $m-app', then 'docker compose up -d --no-deps $m-db $m-app'." >&2
        rc=1; continue
    fi
    echo "  ✓  $m: password changed, containers recreated"

    if agent_pgbackrest --stanza="$m" --type=full backup >/dev/null 2>&1; then
        echo "     full backup taken"
    else
        echo "  ⚠  $m: full backup failed (the rotation itself succeeded)" >&2
        rc=1
    fi
    if $DC exec -T backup-agent sh -c '[ "${BACKUP_S3_ENABLED:-}" = 1 ]' 2>/dev/null; then
        agent_pgbackrest --stanza="$m" --repo=2 --type=full backup >/dev/null 2>&1 \
            && echo "     off-site full backup taken" \
            || { echo "  ⚠  $m: off-site full backup failed (the rotation itself succeeded)" >&2; rc=1; }
    fi
done
exit "$rc"
