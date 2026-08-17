#!/bin/bash
# ciso-backup-agent — pgBackRest scheduler (FEAT-30 étage 1).
#
# Per module <m>, the compose mounts:
#   /pg/<m>    ← <m>-pgdata   (read-only PGDATA)
#   /sock/<m>  ← <m>-pgsock   (postgres unix socket)
#   /var/lib/pgbackrest ← backups-repo (shared encrypted repository)
#
# Cipher + retention come from PGBACKREST_* env vars (compose .env).
# Schedule: full backup on Sunday (or when the stanza has none), diff
# backup daily at ~02:00, `pgbackrest verify` weekly on Monday.
# Status is written to $REPO/agent/status.json for future Pilot health.
set -u

MODULES="${BACKUP_MODULES:-pilot risk vendor compliance asset audit access surface appsec watch}"
REPO="${PGBACKREST_REPO1_PATH:-/var/lib/pgbackrest}"
CONF_DIR="$REPO/agent"
CONF="$CONF_DIR/pgbackrest.conf"
STATUS="$CONF_DIR/status.json"
BACKUP_HOUR="${BACKUP_HOUR:-2}"
export PGBACKREST_CONFIG="$CONF"

mkdir -p "$CONF_DIR"

log() { echo "[agent] $(date -u '+%F %T') $*"; }

write_conf() {
    {
        echo "[global]"
        echo "repo1-path=$REPO"
        echo "log-level-console=info"
        echo "log-level-file=off"
        echo "start-fast=y"
        for m in $MODULES; do
            echo ""
            echo "[$m]"
            # The DB containers run with PGDATA=/pg/<m> and the agent mounts
            # the same volume at the same path — pgBackRest's data-directory
            # identity check passes without tricks.
            echo "pg1-path=/pg/$m"
            echo "pg1-socket-path=/sock/$m"
            echo "pg1-user=$m"
            echo "pg1-database=$m"
        done
        # pilot's DB/user follow the same <module> convention in the suite.
    } > "$CONF"
}

wait_socket() {
    local m="$1" i=0
    while [ ! -S "/sock/$m/.s.PGSQL.5432" ] && [ $i -lt 60 ]; do sleep 5; i=$((i+1)); done
    [ -S "/sock/$m/.s.PGSQL.5432" ]
}

ensure_stanza() {
    local m="$1"
    if ! pgbackrest --stanza="$m" info --output=json 2>/dev/null | grep -q '"status"'; then
        log "stanza-create $m"
    fi
    pgbackrest --stanza="$m" stanza-create 2>&1 | sed "s/^/[$m] /" || true
}

has_full() {
    pgbackrest --stanza="$1" info --output=json 2>/dev/null | grep -q '"type":"full"'
}

run_backup() {
    local m="$1" type="$2"
    log "backup $m ($type)"
    pgbackrest --stanza="$m" --type="$type" backup 2>&1 | tail -2 | sed "s/^/[$m] /"
    return "${PIPESTATUS[0]}"
}

restore_test() {
    # Weekly proof that a backup actually restores: latest backup + WAL into
    # a throwaway scratch on port 5434 (5433 belongs to admin sessions),
    # sanity = alembic_version readable. Result lands in restore-test.json,
    # surfaced by /health and the Pilot dashboard.
    local m="$1" rc=1 rev=""
    local scratch="/tmp/rtest-data-$m" sock="/tmp/rtest-$m"
    rm -rf "$scratch" "$sock"; mkdir -p "$scratch" "$sock"; chmod 700 "$scratch"
    if pgbackrest --stanza="$m" --pg1-path="$scratch" restore >/dev/null 2>&1; then
        pg_ctl -D "$scratch" -l "$scratch/startup.log" \
            -o "-p 5434 -k $sock -c listen_addresses= -c archive_mode=off" start >/dev/null 2>&1
        local i=0
        while [ $i -lt 240 ]; do
            rev=$(psql -h "$sock" -p 5434 -U "$m" -d "$m" -tAc \
                "SELECT version_num FROM alembic_version" 2>/dev/null)
            if [ -n "$rev" ] && psql -h "$sock" -p 5434 -U "$m" -d "$m" -tAc \
                "SELECT NOT pg_is_in_recovery()" 2>/dev/null | grep -q t; then rc=0; break; fi
            sleep 3; i=$((i+1))
        done
        pg_ctl -D "$scratch" stop -m fast >/dev/null 2>&1
    fi
    rm -rf "$scratch" "$sock"
    echo "{\"module\": \"$m\", \"ok\": $([ $rc -eq 0 ] && echo true || echo false), \"revision\": \"$rev\", \"at\": \"$(date -u '+%FT%TZ')\"}"
    return $rc
}

run_restore_tests() {
    log "weekly restore-test starting"
    {
        echo "{\"updated_at\": \"$(date -u '+%FT%TZ')\", \"results\": ["
        local first=1
        for m in $MODULES; do
            [ $first -eq 0 ] && echo ","
            first=0
            restore_test "$m" || log "WARN: restore-test FAILED for $m"
        done
        echo "]}"
    } > "$CONF_DIR/restore-test.json.tmp" && mv "$CONF_DIR/restore-test.json.tmp" "$CONF_DIR/restore-test.json"
    log "weekly restore-test done"
}

write_status() {
    {
        echo "{"
        echo "  \"updated_at\": \"$(date -u '+%FT%TZ')\","
        echo "  \"stanzas\": ["
        local first=1
        for m in $MODULES; do
            [ $first -eq 0 ] && echo "  ,"
            first=0
            echo "  {\"module\": \"$m\", \"info\": $(pgbackrest --stanza="$m" info --output=json 2>/dev/null || echo 'null')}"
        done
        echo "  ]"
        echo "}"
    } > "$STATUS.tmp" && mv "$STATUS.tmp" "$STATUS"
}

# ── Startup ──────────────────────────────────────────────────────
write_conf
log "agent starting — modules: $MODULES"
# Recovery API (FEAT-30 phase 2) — compose-network only, token-authed.
python3 /usr/local/bin/agent_api.py &
for m in $MODULES; do
    if wait_socket "$m"; then
        ensure_stanza "$m"
        # Guarantee at least one full backup per stanza right away: the
        # PITR window only starts once a base backup exists.
        if ! has_full "$m"; then
            run_backup "$m" full || log "WARN: initial full backup failed for $m"
        fi
    else
        log "WARN: no socket for $m — skipped (module down?)"
    fi
done
write_status
[ -f "$CONF_DIR/restore-test.json" ] || run_restore_tests
log "startup cycle done"

# ── Daily loop ───────────────────────────────────────────────────
LAST_DAY=""
while true; do
    sleep 600
    now_day=$(date -u '+%F')
    now_hour=$(date -u '+%-H')
    if [ "$now_day" != "$LAST_DAY" ] && [ "$now_hour" -ge "$BACKUP_HOUR" ]; then
        LAST_DAY="$now_day"
        dow=$(date -u '+%u')   # 1=Mon .. 7=Sun
        for m in $MODULES; do
            [ -S "/sock/$m/.s.PGSQL.5432" ] || { log "skip $m (down)"; continue; }
            ensure_stanza "$m"
            if [ "$dow" = "7" ] || ! has_full "$m"; then
                run_backup "$m" full || log "WARN: full backup failed for $m"
            else
                run_backup "$m" diff || log "WARN: diff backup failed for $m"
            fi
            # Retention (expire) applies PGBACKREST_REPO1_RETENTION_* env.
            pgbackrest --stanza="$m" expire 2>&1 | tail -1 | sed "s/^/[$m] /" || true
            if [ "$dow" = "1" ]; then
                log "verify $m"
                pgbackrest --stanza="$m" verify 2>&1 | tail -1 | sed "s/^/[$m] /" || log "WARN: verify failed for $m"
            fi
        done
        [ "$dow" = "1" ] && run_restore_tests
        write_status
    fi
done
