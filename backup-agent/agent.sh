#!/bin/bash
# ciso-backup-agent — pgBackRest scheduler (FEAT-30 stage 1).
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
# Off-site repository (FEAT-29). Set by docker-compose.s3.yml, which also
# provides the PGBACKREST_REPO2_*: repo2's configuration therefore comes from
# the environment, not from $CONF — the variables take precedence over the file.
S3="${BACKUP_S3_ENABLED:-0}"
# Off-site restore test: monthly, one module at a time. Restoring from S3
# downloads a whole database; doing it for ten modules every week would cost
# in transfer without proving anything more.
S3_TEST_DAY="${BACKUP_S3_TEST_DAY:-01}"
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
    # The EXISTENCE of the socket proves nothing: the postgres image entrypoint
    # starts a temporary server during initialization, socket included. The
    # agent then started too early, stanza-create and the initial backup
    # failed — and since the loop only comes back at the scheduled hour, the
    # stanza stayed WITHOUT a base backup, hence without a PITR window, until
    # the next day and with nothing flagging it.
    #
    # So we wait for the database to ANSWER, not for a file to appear.
    local m="$1" i=0
    while [ $i -lt 60 ]; do
        if [ -S "/sock/$m/.s.PGSQL.5432" ] \
           && pg_isready -h "/sock/$m" -U "$m" -d "$m" >/dev/null 2>&1; then
            return 0
        fi
        sleep 5; i=$((i+1))
    done
    return 1
}

ensure_stanza() {
    local m="$1"
    if ! pgbackrest --stanza="$m" info --output=json 2>/dev/null | grep -q '"status"'; then
        log "stanza-create $m"
    fi
    # stanza-create handles ALL configured repositories in one call — and
    # refuses the --repo option (« option 'repo' not valid for command
    # 'stanza-create' »). Unlike backup, there is therefore nothing to repeat
    # for repo2.
    pgbackrest --stanza="$m" stanza-create 2>&1 | sed "s/^/[$m] /" || true
}

has_full() {
    pgbackrest --stanza="$1" ${2:+--repo=$2} info --output=json 2>/dev/null \
        | grep -q '"type":"full"'
}

run_backup() {
    local m="$1" type="$2" rc=0
    log "backup $m ($type)"
    pgbackrest --stanza="$m" --type="$type" backup 2>&1 | tail -2 | sed "s/^/[$m] /"
    rc="${PIPESTATUS[0]}"

    # A base backup only goes TO the highest-priority repository: « When multiple
    # repositories are configured, pgBackRest will backup to the highest
    # priority repository unless the --repo option is specified. » Only WAL
    # archiving is fanned out to all of them. Hence this second explicit call.
    if [ "$S3" = "1" ]; then
        local t2="$type"
        # A diff with no full on THIS repository has nothing to build on: the
        # repositories have their own cycles, repo2 may be younger.
        has_full "$m" 2 || t2="full"
        log "backup $m ($t2) → hors site"
        pgbackrest --stanza="$m" --repo=2 --type="$t2" backup 2>&1 \
            | tail -2 | sed "s/^/[$m repo2] /"
        # An off-site failure must not mask a successful local backup: these
        # are two incidents of different severity.
        [ "${PIPESTATUS[0]}" -eq 0 ] || log "WARN: sauvegarde hors site échouée pour $m"
    fi
    return "$rc"
}

restore_test() {
    # Weekly proof that a backup actually restores: latest backup + WAL into
    # a throwaway scratch on port 5434 (5433 belongs to admin sessions),
    # sanity = alembic_version readable. Result lands in restore-test.json,
    # surfaced by /health and the Pilot dashboard.
    local m="$1" repo="${2:-1}" rc=1 rev=""
    local scratch="/tmp/rtest-data-$m" sock="/tmp/rtest-$m"
    rm -rf "$scratch" "$sock"; mkdir -p "$scratch" "$sock"; chmod 700 "$scratch"
    if pgbackrest --stanza="$m" --repo="$repo" --pg1-path="$scratch" restore >/dev/null 2>&1; then
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
    echo "{\"module\": \"$m\", \"repo\": $repo, \"ok\": $([ $rc -eq 0 ] && echo true || echo false), \"revision\": \"$rev\", \"at\": \"$(date -u '+%FT%TZ')\"}"
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

run_s3_restore_test() {
    # An off-site repository that is never restored is an assumption, not a
    # backup: it is the one you never use until the day everything depends on
    # it, and whose failures — expired credentials, moved bucket, retention
    # imposed by the host — are silent.
    #
    # A single module per month, rotated over the year: the proof is about the
    # chain (credentials, network, decryption, consistency), not about one
    # module in particular. Restoring all ten would cost ten times more in
    # transfer for the same information.
    local n mois idx m
    set -- $MODULES; n=$#
    mois=$(date -u '+%-m')
    idx=$(( (mois - 1) % n + 1 ))
    eval "m=\${$idx}"
    log "test de restauration hors site — $m (dépôt 2)"
    restore_test "$m" 2 > "$CONF_DIR/restore-test-s3.json.tmp" \
        && mv "$CONF_DIR/restore-test-s3.json.tmp" "$CONF_DIR/restore-test-s3.json" \
        || { log "WARN: test de restauration HORS SITE ÉCHOUÉ pour $m"
             mv "$CONF_DIR/restore-test-s3.json.tmp" "$CONF_DIR/restore-test-s3.json" 2>/dev/null || true; }
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
            if [ "$S3" = "1" ]; then
                # Two repositories published separately: « fresh local, off-site
                # lagging behind » is the most likely failure mode, and it must
                # be readable without interpretation.
                echo "  {\"module\": \"$m\", \"info\": $(pgbackrest --stanza="$m" info --output=json 2>/dev/null || echo 'null'), \"info_repo2\": $(pgbackrest --stanza="$m" --repo=2 info --output=json 2>/dev/null || echo 'null')}"
            else
                echo "  {\"module\": \"$m\", \"info\": $(pgbackrest --stanza="$m" info --output=json 2>/dev/null || echo 'null')}"
            fi
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
            [ "$S3" = "1" ] && { pgbackrest --stanza="$m" --repo=2 expire 2>&1 \
                | tail -1 | sed "s/^/[$m repo2] /" || true; }
            if [ "$dow" = "1" ]; then
                log "verify $m"
                pgbackrest --stanza="$m" verify 2>&1 | tail -1 | sed "s/^/[$m] /" || log "WARN: verify failed for $m"
                [ "$S3" = "1" ] && { pgbackrest --stanza="$m" --repo=2 verify 2>&1 \
                    | tail -1 | sed "s/^/[$m repo2] /" || log "WARN: verify repo2 failed for $m"; }
            fi
        done
        [ "$dow" = "1" ] && run_restore_tests
        [ "$S3" = "1" ] && [ "$(date -u '+%d')" = "$S3_TEST_DAY" ] && run_s3_restore_test
        write_status
    fi
done
