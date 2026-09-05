#!/bin/bash
# restore.sh — PITR restore of one module into a SCRATCH directory inside
# the agent container (FEAT-30 runbook, levels N1/N2). NEVER touches the
# live PGDATA: the recovered instance runs on a second port inside this
# container for inspection / extraction / dump.
#
# Usage (from the host):
#   podman exec -it ciso-backup-agent restore.sh <module> [--time "2026-08-12 14:35:00+00"]
#   podman exec -it ciso-backup-agent restore.sh <module> --repo 2   # from the off-site repo
#   podman exec -it ciso-backup-agent restore.sh <module> --set <label>
#   podman exec -it ciso-backup-agent restore.sh <module> --stop     # stop+clean scratch
#
# --repo 2 restores from the S3 repository (FEAT-29). This is the path for a
# recovery after losing the host: both repositories hold the same backups, but
# only the second one survives the machine disappearing.
#
# After a successful restore the scratch postgres listens on the unix
# socket /tmp/restore-<module> (port 5433). Examples:
#   psql -h /tmp/restore-<module> -p 5433 -U <module> -d <module>
#   pg_dump -h /tmp/restore-<module> -p 5433 -U <module> <module> > /var/lib/pgbackrest/agent/<module>-restored.sql
#
# The runbook (private/docs/runbooks/pitr-restore.md) covers the full
# N1 (object) / N2 (module) / N3 (suite) procedures, including the
# mandatory `alembic upgrade head` step when T predates a migration and
# the Pilot measures resync afterwards.
set -euo pipefail

MOD="${1:?usage: restore.sh <module> [--time \"YYYY-MM-DD HH:MM:SS+00\"] [--repo N] [--set LABEL] [--stop]}"
shift || true
REPO="${PGBACKREST_REPO1_PATH:-/var/lib/pgbackrest}"
export PGBACKREST_CONFIG="$REPO/agent/pgbackrest.conf"
SCRATCH="/tmp/restore-data-$MOD"
SOCKDIR="/tmp/restore-$MOD"
PIDFILE="$SCRATCH/postmaster.pid"

TIME=""
SET=""
RREPO="1"
STOP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --time) TIME="$2"; shift 2 ;;
        --set)  SET="$2";  shift 2 ;;
        --repo) RREPO="$2"; shift 2 ;;
        --stop) STOP=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# --time designates a point in time, --set a specific backup. Combining them
# amounts to asking for two contradictory targets; pgBackRest would silently
# pick one, which is the worst possible behavior for a restore.
if [ -n "$TIME" ] && [ -n "$SET" ]; then
    echo "!! --time et --set sont exclusifs : choisissez un instant OU une sauvegarde" >&2
    exit 2
fi

if [ "$STOP" = "1" ]; then
    [ -f "$PIDFILE" ] && pg_ctl -D "$SCRATCH" stop -m fast || true
    rm -rf "$SCRATCH" "$SOCKDIR"
    echo "scratch instance for $MOD stopped and cleaned"
    exit 0
fi

[ -d "$SCRATCH" ] && { echo "scratch already exists — run with --stop first" >&2; exit 1; }
mkdir -p "$SCRATCH" "$SOCKDIR"
chmod 700 "$SCRATCH"

echo ">>> pgbackrest restore ($MOD${TIME:+ @ $TIME}${SET:+ set $SET}, dépôt $RREPO)"
if [ -n "$TIME" ]; then
    pgbackrest --stanza="$MOD" --repo="$RREPO" --pg1-path="$SCRATCH" \
        --type=time --target="$TIME" --target-action=promote restore
elif [ -n "$SET" ]; then
    pgbackrest --stanza="$MOD" --repo="$RREPO" --pg1-path="$SCRATCH" \
        --set="$SET" restore
else
    pgbackrest --stanza="$MOD" --repo="$RREPO" --pg1-path="$SCRATCH" restore
fi

echo ">>> starting scratch postgres (socket $SOCKDIR, port 5433)"
pg_ctl -D "$SCRATCH" -l "$SCRATCH/startup.log" -o "-p 5433 -k $SOCKDIR -c listen_addresses=* -c archive_mode=off" start

echo ">>> recovery in progress — waiting for promotion"
for i in $(seq 1 450); do
    if psql -h "$SOCKDIR" -p 5433 -U "$MOD" -d "$MOD" -tAc "SELECT NOT pg_is_in_recovery()" 2>/dev/null | grep -q t; then
        break
    fi
    sleep 2
done

echo ">>> restored state:"
psql -h "$SOCKDIR" -p 5433 -U "$MOD" -d "$MOD" -c "SELECT version_num AS alembic_revision FROM alembic_version" || true
echo "OK — inspect with: psql -h $SOCKDIR -p 5433 -U $MOD -d $MOD"
echo "     clean with:   restore.sh $MOD --stop"
