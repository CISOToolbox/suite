# ciso-postgres — the suite's common DB image (FEAT-30 stage 1).
# Same base (tag AND digest) as the previous per-module postgres:16-alpine so
# an in-place swap keeps the data directories byte-compatible (same libc/
# collations — switching to a glibc image on existing volumes corrupts text
# indexes). Adds pgBackRest for continuous WAL archiving (archive_command)
# to the shared backups repository volume. Archive/cipher settings arrive
# via PGBACKREST_* environment variables — no conf file, no secret baked in.
FROM postgres:16-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb

RUN apk add --no-cache pgbackrest && \
    mkdir -p /var/log/pgbackrest && chown postgres:postgres /var/log/pgbackrest
