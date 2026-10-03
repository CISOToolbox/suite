# ciso-postgres — the suite's common DB image (FEAT-30 stage 1).
# Same base (tag AND digest) as the previous per-module postgres:16-alpine so
# an in-place swap keeps the data directories byte-compatible (same libc/
# collations — switching to a glibc image on existing volumes corrupts text
# indexes). Adds pgBackRest for continuous WAL archiving (archive_command)
# to the shared backups repository volume. Archive/cipher settings arrive
# via PGBACKREST_* environment variables — no conf file, no secret baked in.
FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

RUN apk add --no-cache pgbackrest && \
    mkdir -p /var/log/pgbackrest && chown postgres:postgres /var/log/pgbackrest
