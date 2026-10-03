# ciso-backup-agent — pgBackRest scheduler for the suite (FEAT-30 stage 1).
# Shared-volume topology: the agent sees every module's PGDATA (read-only)
# and unix socket through named volumes, and drives base backups + retention
# + verification against the shared encrypted repository. WAL archiving
# itself runs in each DB container (archive_command). No docker/podman
# socket, no TLS server pair, no extra daemon in the DB containers.
# Same pinned base as ciso-postgres so uid 70 (postgres) matches the
# repository files written by the DB containers.
FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

# gosu (and its su-exec alias) ship with the postgres base for its root
# entrypoint; this agent runs as USER postgres and never calls them, so they go.
RUN apk add --no-cache pgbackrest bash python3 && \
    rm -f /usr/local/bin/gosu /usr/local/bin/su-exec && \
    mkdir -p /var/log/pgbackrest && chown postgres:postgres /var/log/pgbackrest

COPY agent.sh /usr/local/bin/agent.sh
COPY agent_api.py /usr/local/bin/agent_api.py
COPY restore.sh /usr/local/bin/restore.sh
RUN chmod +x /usr/local/bin/agent.sh /usr/local/bin/restore.sh

USER postgres
ENTRYPOINT ["/usr/local/bin/agent.sh"]
