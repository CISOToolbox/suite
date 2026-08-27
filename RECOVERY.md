# Recovery

What a restore gives back, what it does not, and the three ways it goes wrong
quietly.

Operational procedures — restoring one object, one module, or the whole suite —
belong to your deployment. This document describes what the *product* does, so
that those procedures rest on something true.

## What a backup contains

The `backup-agent` container drives pgBackRest against every module database:
continuous WAL archiving, a full backup, differentials, retention, and a weekly
restore test. With off-site backup enabled it maintains a second repository on
S3-compatible object storage.

It holds **database contents**. It does not hold, and cannot hold:

| | Where it lives | Comes back on its own? |
|---|---|---|
| Database contents | the repository | yes |
| Settings Pilot stores encrypted (SMTP, AI keys, connector tokens) | the databases | yes — provided `ENCRYPTION_KEY` is unchanged |
| `ENCRYPTION_KEY` itself | the `.env` | **no** — and without it the row above is unreadable |
| `DB_PASSWORD`, `JWT_SECRET`, identity-provider secrets | the `.env` | **no** |
| Repository passphrase and S3 credentials | the `.env` | **no**, obviously |

The last three lines are the point: the secrets needed to *open* a backup
cannot be inside it. They must survive independently of the machine they
protect — a password manager, a corporate vault, offline media. A repository
whose passphrase is lost is not a backup.

## Schema and migrations

A restore brings back the schema **and** the data as of time T. The container
image does not move: it stays at the deployed version. After a restore you
therefore have recent code facing a possibly older schema.

### Older schema than the code — handled automatically

The normal case, and it resolves itself. Each module's entrypoint does:

```sh
if [ -z "$(alembic current)" ]; then alembic stamp head; else alembic upgrade head; fi
```

A restored database has a populated `alembic_version`, so it takes the
`upgrade head` path and the missing migrations apply at startup, in order.
This is why applications must be restarted **after** their databases.

### Newer schema than the code — impossible

Alembic migrations are **one-way**. There is no downgrade path.

Restoring a recent backup while pinning an older suite version runs old code
against an advanced schema: a failed startup, or worse, silently wrong reads.

**Never lower the image version below the one that produced the backup.** A
rollback is done by restoring, never by changing a tag — which is also why the
upgrade path refuses to run without a usable dump.

### The empty-database case

On a genuinely empty database the entrypoint **stamps** instead of migrating:
`create_all()` builds the current schema, and replaying migrations from zero
would fail since some of them assume a pre-existing schema.

The practical consequence: if the logs say `fresh database — stamping` where
migrations were expected, **the restore restored nothing**. The module will
still start, without an error, on an empty database.

### Restoring one module and not the others

Each database is consistent on its own, but measures flow upward into Pilot:
its consolidated action plan will reference objects that vanished from the
restored module, or ignore those that reappeared.

No database error reports this. After a partial restore, resynchronise the
measures from the module concerned.

## Verify by the revision, not by the startup

A module that starts is not proof. The revision is:

```bash
docker compose exec -T <module>-db psql -U <module> -d <module> \
  -tAc "select version_num from alembic_version"
```

Every revision must match what the deployed image expects. This is the same
principle as reading the `Image` column of `compose ps` rather than trusting
the compose file: the absence of an error is not evidence.

## Off-site backup

The repository lives in a Docker volume, on the same host and the same disk as
the databases it protects. That covers logical failure — a bad migration, an
accidental delete. It does not cover losing the host: dead disk, destroyed VM,
ransomware. Then databases and backups disappear together.

A second repository on S3-compatible storage is enabled through a compose
overlay:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.s3.yml
```

It is an overlay rather than a conditional variable because pgBackRest refuses
an empty environment variable: an empty default would stop every non-S3
deployment from starting.

### What enabling it changes

WAL archiving switches to **asynchronous**, and that is not a performance
detail. WAL is pushed to every repository; without asynchronous archiving, one
unreachable repository stops the others from moving more than one segment
ahead. The `archive_command` then fails, WAL accumulates in `pg_wal`, the disk
fills, the database stops.

Without that setting, an off-site backup meant to protect against losing the
host would cause exactly that, at a time chosen by the storage provider.

### Credentials

pgBackRest needs four permissions. A "write-only" key does not work:

| Operation | Scope | Why |
|---|---|---|
| list | the **bucket** | the one that gets forgotten — a bucket permission, not an object one |
| read | objects | `backup.info` is read before every backup |
| write | objects | the backups themselves |
| delete | objects | retention expires old backups |

Missing the list permission produces a misleading failure: S3 answers **403 on
an object that does not exist** rather than 404, so that a caller who may not
list cannot learn what exists. On a fresh repository every path is missing, so
the first call fails with `AccessDenied` and reads like a credentials problem.

Protection against ransomware does not come from removing the read permission.
It comes from **object lock** or versioning on the bucket, where writes stay
possible and deletions are neutralised server-side.

**A distinct passphrase for the off-site repository** is worth the trouble:
that repository is exposed to a third party — the storage provider — where the
local one is not. Separate keys let you entrust one without the other.

**If the bucket filters by source IP, the recovery host must be in the
allow-list too.** A standby built in a hurry has a different egress address and
is refused with that same `AccessDenied`, at the worst possible moment.

### Internal object storage must serve HTTPS

pgBackRest speaks TLS to an S3 repository. Against a plaintext endpoint the
call does not fail — it *hangs*. And an `archive_command` that hangs blocks
PostgreSQL's shutdown: on a first start the container dies with
`pg_ctl: server does not shut down`, a symptom pointing at nothing related to
storage.

Serve HTTPS and provide the authority through `repo2-storage-ca-file`.

## Rehearsing

An off-site repository that has never been restored is a hypothesis, not a
backup. The agent restores one database per month from it, rotating across
modules, precisely because that repository is the one nobody uses until
everything depends on it — and the one whose failures are silent: expired
credentials, a moved bucket, retention imposed by the provider.

Two things differ between a rehearsal and a real recovery:

**The original host is still alive**, so both deployments share one repository.
The restored copy's agent will apply its own retention and expire the source's
backups. Stop it as soon as the restore succeeds.

**The recovery host must be sized like the original.** A rehearsal on an
undersized machine fails in a way that points nowhere useful: containers
restarting in under a second, exit code 0, no OOM signature, and `docker stats`
showing almost nothing — because a container that dies before doing any work
never reaches its working set.
