# Contributing to CISO Toolbox — Suite

Thanks for taking the time to contribute. This repository is the **integrated
suite**: Pilot plus the nine backend modules behind one nginx edge, wired by
`docker-compose.yml`. A few things about it are unusual — please read this
before opening a pull request.

## This repository is partly replicated and partly generated

The suite is developed in a private monorepo and published here. Files fall into
three categories:

| Category | Where | Editable here? |
|----------|-------|----------------|
| Module code | `<module>/src/`, `<module>/alembic/`, `<module>/app/ts/`, `<module>/Dockerfile`, `docker-compose.yml`, `nginx.conf`, `backup-agent/` | **Yes** |
| Replicated Python helpers | `<module>/src/*_common.py`, `<module>/src/settings_crypto.py`, `<module>/src/ssrf_guard.py`, `pilot/src/settings_crypto.py`, … | **No** |
| Generated frontend assets | `<module>/app/js/*.js` and `app/css/*.css` carrying a `GENERATED` header | **No** |

### Replicated Python helpers

Files such as `auth_common.py`, `settings_crypto.py`, `audit_common.py`,
`backup_common.py`, `version_common.py`, `ai_proxy_common.py` and
`ssrf_guard.py` are **verbatim copies** of a single master kept in the shared
backend library. Each one carries a `REPLICATED` banner. Every module ships the
same copy, so a patch applied to one here would be silently reverted on the next
propagation *and* would leave the other modules unfixed — exactly the class of
bug (a fix landing in one module only) the shared master exists to prevent.
**Open an issue describing the change instead**, and it will be applied to the
master and propagated to every module at once.

### Generated frontend assets

The shared TypeScript (`shared/ts/`) and stylesheets are compiled once in the
private monorepo and distributed into each module's `app/js/` and `app/css/`,
each file prefixed with a `GENERATED` banner. Module-specific TypeScript lives
in `app/ts/` and **is** editable — it is compiled in place. A file in `app/js/`
without a `GENERATED` header is module-specific build output.

The practical rule for both banners is identical: **the file is overwritten on
the next run, so do not edit it here.**

## Development

```bash
bash setup.sh                 # generate .env + local TLS cert
docker compose up -d --build
docker compose logs -f
bash shared/smoke-test.sh     # health-check every module (if present)
```

The suite answers on <https://localhost>. Local builds are driven by
`docker-compose.override.yml` (`ciso-*:local`, `pull_policy: never`), so nothing
is pulled from GHCR while you develop.

## Before opening a pull request

```bash
# 1. Python syntax across every module
for m in pilot risk vendor compliance asset audit access surface appsec watch; do
  python3 -m compileall -q "$m/src"; done

# 2. The auth sentinel contract (the None == auth-disabled rule)
python3 tests/test_auth_sentinel.py

# 3. Dependency pins stay aligned with constraints.txt
bash tests/check-deps-drift.sh          # DRIFT / UNPINNED fail; LOOSE / STALE warn

# 4. Every image is pinned to a digest
bash tools/pin-images.sh --check

# 5. Known vulnerabilities
osv-scanner scan source --recursive .
```

## Images

- Reference images by digest (`name:tag@sha256:…`). Refresh at release with
  `bash tools/pin-images.sh`; CI gates on `--check`.
- Every image pushed to GHCR must be **multi-arch** (`linux/amd64` +
  `linux/arm64`).

## Dependencies

- Pin exact versions (`==`) in every `requirements*.txt`.
- Any new shared package must also be pinned in `constraints.txt`, at the **same
  version across all modules** — `check-deps-drift.sh` enforces this.
- Justify new dependencies in the pull request: what it does, why the standard
  library is not enough, and how actively it is maintained.

## Commit messages

Conventional commits — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`, `perf:`, `build:`. One concern per commit.

## Security issues

Do **not** open a public issue or pull request for a vulnerability. Follow
[`SECURITY.md`](./SECURITY.md).
