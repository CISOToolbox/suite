# Contributing to CISO Toolbox — Suite

Thanks for taking the time to contribute. This repository is the **integrated
suite**: Pilot plus the nine backend modules behind one nginx edge, wired by
`docker-compose.yml`. A few things about it are unusual — please read this
before opening a pull request.

## Generated files

Some files in this repository are generated and must not be edited here — the
next release overwrites them and the change is lost. They carry a header that
says so:

| Category | Where | Editable here? |
|----------|-------|----------------|
| Module code | `<module>/src/`, `<module>/alembic/`, `<module>/app/ts/`, `<module>/Dockerfile`, `docker-compose.yml`, `nginx.conf`, `backup-agent/` | **Yes** |
| Shared Python helpers | `<module>/src/*_common.py`, `<module>/src/settings_crypto.py`, `<module>/src/ssrf_guard.py`, … (header "Generated file - do not edit") | **No** |
| Shared frontend assets | `<module>/app/js/*.js` and `app/css/*.css` carrying the same header | **No** |

The shared Python helpers (`auth_common.py`, `settings_crypto.py`,
`audit_common.py`, `backup_common.py`, `version_common.py`,
`ai_proxy_common.py`, `ssrf_guard.py`…) are identical in every module on
purpose: a fix that lands in one module only is exactly the class of bug they
exist to prevent. The shared frontend (design system, i18n runtime, common
widgets) is compiled once and shipped into each module's `app/js/` and
`app/css/`. Module-specific TypeScript lives in `app/ts/` and **is** editable;
a file in `app/js/` without the header is module-specific build output.

**To change a generated file, open an issue describing the change**: it is
applied at the source and reaches every module in the next release.

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
