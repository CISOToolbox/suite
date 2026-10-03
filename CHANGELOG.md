# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 0.12.0 — 2026-10-03

### Modules

- pilot: 1.1.3 → **1.2.0**
- risk: 1.0.4 → **1.1.0**
- compliance: 1.0.4 → **1.1.0**
- audit: 1.0.4 → **1.1.0**
- vendor: 1.2.0 → **1.3.0**
- asset: 1.1.0 → **1.2.0**
- access: 1.2.0 → **1.3.0**
- surface: 1.4.0 → **1.5.0**
- appsec: 1.1.4 → **1.2.0**
- watch: 1.0.4 → **1.1.0**

### Added

- Non-conformity and derogation register in Compliance, Surface, AppSec, Access and Vendor, consolidated live in Pilot: non-conformities on one or several items, remediation through corrective measures, time-boxed derogations that never count as compliant.
- `tools/` ships the i18n packaging (`i18n-apply.sh`, `i18n-package.py`, `i18n.conf`) that `tools/build-client-image.sh --langs` runs.

### Changed

- Every image installs a complete dependency lock with hashes (`<module>/requirements-lock.txt`), transitive dependencies included; semgrep's environment (AppSec) and the build tools of source-only packages (Watch) are hashed too.
- Client add-ons layered by `Dockerfile.addons` install their Python dependencies from their own hashed lock (`BASE_LOCK=<image lock> bash tests/lock-deps.sh <add-on>`); without one, only what the image already holds is accepted. **A client add-on that adds a package must now ship its lock.**
- The CI unit tests run on Python 3.13 from `<module>/requirements-test-lock.txt`: the image lock plus the test tools, with hashes.
- `tests/check-deps-drift.sh` checks the image, build and unit-test locks; `tests/lock-deps.sh` generates all three.
- GitHub Actions move to their Node.js 24 releases.

### Fixed

- Security updates: PyJWT 2.15.0 (GHSA-42vr-xj54-vc7v), urllib3 2.8.0, anyio 4.14.2 (GHSA-82r6-8w77-94w6); semgrep 1.177.0.
- `tools/release-check.sh` verifies the tag the compose pins and counts real image architectures.

### Documentation

- `TRANSLATING.md` and the README describe what `i18n.conf` and `--langs` actually do; comments and docs point only at files shipped in the repositories.

## 0.11.0 — 2026-09-08

### Modules

- pilot: 1.1.2 → **1.1.3**
- risk: 1.0.3 → **1.0.4**
- compliance: 1.0.3 → **1.0.4**
- audit: 1.0.3 → **1.0.4**
- vendor: 1.1.3 → **1.2.0**
- asset: 1.0.3 → **1.1.0**
- access: 1.1.2 → **1.2.0**
- surface: 1.3.1 → **1.4.0**
- appsec: 1.1.3 → **1.1.4**
- watch: 1.0.3 → **1.0.4**

### Added

- Surface: Microsoft Defender connector — a host discovered by the connector arrives enabled with the connector as its only active scanner; disabling the host silences its findings
- Vendor: threat methodology — maturity and confidence floored at 1, distinct "unassessed" threat state
- Access: service-account lifecycle and dashboard charts
- Asset: dashboard charts

### Changed

- Every image republished under a new tag so that the published code and the images agree (the previous 0.10.1 images predated several merged fixes)
