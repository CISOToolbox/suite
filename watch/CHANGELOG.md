# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 1.1.2 — 2026-10-05

### Maintenance

- `constraints.txt` no longer pins semgrep (dropped with the AppSec Opengrep migration); the image content is unchanged.

## 1.1.1 — 2026-10-03

### Maintenance

- `constraints.txt` pins semgrep 1.179.0 and `tests/check-deps-drift.sh` no longer carries a PyJWT exception; the image content is unchanged.

## 1.1.0 — 2026-10-03

### Fixed

- The feed parser's source-only dependency (sgmllib3k) is built with a pinned, hashed setuptools.
- Forms lay out on the shared form grid and collapse to one column below 768 px; checkboxes sit on the line of their label.
- Muted text keeps AA contrast on every background; one shared signed-in user block in the toolbar.
- Picking a person closes the result list.
- Security updates: PyJWT 2.15.0 (GHSA-42vr-xj54-vc7v), anyio 4.14.2 (GHSA-82r6-8w77-94w6).

### Changed

- The image installs a complete dependency lock with hashes (`requirements-lock.txt`), transitive dependencies included; the unit tests run on that same lock.

### Documentation

- Comments and documentation point only at files shipped in this repository.
