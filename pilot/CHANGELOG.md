# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 1.2.0 — 2026-10-03

### Added

- Non-conformity and derogation register: declare a non-conformity on one or several items, carry its remediation with corrective measures, or grant a time-boxed derogation; a derogation never counts as compliant.
- Register actions follow the module role and the projects the user may read; a read-only account writes nothing.
- Linked measures show their status, open for editing from the record, and must be done before the record closes.
- Consolidated non-conformity and derogation register, read live from the modules, with links that open each record in its module.
- Consolidated group cards move on the measures kanban.

### Fixed

- A group move on the kanban reloads the measures, reports write-back errors and refuses the cancelled column.
- A module without a register answers 404 on the relay; relayed refusals reach the user.
- Forms lay out on the shared form grid and collapse to one column below 768 px; checkboxes sit on the line of their label.
- Muted text keeps AA contrast on every background; one shared signed-in user block in the toolbar.
- Picking a person closes the result list.
- Security updates: PyJWT 2.15.0 (GHSA-42vr-xj54-vc7v), urllib3 2.8.0, anyio 4.14.2 (GHSA-82r6-8w77-94w6).

### Changed

- The image installs a complete dependency lock with hashes (`requirements-lock.txt`), transitive dependencies included; the unit tests run on that same lock.

### Documentation

- Comments and documentation point only at files shipped in this repository.
