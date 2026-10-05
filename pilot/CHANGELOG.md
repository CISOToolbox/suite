# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 1.3.0 — 2026-10-05

### Added

- Export a PSAT campaign's per-user progress as CSV from the KPI detail
- Keep each user's PSAT campaign progress at sync

### Fixed

- Tell the admin when a PSAT run could not refresh the CSV export
- Keep the PSAT export consistent across sync races, casing and large tenants
- Follow every PSAT training when the campaign filter is empty

### Changed

- Index PSAT snapshot rows on the normalised campaign name

### Upgrade note

- A connector set up with an API key but no name filter and no explicit campaign list used to do nothing on sync; it now follows every current training. Each one becomes a completion KPI counted as mandatory, raises an overdue measure while overdue users remain, and feeds the Access awareness proof for the configured e-mail domains (every user when none is set). Set a name filter or an explicit campaign list to narrow the scope.

## 1.2.1 — 2026-10-03

### Maintenance

- `constraints.txt` pins semgrep 1.179.0 and `tests/check-deps-drift.sh` no longer carries a PyJWT exception; the image content is unchanged.

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
