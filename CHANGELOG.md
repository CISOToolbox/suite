# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

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
