# Release & versioning

CISO Toolbox follows a **distribution model**: every module is an
independent product with its own version, and the suite is a *composition*
that pins a coherent set of them. This document is the contract — it says
what a number means, who owns it, and what must be true before a tag.

## Two levels, two meanings

| | Owner | Where the number lives | Meaning |
|---|---|---|---|
| **Module version** | the module | `<module>/VERSION` | The state of that module's code. Tagged in its own repo (`CISOToolbox/<module>`), baked into both of its images |
| **Suite version** | the suite | `VERSION` (repo root) | The composition: which module versions are shipped together, plus the integration layer (compose, nginx, Pilot wiring, docs) |

Both use **SemVer** (`MAJOR.MINOR.PATCH`), and they move **independently**:
a module release does not force a suite release, and a suite release does
not renumber modules that did not change.

### Module version — when to bump

- **MAJOR** — a breaking change for consumers: an HTTP API contract, the
  exported data model in a way older files cannot be migrated, a required
  environment variable, a removed feature.
- **MINOR** — a new feature, backward compatible (including a new
  `schema_rev` with its migration: old exports still load).
- **PATCH** — a fix with no contract change.

**Removing an add-on: MAJOR or MINOR?** It depends on who could depend on
it, not on how much code disappears. A `core/` scanner, or any capability
of the **public standalone build**, is something an outside user may have
built on: removing it is a **MAJOR**. A `generic/` or `custom/` add-on that
only ever shipped in the suite or in a client image has no external
consumer, so removing it is a **MINOR** — this is what was decided when
`generic/smb_scan` (Python) was dropped in favour of `generic/smb_scan_rs`.
Note the capability delta in the release notes either way: that removal
cost PDF *body* extraction on file shares, which matters to whoever ran it.

The number is the **same in both of the module's images** — they are the
same release, packaged twice:

```
ghcr.io/cisotoolbox/ciso-<module>:vX.Y.Z          # public standalone build
ghcr.io/cisotoolbox/ciso-<module>-suite:vX.Y.Z    # suite build (+ integration routes)
```

`PRODUCT_VERSION` is baked from `<module>/VERSION` at build time. It is not
decorative: `version_common.py` exposes it and the backup machinery refuses
to restore an archive produced by a **newer** version, so a wrong number
breaks restores.

### Suite version — when to bump

- **MAJOR** — the composition breaks: a cross-module contract changes
  (authentication, Pilot internal APIs, backup format), or an upgrade
  requires an ordered procedure.
- **MINOR** — modules gain features, a module joins or leaves the
  composition, the integration layer gains capabilities.
- **PATCH** — fixes only.

## Version numbers that are NOT the product version

Three identifiers coexist and must never be conflated:

| Identifier | Scope | Source of truth |
|---|---|---|
| `PRODUCT_VERSION` | the release | `<module>/VERSION` |
| Alembic revision | the database schema | `alembic_version` table (the live DB) |
| `meta.schema_rev` | the **exported** data model | the app's `SCHEMA_REV` (FEAT-36) |

A module can ship several releases without touching its database schema,
and can bump `schema_rev` in a MINOR release as long as older exports still
migrate (they must — see the export durability guarantee).

## Compatibility: the suite release IS the manifest

The suite's `docker-compose.yml` pins an explicit image tag per module. A
suite tag therefore describes exactly one tested combination, and the
matrix below (kept in this repo) makes it readable:

| Suite | Pilot | Risk | Compliance | Audit | Vendor | Asset | Access | Surface | AppSec | Watch |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.9.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 |
| 0.9.1 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.1 | 1.0.0 |
| 0.9.2 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.1.0 | 1.0.0 |
| 0.9.3 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.0.0 | 1.1.0 | 1.0.0 |
| 0.9.4 | 1.1.0 | 1.0.1 | 1.0.1 | 1.0.1 | 1.1.1 | 1.0.1 | 1.1.0 | 1.1.0 | 1.1.1 | 1.0.1 |
| 0.10.0 | 1.1.1 | 1.0.2 | 1.0.2 | 1.0.2 | 1.1.2 | 1.0.2 | 1.1.1 | 1.3.0 | 1.1.2 | 1.0.2 |
| 0.10.1 | 1.1.2 | 1.0.3 | 1.0.3 | 1.0.3 | 1.1.3 | 1.0.3 | 1.1.2 | 1.3.1 | 1.1.3 | 1.0.3 |
| 0.11.0 | 1.1.3 | 1.0.4 | 1.0.4 | 1.0.4 | 1.2.0 | 1.1.0 | 1.2.0 | 1.4.0 | 1.1.4 | 1.0.4 |

Rules that keep the two levels coherent:

1. A module version is published **first** (tag + images), then a suite
   release may pin it. The suite never pins a tag that does not exist.
2. The suite repo and the standalone repos carry the **same module code**.
   The two trees must be identical before any tag — otherwise the two repos
   would ship different code under the same number.
3. Every suite release updates the matrix above, in the same commit as the
   compose pins.

`tools/release-check.sh` checks versions, pins, matrix and changelog offline;
`--remote` adds rule 1 (every pinned tag exists on its module repository)
and the multi-arch images on GHCR; `--strict` requires each pin to equal the
module's VERSION (release time — between two suite releases a module VERSION
may run ahead of its pin). CI runs `--remote` and `tools/pin-images.sh --check`
on every pull request, with `--strict` on `release/*` branches.

## Release procedure

**The tag is the release.** A module or suite version exists once its
annotated tag `vX.Y.Z` is on the public repository: that tag is the commit the
images were built for, what the compose pins, and what a deployment checks
out. An image without its tag, or a tag on the wrong repository, is not a
release.

**A module** version exists once its tag `vX.Y.Z` and both images are on
`CISOToolbox/<module>` and GHCR; this repository only consumes the result
(rule 1 above).

**The suite** — after every module it pins is tagged:

1. `VERSION` → `X.Y.Z`; every `image:` in `docker-compose.yml` points at
   `ciso-<module>-suite:v<module VERSION>`; `bash tools/pin-images.sh`
   re-resolves the digests (it fails on an image that is not published).
2. Add the matrix row above and the `## X.Y.Z` section to `CHANGELOG.md`
   (module versions moved, integration changes).
3. `bash tools/release-check.sh --remote --strict` — all green (it refuses a
   version without its changelog section).
4. Open the release as a pull request titled `release: CISO Toolbox suite X.Y.Z`
   (`main` is protected: no direct push, releases included). Merge.
5. Tag the merge commit: `git tag -a vX.Y.Z -m "CISO Toolbox suite X.Y.Z" && git push origin vX.Y.Z`,
   then publish the GitHub release with the changelog section as its notes.

## Current line

The public launch starts the modules at **1.0.0** — they are complete,
production-ready products — and the suite at **0.9.0**: the composition is
published as a **public beta** while the cross-module contracts
(authentication, Pilot internal APIs, backup format) settle. `1.0.0` will
mark the moment those contracts are frozen.
