# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 1.4.1 — 2026-10-23

### Fixed

- A composed character is dispatched once in the Firefox and Safari event order too (socle)
- A character composed with a dead key or an IME is dispatched once, complete (socle)

### Maintenance

- Socle composition dedup (propagation)

## 1.4.0 — 2026-10-20

### Added

- The AI assistant toggle and the module's AI provider in one section, fields usable once the assistant is on (settings)
- One Save button for every section, sections in an exclusive accordion, unsaved changes guarded (settings)
- Remove a provider's saved keys from the settings drawer (ai)
- The settings drawer lets a standalone module's admin set its AI provider, model and keys (ai)
- A standalone module runs its AI on its server, set by its admin; Pilot's in the suite (ai)
- The local account is shown fixed; without an identity provider the section says the module has one account (users)
- The module's key opens one local account, its admin; other accounts come from an identity provider (auth)
- One shared sign-in router for the nine backend modules — identity providers everywhere (auth)
- Users section in the settings of the backend modules (settings)
- User administration router for standalone modules — module roles, pending, disabled, last admin kept (users)
- Standalone accounts await approval, and their role is read from the module on every request (auth)
- Outbound proxy section in the settings of the backend modules (settings)
- The outbound proxy is settable in the module itself when Pilot is absent (proxy)
- SMTP settings in the standalone modules (shared)
- Redirect policy in the target dialog
- Export_proxy, for a proxy kept outside the proxy.* rows (Pilot's own) (shared)
- Distinguish "not assessed" from 0 in the criticality formula
- Refresh the AI model catalogue (ai)

### Fixed

- No multi-tenant Entra default — an unset tenant is empty, and the README says it is required (auth)
- A module menu opened before the module learns it is standalone is closed (chrome)
- A standalone module lists only itself in the module switcher (chrome)
- A given-up section drops its error; AI provider input typed while the assistant is off is discarded (settings)
- Every way out of the panel asks before unsaved edits go; one save at a time; a refused or declined change stays pending (settings)
- The module honours ALLOW_INSECURE_CUSTOM_LLM_ENDPOINT at call and at save (ai)
- AI settings are stored as they were checked (ai)
- Pilot's push is stored as Pilot checked it; a module admin's endpoint is checked as the call checks it; keys in clear without ENCRYPTION_KEY (ai)
- One email_verified rule for Google and OIDC; tests for OIDC and the account lock (auth)
- An address the identity provider has not verified is refused (auth)
- Only the key's own account is local; the key never revives an account; account creation serialised (auth)
- A provider sign-in marks the account as the provider's; the token closes once such an admin exists (auth)
- A role change says what changed to the module's write journal (users)
- The shared token closes once an admin signs in through the identity provider (auth)
- The last-admin guard locks the admin rows; one journal entry per change (users)
- With an identity provider configured, the shared token only creates the first account (auth)
- A refused sign-in says why — awaiting approval, disabled, domain not allowed (login)
- AppSec, Surface, Watch and Audit sign-in pages show their own name (login)
- Exact masking docstring; contract checks proxy_common never forces allow_private (proxy)
- Mask a token user name with an empty password, redact credentials in any case, contract reads the validator's AST (proxy)
- Mask a token-only proxy userinfo, keep credentials out of refusals, leave omitted fields as they are (proxy)
- The settings router reads proxy_common at call time (proxy)
- SMTP credentials from the environment never go to a host saved in the app (shared)
- SMTP host checked with ssrf_guard; an empty host clears the saved config (shared)
- SMTP settings help says what an empty host really does (shared)
- Honour hideAI in the managed settings drawer (shared)
- Resolve SMTP from the environment when Pilot is absent
- The custom LLM endpoint check follows the proxy, Watch's assistant reaches the custom LLM
- The AI agent reaches a custom LLM through the outbound proxy
- Status line errors are styled and stay long enough to read
- Pilot's proxy exempts every registry host once normalized, never '*' or a list, and the default modules even when the database is not ready
- A database not ready at start-up still leaves a readable NO_PROXY
- A database not ready at start-up still leaves a readable NO_PROXY (shared)
- A lowercase deployment proxy exempts the internal services too
- A lowercase deployment proxy exempts the internal services too (shared)
- An IPv6 range in the deployment's NO_PROXY is left out, it breaks httpx
- An IPv6 range in the deployment's NO_PROXY is left out, it breaks httpx (shared)
- APP_URL is not internal, a deployment's range is kept as written
- APP_URL is not internal, a deployment's range is kept as written (shared)
- The deployment's own proxy is the base Pilot overrides, never erased
- The deployment's own proxy is the base Pilot overrides, never erased (shared)
- A clear message for an IPv6 exception with a port
- A clear message for an IPv6 exception with a port (shared)
- Proxy exceptions take a port or an underscore, refuse ranges, log an unreadable one
- Proxy exceptions take a port or an underscore, refuse ranges, log an unreadable one (shared)
- Validate proxy exceptions, match ranges and wildcards, keep the deployment's NO_PROXY
- Validate proxy exceptions, match ranges and wildcards, keep the deployment's NO_PROXY (shared)
- Internal services bypass the pushed proxy, and an empty push clears a stale row
- Internal services bypass the pushed proxy, and an empty push clears a stale row (shared)
- One URL per proxy value, keep the pushed proxy out of backups, say when it cannot be decrypted
- A proxy value is one URL, and an unreadable one is not announced restored (shared)
- Keep the pushed proxy across restarts, and let Pilot clear it
- Store the outbound proxy pushed by Pilot and restore it at start-up (shared)
- Store the custom LLM label sent with the AI keys (ai)
- Accept the outbound proxy pushed by Pilot
- Tolerate only the missing suite-only file
- Start without the suite-only routes
- Reposition modal dropdowns on scroll; drop audit webapp orphan (ui)
- Actions filter, project form and action modal UX
- Distinguish the most-severe level from the next on charts (ui)
- Remove a connector's dashboard footprint when its config is cleared

### Changed

- The region check at save reuses _safe_bedrock_region (ai)
- One proxy URL validator in proxy_common, shared by the internal routes and Pilot (proxy)
- Drop pushed_proxy, the scanners no longer need it
- Drop pushed_proxy, the scanners no longer need it (shared)
- Drop bypasses_proxy, and read the deployment's NO_PROXY at start-up in the test
- Drop bypasses_proxy, only the scanners would use it (shared)

### Documentation

- What the shared token allows, translated refusals in the users section (users)

### Tests

- The http opt-out never reaches a private address, and accepts the values Pilot accepts (ai)
- The operator's http opt-out for a custom LLM reaches the module (ai)
- An admin that came from Pilot does not close the shared token (auth)
- Pin the session key in the standalone users tests, whatever the import order (users)
- Every proxy_common copy, Pilot's included, passes allow_private on to ssrf_guard (contracts)
- Proxy exception refusals name the entry at fault
- A database not ready at start-up leaves a readable NO_PROXY, external URLs are not internal
- A restart starts from the stored rows, a lowercase deployment proxy exempts the internal services
- An IPv6 range in the deployment's NO_PROXY is left out, logged
- APP_URL is not internal, a deployment's range is kept, the shell's proxy never leaks in
- The deployment's own proxy is the base Pilot overrides, http_proxy covered too
- Proxy exceptions with a port or an underscore are kept, ranges are refused, an unreadable one is logged
- Proxy exceptions are validated, matched with ranges and wildcards, and the deployment's kept
- Internal services bypass the pushed proxy, a stale row clears, logs hold the host only
- A proxy value is one URL, and an unreadable one is not announced restored
- The pushed proxy is stored, restored at start-up and clearable
- The outbound proxy pushed by Pilot reaches the module

### Maintenance

- Proxy_common gains export_proxy (unused here)

## 1.3.0 — 2026-10-05

### Added

- Unpack Opengrep at build time, ship its LGPL text and an SBOM of what it bundles
- Show a finding closed by the SAST engine change, with its former status
- House SAST rules — GitHub-owned actions pinned by SHA, Renovate release age
- Carry Semgrep-era SAST findings over, keep the others readable 30 days
- The SAST scanner is called sast
- SAST runs Opengrep on rules built into the image

### Fixed

- Kill a scanner started during or after shutdown
- Stop running scanners on shutdown and never wait on held pipes
- Stop a timed-out scanner's whole process tree
- Keep the dot in pypi purls of the Opengrep SBOM
- Give each Opengrep run its own temporary directory
- Rename a duplicated rule id on its own line only
- Describe what the Opengrep binary really bundles, not its dev lock
- Give rules sharing an id in one directory distinct names
- Stop reading rule ids at the next top-level key
- Index every rule id of a file; run Opengrep from a writable, persistent HOME
- Decide the Semgrep-era carry-over once, keep each former status

### Tests

- Make the scanner shutdown tests deterministic
- SBOM from the bundled listing, rename scope
- Rule ids, renamed collisions, Opengrep SBOM
- A former verdict never reaches later code; real fingerprints carried over
- SAST identity, rule names, re-keying, purge and reopening

## 1.2.1 — 2026-10-03

### Fixed

- semgrep 1.179.0: its environment now runs PyJWT 2.15.0, like the module, instead of 2.13.0 (CVE-2026-102268 and related HIGH findings).
- trivy 0.75.0 in the image (0.70.0 carried 50 HIGH findings in its own dependencies), checked against the official sha256.

## 1.2.0 — 2026-10-03

### Added

- Non-conformity and derogation register: declare a non-conformity on one or several items, carry its remediation with corrective measures, or grant a time-boxed derogation; a derogation never counts as compliant.
- Register actions follow the module role and the projects the user may read; a read-only account writes nothing.
- Linked measures show their status, open for editing from the record, and must be done before the record closes.

### Fixed

- Semgrep 1.177.0 runs in its own virtual environment, installed from a hashed lock.
- Malformed Semgrep rule metadata never breaks a scan; a low-confidence rule with likelihood at most medium rates low.
- Forms lay out on the shared form grid and collapse to one column below 768 px; checkboxes sit on the line of their label.
- Muted text keeps AA contrast on every background; one shared signed-in user block in the toolbar.
- Picking a person closes the result list.
- Security updates: PyJWT 2.15.0 (GHSA-42vr-xj54-vc7v), anyio 4.14.2 (GHSA-82r6-8w77-94w6).

### Changed

- The image installs a complete dependency lock with hashes (`requirements-lock.txt`), transitive dependencies included; the unit tests run on that same lock.

### Documentation

- Comments and documentation point only at files shipped in this repository.
