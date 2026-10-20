# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

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
- Every module's write journal records what a route says changed; one journal implementation
- A provider sign-in marks the account as the provider's; the token closes once such an admin exists (auth)
- A role change says what changed to the module's write journal (users)
- The last-admin guard locks the admin rows; one journal entry per change (users)
- A refused sign-in says why — awaiting approval, disabled, domain not allowed (login)
- Exact masking docstring; contract checks proxy_common never forces allow_private (proxy)
- Mask a token user name with an empty password, redact credentials in any case, contract reads the validator's AST (proxy)
- Mask a token-only proxy userinfo, keep credentials out of refusals, leave omitted fields as they are (proxy)
- The settings router reads proxy_common at call time (proxy)
- SMTP credentials from the environment never go to a host saved in the app (shared)
- SMTP host checked with ssrf_guard; an empty host clears the saved config (shared)
- SMTP settings help says what an empty host really does (shared)
- Honour hideAI in the managed settings drawer (shared)
- A restore says which proxy settings it left out
- The custom LLM endpoint check follows the proxy, Watch's assistant reaches the custom LLM
- A restored proxy is validated like a saved one
- The AI agent reaches a custom LLM through the outbound proxy
- AI keys are checked through the proxy being saved, the custom LLM key only with its endpoint
- Status line errors are styled and stay long enough to read
- An unreadable SMTP password is reported once, by Pilot
- A bug met while retrying Pilot's proxy is logged as an error
- A database error at start-up is retried until Pilot's proxy applies, any other error is not swallowed, the backup agent stays exempt
- Pilot's proxy exempts every registry host once normalized, never '*' or a list, and the default modules even when the database is not ready
- Pilot's own outbound calls follow the proxy of its settings, its modules stay direct
- Only the clear button clears a key, validate the custom LLM with its stored key, trim the proxy
- A database not ready at start-up still leaves a readable NO_PROXY
- A database not ready at start-up still leaves a readable NO_PROXY (shared)
- The settings route masks every secret, the custom LLM key included
- A lowercase deployment proxy exempts the internal services too (shared)
- Focus clears a key's bullets again, a clear button removes the key
- An IPv6 range in the deployment's NO_PROXY is left out, it breaks httpx (shared)
- APP_URL is not internal, a deployment's range is kept as written
- APP_URL is not internal, a deployment's range is kept as written (shared)
- A key emptied in the settings screen is sent empty, and clears it
- The deployment's own proxy is the base Pilot overrides, never erased (shared)
- A 405 on the SMTP push is a module without mail, not a failure
- The exception hint says an IPv6 takes no port
- A clear message for an IPv6 exception with a port (shared)
- Hold back an SMTP config whose password is unreadable, report a refused SMTP push and a left-out exception
- Refuse ranges in the proxy exceptions, and hold back a custom LLM whose key is unreadable
- Proxy exceptions take a port or an underscore, refuse ranges, log an unreadable one (shared)
- Validate the proxy settings, and explain the exception list
- Validate proxy exceptions, match ranges and wildcards, keep the deployment's NO_PROXY (shared)
- Internal services bypass the pushed proxy, and an empty push clears a stale row (shared)
- A refused or broken push step no longer hides the rest
- Saving the settings reports the modules the push failed on
- A proxy value is one URL, and an unreadable one is not announced restored (shared)
- Never push a key Pilot cannot decrypt, and push every AI setting
- Push every proxy field, empty included
- Store the outbound proxy pushed by Pilot and restore it at start-up (shared)
- Push every AI key, empty included, and the custom LLM label
- Store the custom LLM label sent with the AI keys (ai)
- Report a refused proxy push, and send the custom LLM with the keys modules store
- Report a module that refuses the custom LLM push
- Tolerate only the missing suite-only file
- Start without the suite-only routes
- Reposition modal dropdowns on scroll; drop audit webapp orphan (ui)
- Actions filter, project form and action modal UX
- Distinguish the most-severe level from the next on charts (ui)
- Remove a connector's dashboard footprint when its config is cleared
- Don't let an empty region mark PSAT as unconfigured
- Degrade the settings panel if the AI catalogue fetch fails
- Drive the settings model dropdown from the shared catalogue

### Changed

- The region check at save reuses _safe_bedrock_region (ai)
- One proxy URL validator in proxy_common, shared by the internal routes and Pilot (proxy)
- Drop pushed_proxy, the scanners no longer need it
- Drop pushed_proxy, the scanners no longer need it (shared)
- Drop bypasses_proxy, only the scanners would use it
- Drop bypasses_proxy, only the scanners would use it (shared)

### Documentation

- What the shared token allows, translated refusals in the users section (users)

### Tests

- The OAuth state guard is checked in the shared sign-in of every module (auth)
- Every proxy_common copy, Pilot's included, passes allow_private on to ssrf_guard (contracts)
- An endpoint saved alone is checked with the stored model
- Follow-ups on the AI agent through the proxy and the restored proxy
- A restored proxy is validated like a saved one
- The AI agent reaches a custom LLM through the outbound proxy
- A partial save or resync is shown as an error, run under node
- AI keys are checked through the proxy being saved, the custom LLM key only with its endpoint
- Status line errors are styled and stay long enough to read
- An unreadable SMTP password is reported once, not per module
- Proxy exception refusals name the entry at fault
- A refused connection at start-up is retried, a bug met while retrying is an error
- A database error at start-up is said and retried, any other error is not swallowed, the backup agent stays exempt
- Resync and backup restore apply Pilot's proxy, registry hosts are normalized, the default modules stay exempt
- Pilot's own outbound calls follow the proxy of its settings, modules stay direct
- Only the clear button clears a key, the custom LLM is validated with its stored key, the proxy is trimmed
- The settings route returns no secret, the custom LLM key included
- Focus clears a key's bullets, typing marks it, a clear button empties it, under node
- A key cleared through the settings route is cleared in the modules
- A key emptied in the screen is sent empty, the custom LLM key pushed is the stored one
- A module without an SMTP route answers 405, which is not a failure
- An unreadable SMTP password, a refused SMTP push and a stored range are reported
- Ranges are refused, an unreadable custom LLM key holds back its endpoint too
- Proxy settings are validated before they are pushed
- A refused or broken push step does not hide the rest
- Saving the settings reports the modules the push failed on
- A key Pilot cannot decrypt never blanks the modules' copy
- Every proxy field goes with each push
- The push carries the custom LLM label and clears provider keys
- A refused proxy push is reported, and the custom LLM survives a module restart
- A module refusing the custom LLM push is reported

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
