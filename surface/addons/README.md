# Surface add-on scanners — authoritative guide

This is the **reference** for how Surface add-ons work (for any future session
touching them). It covers the registration contract, runtime discovery,
per-target config & secrets, the **in-app help** mechanism, build/packaging,
and propagation rules.

## TL;DR

- **Every scanner is an add-on module** — even the built-in ones. `scanners.py`
  is just the engine (registry + loader + dispatcher + cross-cutting config);
  it contains **no scanner logic**. Shared helpers live in `src/scan_common.py`.
- Three tiers under `addons/`:
  - **`core/<name>/`** — always-on built-in scanners (nmap, tls, tls_grade,
    ct_logs, dns_brute, takeover, email_security, typosquatting,
    sensitive_files, security_headers, js_analysis, discovery). **Bundled in
    every image** (the standard Dockerfile COPYs `addons/core` into
    `/app/addons`) and **synced to `backend-standalone`**. Removable from a slim
    client image via `--exclude-core`.
  - **`generic/<name>/`** — optional, shareable add-ons: heavier / optional
    scanners (`nuclei`, `cve_lookup`, `shodan`, `cloud_buckets`, `screenshot`)
    and the SMB scanners (`smb_scan`, `smb_scan_rs`). **Opt-in** per image;
    **never** bundled by the standard Dockerfile, **never** synced to the public
    standalone build. An optional scanner can still be default-on *when included*
    by declaring `SURFACE_DEFAULT_SCANNERS` (e.g. `nuclei` / `cve_lookup` re-add
    themselves to the host defaults).
  - **`custom/<client>/`** — client-specific add-ons. Opt-in, baked into a
    client image only.
- **The tier is also a licensing boundary.** `core` and `generic` add-ons are
  open source (MIT) and maintained in this tree — an add-on of general use
  belongs in `generic`, where every deployment benefits from it. A `custom`
  add-on **belongs to its organization**: it encodes internal integrations or
  non-public knowledge, lives in the organization's private repo (staged at
  build time via `build-client-image.sh --custom-dir`, never committed here),
  and keeps whatever license its owner chooses — MIT imposes no copyleft, so
  a custom add-on never has to be published.
- Everything an add-on contributes (scanner callable, a new target `kind` like
  `file_share`, the in-app help doc) is **discovered at runtime** from the
  module — no engine change needed to add or remove one.

## 1. Module contract

A scanner module exposes two module-level dicts:

```python
SURFACE_SCANNERS = {
    "<name>": {
        "label": "Human label",
        "kinds": {"file_share"},      # target kinds this scanner applies to.
                                      # A NEW kind (e.g. file_share) is created
                                      # just by being named here — see §3.
        "callable": scan_fn,          # see calling conventions below
        "returns_discovered": False,  # True if callable returns (findings, [discovered_hosts])
        "wants_config": True,         # callable gets (value, asset_config)
        "wants_prior_findings": False,# callable gets (value, prior_findings)
        "doc": _DOC,                  # optional in-app help — see §5
    },
}
SURFACE_DEFAULT_SCANNERS = {"file_share": ["<name>"]}  # default scanners per kind
```

**Calling conventions** (resolved in `src/scanners.py:_run_scanners_inner`):
- default: `callable(value)`
- `wants_prior_findings`: `callable(value, prior_findings)`
- `wants_config`: `callable(value, asset_config)`  ← config is `MonitoredAsset.config` (JSONB)

A scanner returns a `list[dict]` of findings (or `(findings, discovered)` when
`returns_discovered`). Each finding dict: `scanner, type, severity, title,
description, target, evidence`.

> **Dedup identity** = `dedup_key = scanner|type|target` (see
> `src/findings_dedup.py`). If one `target` can legitimately yield several
> distinct findings (e.g. several secret rules matching the same file), vary
> the `type` so they don't collapse. `smb_scan_rs` sets `type` = rule name and
> keeps `target` = the file's UNC path for exactly this reason.

## 2. Runtime discovery

`src/scanners.py:_load_addon_scanners()` (called at import) walks every dir in
`SURFACE_ADDON_PATHS` (+ `/app/addons`, recursively), imports each `*.py`
(skipping `_*`, `test_*`, `conftest.py`), and merges its `SURFACE_SCANNERS` /
`SURFACE_DEFAULT_SCANNERS` into `SCANNER_REGISTRY` / `DEFAULT_SCANNERS_BY_KIND`.
A broken add-on (e.g. missing dependency) is logged and skipped — it never
crashes boot. The whole registry `entry` dict is stored verbatim, so any extra
key you add (like `doc`) is preserved.

`SURFACE_ADDON_PATHS` is set by the add-on overlay Dockerfile to `/app/addons`.

## 3. Target kinds are catalogue-driven

`GET /api/monitored-assets/scanners-catalog` returns the base kinds
(`domain`, `host`, `ip_range`) **plus any extra kind** named in a loaded
scanner's `kinds` (e.g. `file_share`). The add-target UI builds its radios from
this catalog, so **"Partage de fichiers" only appears when the SMB add-on is
loaded**. Backend create/patch validate the kind against the same catalog
(`_validate_kind` in `routes/monitored.py`).

## 4. Per-target config & secrets

Non-secret options live in `MonitoredAsset.config` (JSONB, migration `010`)
and reach the scanner via `wants_config`. Secrets (e.g. the SMB password) are
**encrypted at rest** with `src/crypto.py` (AES-256-GCM + PBKDF2, key from
`ENCRYPTION_KEY`):

- On write, `routes/monitored.py:_merge_config_secrets` encrypts
  `smb_password` → `smb_password_enc` and preserves it across PATCH when the
  field is left empty.
- On read, `_redact_config_out` strips `*_enc` and exposes a boolean
  `smb_password_set` so the UI can show "set / not set" without leaking.
- The scanner decrypts at scan time; plaintext is never stored or returned.

## 5. In-app help for add-ons (TRUE conditional doc)

The Méthodologie / Utilisation help tabs must show an add-on's documentation
**only when that add-on is installed — and not even ship the text otherwise.**
So add-on help does **NOT** live in the core i18n bundle. Instead:

1. The add-on declares a bilingual `doc` in its registry entry:
   ```python
   _DOC = {"fr": {"methodo": "<html>", "usage": "<html>"},
           "en": {"methodo": "<html>", "usage": "<html>"}}
   SURFACE_SCANNERS["<name>"]["doc"] = _DOC
   ```
   Keep it **developer-authored HTML only** (no user input). Use `\\\\` for a
   literal `\\` in UNC paths inside Python strings.
2. `src/scanners.py:addon_help_docs()` collects `{scanner, kinds, doc}` for
   every loaded scanner that has a `doc`.
3. `GET /api/monitored-assets/addon-docs` returns them — `[]` on a core image
   (nothing bundled, nothing served).
4. Frontend (`Surface_app.ts`): `_loadAddonHelpDocs()` fetches once and
   `_renderAddonHelpDocs()` injects the HTML (current language) into
   `#help-content-methodo` / `#help-content-usage`, tagging nodes
   `data-addon-injected`. It re-runs on every `renderPanel` (covers boot,
   navigation, and `switchLang` — which resets the tabs' `data-i18n-html` and
   wipes injected nodes, so we re-add them in the new language).

Net effect: the public/suite image's JS bundle and `/addon-docs` response
contain **zero** add-on doc text; the client image with the add-on serves it.

## 6. Build & packaging

- The **standard `Dockerfile`** is **lean** (~286 MB): it bundles `addons/core`
  (`COPY addons/core/ addons/core/`) and `requirements.txt`, plus `nmap`, but
  **no** heavy/optional binaries (no nuclei, no Playwright/Chromium). Every image
  (suite, public standalone, client) ships the always-on core scanner set only.
- `Dockerfile.addons` overlays **optional** add-ons on top of the core image:
  `FROM <core>`, `USER root`, `COPY .client-addons/ /app/addons/`, then in one
  layer: drop any `ARG EXCLUDE_CORE` dirs, install each add-on's
  `apt-packages.txt` (system libs), `requirements.txt` (pip), run each add-on's
  **`install.sh`** (heavy binaries — e.g. `nuclei/install.sh` downloads the
  arch-correct nuclei binary + templates via python; `screenshot/install.sh`
  runs `playwright install chromium`), `chmod` bundled `bin/*`, `chown`, `USER
  surface`, `ENV SURFACE_ADDON_PATHS=/app/addons`. **So a scanner's heavy deps
  exist only in images that include its add-on** — e.g. nuclei/Chromium are
  absent from the lean base and from a client image that doesn't select them.
  Add-on packaging hooks (all optional, picked up automatically): `bin/<arch>`
  binaries, `apt-packages.txt`, `requirements.txt`, `install.sh`.
- `shared/build-client-image.sh <client> --module surface --addons generic/smb_scan_rs`
  builds the core (with `addons/core` baked in) then overlays the selected
  optional add-ons → `ciso-surface-<client>:<tag>`.
- **Suite vs client policy:**
  - **Suite image** (the integrated governance / test environment) = **the most
    complete**: build it with **all** generic add-ons. Since `build-client-image.sh`
    defaults `--addons` to `generic` (all) when omitted, the suite is simply
    `build-client-image.sh suite --module surface` → core + every generic scanner
    (nuclei, cve_lookup, shodan, cloud_buckets, screenshot, smb_scan, smb_scan_rs)
    with their heavy deps installed by the overlay. `docker-compose.yml`
    references `ciso-surface-suite:latest`.
  - **Client images** = **strictly what the client needs** — pass an explicit,
    minimal `--addons` (and optionally `--exclude-core`). e.g. acme below.
  - The **public standalone** stays lean/core-only (synced `addons/core`); add
    generic add-ons only if a standalone deployment wants them.
- **Slim client builds** — drop unwanted core scanners with `--exclude-core`:
  ```
  shared/build-client-image.sh acme --module surface \
      --addons generic/smb_scan_rs --exclude-core shodan,cloud_buckets --tag v0.1.2
  ```
  → `ciso-surface-acme:v0.1.2` = all core scanners **except** `shodan` +
  `cloud_buckets`, **plus** the SMB add-on. Excluded scanners simply don't
  register, so the add-target UI / catalog never offers them (they are opt-in
  scanners, never in `DEFAULT_SCANNERS_BY_KIND`, so nothing dangles). The dir
  name passed to `--exclude-core` is the `addons/core/<name>` folder, which may
  hold several registry entries (e.g. `shodan` → `shodan_domain` +
  `shodan_host`; `nmap` → `nmap_quick/standard/deep`).
- **Multi-arch for GHCR**: `podman build --platform linux/amd64,linux/arm64
  --manifest …` then `podman manifest push --all` (see root `CLAUDE.md` §6).
  With `--exclude-core`, pass the same args to the manifest build (the overlay
  Dockerfile honours `--build-arg EXCLUDE_CORE="shodan cloud_buckets"`).

## 7. Propagation rules (important)

- **`addons/core` IS synced** to `backend-standalone/<module>/addons/core` by
  `sync-backend-modules.sh` (they are built-ins the standalone image needs).
- **`addons/generic` and `addons/custom` are NEVER synced** — they are opt-in
  and must not leak into the public standalone build. Propagate them only by
  building a client/suite image.
- Edit add-on source here (`backend-clients/demo-docker/surface/addons/…`) —
  the source of truth. `src/scan_common.py` (shared helpers) is synced via the
  normal `src/` path.

## Layout

```
addons/
├── README.md                      ← this file
├── core/<name>/<name>.py          ← built-in scanners (bundled everywhere, synced)
├── generic/<name>/<name>.py       ← optional shareable scanners (opt-in)
└── custom/<client>/<name>.py      ← client-specific scanners (opt-in)
```

See `core/email_security/` for a minimal reference, and `generic/smb_scan_rs/` for
a full-featured one (content scan with document body extraction, per-target
encrypted credentials, incremental cache, host roll-up, conditional in-app
help).
