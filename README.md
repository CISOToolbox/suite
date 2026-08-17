# CISO Toolbox — Suite

Full-stack security governance platform: **9 domain modules + the Pilot
hub**, nginx reverse proxy, one PostgreSQL per module, centralized
authentication and orchestration via Pilot, point-in-time backups
(pgBackRest) with granular restore from the Pilot UI.

**Docker Compose is the reference deployment** and the one documented
here; the modules are plain containers, so other orchestrators
(Kubernetes, OpenShift) are on the roadmap.

## One suite: nine autonomous modules, one hub

CISO Toolbox is **modular by design**: each of the nine application modules
(Risk, Vendor, Compliance, Audit, Access, Asset, Surface, AppSec, Watch) is a
self-contained product — own database, own API, own frontend — that can run
alone or plug into the suite. **Pilot is different**: it is not another
domain module but the **hub of the suite** — it only makes sense alongside
the modules it orchestrates, where it adds what only a suite can offer:
single sign-on, a user directory shared across modules, a consolidated
action plan, centralized backups and point-in-time restore, a global posture
dashboard and KPIs, and email digests of upcoming deadlines.

**If you only need ONE module**, you don't need this repository — every
domain module also ships as a **standalone repo** (its own
`docker-compose.yml`, `.env.example` and `STANDALONE.md`; accounts,
PostgreSQL and API included), and four of them additionally ship a
**browser-only webapp** (no server at all: open the page, work, export
JSON — nothing is sent anywhere) living in the **`webapp/` directory of
the same module repo** and hosted on cisotoolbox.org:

| Module | What it does | Standalone repo | Browser-only |
|---|---|---|---|
| **Risk** | EBIOS RM risk analysis: scenarios, security measures, risk matrix | [CISOToolbox/risk](https://github.com/CISOToolbox/risk) | [risk.cisotoolbox.org](https://risk.cisotoolbox.org) |
| **Compliance** | Multi-framework compliance (ISO 27001, NIS2, DORA…): controls, measures, proofs | [CISOToolbox/compliance](https://github.com/CISOToolbox/compliance) | [compliance.cisotoolbox.org](https://compliance.cisotoolbox.org) |
| **Audit** | ISO 27001 audits: findings, corrective actions, reports | [CISOToolbox/audit](https://github.com/CISOToolbox/audit) | [audit.cisotoolbox.org](https://audit.cisotoolbox.org) |
| **Vendor** | Third-party risk management: assessments, vendor portal, maturity, DORA RoI | [CISOToolbox/vendor](https://github.com/CISOToolbox/vendor) | [vendor.cisotoolbox.org](https://vendor.cisotoolbox.org) |
| **Access** | Access reviews, user lifecycle, identity connectors (AD, Entra, Okta…) | [CISOToolbox/access](https://github.com/CISOToolbox/access) | — |
| **Asset** | Asset inventory with infrastructure connectors (AD, Intune, AWS…) and cross-connector dedup | [CISOToolbox/asset](https://github.com/CISOToolbox/asset) | — |
| **Surface** | External attack surface monitoring: DNS, TLS, exposed services, add-on scanners | [CISOToolbox/surface](https://github.com/CISOToolbox/surface) | — |
| **AppSec** | Application security: SCA/image scans (Trivy), secrets (Gitleaks), SAST (Semgrep), SBOM | [CISOToolbox/appsec](https://github.com/CISOToolbox/appsec) | — |
| **Watch** | Vulnerability & threat watch: CVE/KEV feeds, scopes, alert triage, email digests | [CISOToolbox/watch](https://github.com/CISOToolbox/watch) | — |
| **Phish** | Authorised phishing simulations: campaigns, templates, landing pages, awareness reporting | [CISOToolbox/phish](https://github.com/CISOToolbox/phish) | — |

The suite (this repo) is for organizations that want several modules working
**together**: measures raised in any module flow up into Pilot's consolidated
action plan, identities are provisioned from Pilot's directory, and one
restore UI covers every module.

## Architecture

```
                        ┌──────────────┐
                        │    nginx     │ :443 (HTTPS)
                        │ reverse proxy│ :80  (→ 443)
                        └──────┬───────┘
                               │  /risk /vendor /compliance /audit /asset
                               │  /access /surface /appsec /watch  /(pilot)
       ┌───────┬───────┬───────┼───────┬───────┬───────┬───────┬───────┬───────┐
       ▼       ▼       ▼       ▼       ▼       ▼       ▼       ▼       ▼       ▼
    ┌──────┬──────┬──────┬──────┬──────┬──────┬───────┬──────┬──────┬───────┐
    │ Risk │Vendor│Compl.│Audit │Pilot │Access│ Asset │Surf. │AppSec│ Watch │
    └──┬───┴──┬───┴──┬───┴──┬───┴──┬───┴──┬───┴──┬────┴──┬───┴──┬───┴──┬────┘
       ▼      ▼      ▼      ▼      ▼      ▼      ▼       ▼      ▼      ▼
     PG 16 × 10 (one instance per module) + backup-agent (pgBackRest, PITR)
```

## Modules

| Module | Path | Description |
|--------|------|-------------|
| **Pilot** | `/` | Central dashboard, user directory, consolidated action plan, KPIs, backups & point-in-time restore |
| **Risk** | `/risk/` | EBIOS RM risk analysis (scenarios, measures, risk matrix) |
| **Vendor** | `/vendor/` | Third-party risk management (assessments, templates, maturity, DORA RoI) |
| **Compliance** | `/compliance/` | Multi-framework compliance (ISO 27001, NIS2, DORA, etc.) |
| **Audit** | `/audit/` | ISO 27001 audits: stored audits, corrective actions, frontend-file import |
| **Access** | `/access/` | Access reviews, user lifecycle, AD/Cloud Temple connectors |
| **Asset** | `/asset/` | Asset inventory, connectors (AD, Intune, AWS, Cloud Temple), cross-connector dedup |
| **Surface** | `/surface/` | Attack surface monitoring (DNS, nuclei, nmap, screenshots) |
| **AppSec** | `/appsec/` | Application security (Trivy SCA/images, Gitleaks secrets, Semgrep SAST, SBOM, ignore rules) |
| **Watch** | `/watch/` | Vulnerability & threat watch (CVE feeds, scopes, alerts, digests) |

## Versioning & releases

Each module is an independent product with its own SemVer version
(`<module>/VERSION`, tagged in its own repo, baked into both of its
images); the suite has its own version (`VERSION`) and its
`docker-compose.yml` pins the module images it ships — a suite release is
therefore a tested, reproducible combination. The full contract (what each
number means, the compatibility matrix, the release procedure and its
guardrail `tools/release-check.sh`) is in [RELEASING.md](RELEASING.md).

Current line: modules **1.0.0**, suite **0.9.0** — the composition is
published as a public beta while the cross-module contracts settle.

## Building a custom deployment

The suite composes **à la carte** — a real deployment is a fork of this repo
with only what you need. The full procedure, from fork to running stack:

### Step 1 — Fork and clone

Fork this repository (one private fork per deployment/client keeps
customizations, chosen modules and image tags under version control), then:

```bash
git clone git@github.com:<you>/<your-fork>.git && cd <your-fork>
bash setup.sh        # generates secrets (.env) + a self-signed TLS cert
```

### Step 2 — Choose your modules

Every module only talks to Pilot, never to its siblings, so **any subset
works** (Pilot itself is required — it carries auth, the directory and the
consolidated action plan).

1. In `docker-compose.yml`, remove (or comment out) each unwanted
   `<module>-app` + `<module>-db` service pair and its volumes.
2. In `.env`, set **`PILOT_MODULES`** to the same subset, e.g.:
   ```bash
   PILOT_MODULES=risk,compliance,vendor
   ```

That's all: Pilot's registry (dashboard, backups, restore, config pushes)
targets only that subset, and every app's header module switcher derives its
list from the registry at runtime — there is **no frontend file to edit**.

### Step 3 — Configure the environment

`setup.sh` pre-fills `.env`; review at least:

| Variable | Why |
|---|---|
| `DB_PASSWORD`, `JWT_SECRET`, `SERVICE_TOKEN`, `ENCRYPTION_KEY` | Generated secrets — keep them ≥ 32 chars. `ENCRYPTION_KEY` encrypts credentials at rest (connectors, SMTP password) |
| `APP_URL` | Public URL of the suite |
| `PUBLIC_BASE_URL` | Same public URL — used to absolutize links in outgoing emails (deadline digests). Leave empty to keep relative links |
| `ENTRA_*` / `GOOGLE_*` / `OIDC_*` | At least one OAuth provider (see *Authentication*) |
| `PILOT_MODULES` | The module subset from step 2 |

Transverse runtime settings (AI provider + keys, SMTP server, egress proxy)
are configured **once in Pilot → Settings** and pushed to every module —
nothing per-module to configure.

### Step 4 — Build module images with the add-ons you need

**You only need this step if you customize what an image contains.** For a
simple deployment or an evaluation, skip it entirely: `docker compose up -d`
uses the **prebuilt images from GHCR**
(`ghcr.io/cisotoolbox/ciso-<module>-suite:latest` — core + all generic
add-ons, ready to run). Building your own images matters when you want a
slimmer footprint, a different add-on selection, or client-specific add-ons.

Heavy or optional capabilities are **add-ons baked at build time**, not
runtime downloads. Add-ons live under `<module>/addons/` in three tiers:

| Tier | Path | Shipped | License / ownership |
|---|---|---|---|
| **core** | `addons/core/<name>/` | Always in every image (can be *excluded* for a slim build) | Open source (MIT), part of the module |
| **generic** | `addons/generic/<name>/` | Opt-in, shareable across deployments | Open source (MIT), maintained in this tree |
| **custom** | `addons/custom/<client>/` | Opt-in, one organization only | **Belongs to that organization** — private, never published |

The tier is a **licensing and sharing boundary**, not just a folder
convention:

- **core** and **generic** add-ons are open source under the suite's MIT
  license. They live in this tree, are reviewed and maintained with the
  product, and benefit every deployment — if you build something of general
  use (a scanner, a connector to a widely-used product), contributing it as
  a `generic` add-on is the right home.
- **custom** add-ons are for capabilities an organization does **not** wish
  to share: integrations with internal tools, proprietary business logic,
  scanners encoding non-public knowledge of the organization's environment.
  They are kept **outside this repository** (in the organization's private
  repo, see step 5), keep whatever license their owner chooses, and are
  baked only into that organization's images — the MIT license of the suite
  imposes nothing on them (no copyleft: a custom add-on never has to be
  published).

Current add-on families:

- **Surface** — scanners. Core: nmap, TLS, CT logs, DNS brute-force,
  takeover, email security, typosquatting, sensitive files, security
  headers, JS analysis, discovery. Generic (opt-in, heavy deps install with
  the add-on): `nuclei`, `cve_lookup`, `shodan`, `cloud_buckets`,
  `screenshot`, `smb_scan`, `smb_scan_rs`. Authoritative contract:
  [`surface/addons/README.md`](surface/addons/README.md).
- **Access** — 22 identity connectors under `access/addons/generic/`
  (full list in the [Connectors](#connectors) section). Enabled **per
  project at runtime** (plugin configs with encrypted credentials): baking
  them in costs little, configure only what you use. Contract:
  [`access/addons/generic/README.md`](access/addons/generic/README.md).
- **Asset** — infrastructure connectors (Active Directory/LDAP, Microsoft
  Intune, AWS, Cloud Temple), compiled in, enabled per project at runtime
  like Access.
- **Pilot** — suite-level KPI connectors (AWS security posture, Microsoft
  365 / Entra ID, Proofpoint PSAT awareness), configured once in
  Pilot → Connectors for the whole suite.

Build with [`tools/build-client-image.sh`](tools/build-client-image.sh):

The examples below build the **Surface** module (`--module surface`) — the
same invocations work for any module that has add-ons (e.g.
`--module access`):

```bash
# Rebuild the reference "suite" image of Surface: core + ALL generic add-ons
# (this is what the published ciso-surface-suite:latest contains)
tools/build-client-image.sh suite --module surface

# A minimal client image of Surface: core + one add-on, minus two core scanners
tools/build-client-image.sh acme --module surface \
    --addons generic/smb_scan_rs --exclude-core shodan,cloud_buckets

# Restrict embedded languages (default ships FR + EN)
tools/build-client-image.sh acme --module surface --langs fr
```

The script builds the lean core image, stages the selected add-on subtrees,
then overlays them via `<module>/Dockerfile.addons` (each add-on's
`install.sh`, `apt-packages.txt` and `requirements.txt` run at that point, so
heavy dependencies exist only in images that include the add-on). Output:
`ciso-<module>-<client>:<tag>`.

### Step 5 — Client-specific add-ons

A client with context-specific add-ons keeps them **in their own private
repository** — client code never enters this tree. Layout convention:

```
<client-private-repo>/
└── <module>-addons/          # e.g. access-addons/
    ├── my_connector.py       # the add-on (module contract, see below)
    ├── requirements.txt      # optional extra Python deps
    └── install.sh            # optional system-level setup (Surface)
```

Point the build at that directory with `--custom-dir`: it is staged as
`addons/custom/<client>/` for the duration of the build and removed
afterwards, so the suite tree stays clean:

```bash
tools/build-client-image.sh acme --module access \
    --custom-dir ../acme-private/access-addons
```

What a custom add-on implements depends on the module:

- **Surface scanner**: a module exposing `SURFACE_SCANNERS` — full contract,
  runtime discovery, per-target encrypted secrets and conditional in-app help
  in [`surface/addons/README.md`](surface/addons/README.md).
- **Access connector**: a subclass of `AccessPlugin`
  (`src/plugins/base.py`) returning `UserRecord`s — see any add-on under
  [`access/addons/generic/`](access/addons/generic/) as a reference.

### Step 6 — Publish and wire the images

Every image pushed to a registry MUST be **multi-arch** (`linux/amd64` +
`linux/arm64`) — single-arch builds break deployments on the other platform:

```bash
# docker buildx (CI or any Docker host)
docker buildx build --platform linux/amd64,linux/arm64 \
    -t ghcr.io/<org>/ciso-<module>-<client>:<tag> --push .

# or rootless podman (qemu binfmt provides the cross-arch emulation)
podman build --platform linux/amd64,linux/arm64 \
    --manifest ghcr.io/<org>/ciso-<module>-<client>:<tag> <module>/
podman manifest push --all ghcr.io/<org>/ciso-<module>-<client>:<tag>
```

Then, in your fork's `docker-compose.yml`, replace the module's `build:`
block with the published image:

```yaml
  surface-app:
    image: ghcr.io/<org>/ciso-surface-acme:v1.0.0
```

Naming convention: `ciso-<module>-suite` (reference, all generic add-ons),
`ciso-<module>` (public standalone, core only), `ciso-<module>-<client>`
(client builds, pulled with credentials scoped to that client's images).

### Languages

Both **English (product default)** and **French** ship in every build; the
UI opens in the browser's language when available and users can switch at
runtime (globe icon, per-browser persistence). `--langs` on the build script
strips languages from a specific image if required (e.g. `--langs en` for an
English-only image). Want to contribute a **new language**? See
[TRANSLATING.md](TRANSLATING.md) — the engine is language-agnostic and a
partial translation degrades gracefully to English.

## Quick Start

```bash
# 1. Clone and setup (generates secrets + self-signed TLS cert)
git clone git@github.com:CISOToolbox/suite.git
cd suite
bash setup.sh
```

### 2. Choose your authentication

Two paths: for anything real, plug an **identity provider** (three
supported, combinable); for a **local evaluation**, one line in `.env`
disables authentication entirely (see below). The suite is **fail-closed**:
with the default `AUTH_MODE=pilot`, modules refuse to start until at least
one provider is configured — there is no *silent* unauthenticated mode, the
no-auth mode is always an explicit opt-in. Each configured provider becomes
a button on the login page:

| Option | When to use | `.env` variables |
|---|---|---|
| **Microsoft Entra ID** (Azure AD) | Your users live in a Microsoft 365 / Azure tenant | `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID` — create an *App registration* in the Azure portal. Set `ENTRA_TENANT_ID` to **your tenant id** to restrict sign-in to your organization (`common` accepts any Microsoft account) |
| **Google OAuth** | Google Workspace organizations | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — create an *OAuth client ID* (web application) in the Google Cloud console |
| **Generic OIDC** | Any OpenID Connect IdP: Keycloak, Authentik, Okta, Ping, ADFS… | `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ISSUER` (the issuer URL, discovery is automatic), `OIDC_LABEL` (text of the login button, default "SSO") |
| **No auth — dev/test ONLY** | Local evaluation without an IdP | `AUTH_MODE=none` — every request is served as admin. Never expose such an instance |

Whichever provider you pick, register the matching **redirect URI** in the
IdP: `https://<your-domain>/auth/callback/entra` (or `/google`, `/oidc`).

**Trying the suite without any IdP** — set a single line in `.env`:

```bash
AUTH_MODE=none
```

No login page, every request is served with admin rights, all modules boot
without any credential. This is the fastest way to evaluate the suite on a
laptop, and what the demo data targets. Consequences to know: there are no
user accounts, so per-user features are inert (role assignments, the
per-user notification preferences and deadline digests need a real
identity), and objects are created without an owner. **Never expose an
`AUTH_MODE=none` instance beyond localhost** — switching to real auth later
is just configuring a provider and removing the line.

Sign-in flow: the **first user to log in is auto-promoted admin**; every
later signup lands in the `pending` role (no access) until an admin assigns
their per-module roles in **Pilot → Users**. Details — token derivation, role
model, per-module tiers — in [Authentication](#authentication).

```bash
# 3. Start all services
docker compose up -d

# 4. Open (first user gets admin role automatically)
open https://localhost
```

## Authentication

All modules delegate authentication to Pilot (`AUTH_MODE=pilot`). Pilot supports:

- **Microsoft Entra ID** (Azure AD) — `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`
- **Google OAuth** — `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- **Generic OIDC** — `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ISSUER`

### Session tokens: one derived key per module

`JWT_SECRET` is never used as a signing key directly. Each trust domain gets
its own key, derived with HKDF-SHA256:

```
key(module) = HKDF(JWT_SECRET, salt="ciso-suite/jwt-key/v1", info="ciso-module:<module>")
key(pilot)  = HKDF(JWT_SECRET, salt="ciso-suite/jwt-key/v1", info="ciso-suite")
```

At login Pilot issues **one token per module** (`aud=ciso-module:<module>`),
each signed with that module's key and stored in its own cookie
(`<module>_token`, scoped to `Path=/<module>/` — the path nginx proxies to
that module). Single sign-on is unchanged for the user: one login still opens
every module. What changes is the blast radius — a compromised module holds
only its own derived key, so it can no longer forge sessions for the other
modules, and HKDF being one-way it cannot recover `JWT_SECRET` either. In
`AUTH_MODE=standalone` a module signs its own tokens with the same derived
key (`iss=ciso-<module>`), so a standalone token is not valid on any other
module.

No extra environment variable: the keys are derived at startup. `MODULE_NAME`
becomes mandatory in `AUTH_MODE=pilot` (it selects the key and the cookie) and
a module refuses to start without it. `MODULE_COOKIE` names the cookie in
standalone mode only. Rotating `JWT_SECRET` rotates every derived key and logs
everyone out.

### OAuth Redirect URIs

Register these in your identity provider:

```
https://<your-domain>/auth/callback/entra
https://<your-domain>/auth/callback/google
https://<your-domain>/auth/callback/oidc
```

### Role model

Access control has **two levels**: a suite-level role on the Pilot account,
and one role per module, assigned in **Pilot > Users**.

**Suite-level roles** (the Pilot account itself):

| Role | Scope | Assigned by |
|------|-------|-------------|
| `admin` | Full access to every module + user management, settings, backups & restore | First user auto-promoted; others set by admin |
| `user` | Only the modules where a per-module role was assigned (no role = no access, 403) | Admin assigns per-module roles |
| `viewer` | Read-only on every module (maps to the read tier everywhere) | Set by admin |
| `pending` | No access (awaiting admin approval) | Default for new signups |

**Per-module roles.** Each module names its roles after its own domain, but
they all map onto the same three permission tiers (enforced in
`auth_common.py`):

| Tier | Grants | Role names |
|------|--------|-----------|
| **read** | consult everything in the module | `viewer`, `reader` |
| **triage** | read + act on **existing** objects: finding status, justifications, linked remediation measures — no create/delete, no configuration | `triager` (Surface, AppSec) |
| **write** | read + create/edit the module's objects | `editor`, `contributor`, `manager` |
| **admin** | write + delete/share projects + module settings (scan config, directory source, AI) | `admin`, `control` |

What Pilot > Users offers per module, and what each role is for:

| Module | Roles (increasing rights) | The intermediate role allows |
|--------|---------------------------|------------------------------|
| **Risk** | `viewer` → `editor` → `admin` | create/edit analyses, scenarios, security measures |
| **Vendor** | `viewer` → `manager` → `control`/`admin` | `manager`: vendors, assessments, action plans. `control` (internal-controls team) is admin-equivalent: assessment validation, delete/share |
| **Compliance** | `viewer` → `editor` → `admin` | controls, remediation measures, evidences |
| **Audit** | `viewer` → `editor` → `admin` | audits, findings, corrective actions |
| **Asset** | `viewer` → `contributor` → `admin` | inventory entries; connectors stay admin |
| **Access** | `manager` → `control`/`admin` | `manager`: review campaigns, decisions. `control` is admin-equivalent: sign-off, delete/share. No read-only role — every Access user acts on reviews |
| **Surface** | `viewer` → `triager` → `admin` | triage findings (status, false-positive, remediation measure); targets & scan config stay admin |
| **AppSec** | `viewer` → `triager` → `admin` | applications, finding triage, remediation measures; scanner config stays admin |
| **Watch** | `viewer` → `editor` → `admin` | watch scopes, monitored targets, digests |

A suite `admin` is admin in every module regardless of the matrix; a suite
`viewer` gets the read tier everywhere without per-module assignment.

## AI Integration

Pilot manages AI configuration centrally (`AI_MANAGED_BY_PILOT=true`). Supported providers:

- **Anthropic** (Claude Sonnet 4.6 / Opus 4.6)
- **OpenAI** (GPT-4o / GPT-4o mini)
- **AWS Bedrock** (Claude via SigV4)
- **Custom LLM** (any OpenAI-compatible endpoint)

Configure in Pilot > Settings > AI section. Keys are stored server-side and pushed to modules. Users only see an enable/disable toggle.

## Egress proxy

For deployments where the backend hosts have **no direct internet access**
and must reach outbound services (the LLM API; for Surface also the CVE
feeds and scan probes) through a **corporate forward proxy**:

Configure it **once in Pilot > Settings** (the `http_proxy`, `https_proxy`
and `no_proxy` fields). On save, Pilot pushes the values to every module
over the internal service channel (`PUT /api/internal/proxy`, authenticated
with `SERVICE_TOKEN`). Each module writes them into its process environment;
httpx then routes **every** outbound call through the proxy — no restart and
no per-module change needed. A module started or redeployed later receives
the configuration on the next push.

- The proxy URL is validated against the shared SSRF guard (an internal or
  cloud-metadata target is rejected) and every change is audit-logged
  (source IP + proxy host, credentials stripped).
- `no_proxy` **must** list the internal hosts that stay on the Docker
  network — the other modules, Pilot and the databases — so inter-module
  traffic is never sent to the corporate proxy. PostgreSQL connections use
  asyncpg (not httpx) and are never proxied regardless.
- Standalone single-module deployments have no Pilot: there the proxy is set
  directly via the `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` variables in the
  module's `.env` at deploy time (see each standalone `.env.example`).

## Connectors

Three connector families, all storing credentials **encrypted at rest**
(`ENCRYPTION_KEY`) and configurable from the UI (no rebuild needed —
connectors ship in the images, you only configure the ones you use):

### Pilot connectors (suite-level KPIs)

Configured once in **Pilot → Connectors**, they feed the KPI cockpit and the
consolidated posture:

| Connector | What it pulls |
|-----------|---------------|
| **AWS — Security posture** | Account-level security signals for KPIs |
| **Microsoft 365 / Entra ID** | Tenant security signals (identity, secure score) |
| **Proofpoint PSAT** | Security-awareness campaign completion, overdue learners (feeds KPIs + auto-created actions) |

### Asset connectors (infrastructure inventory)

| Connector | Type | What it pulls |
|-----------|------|---------------|
| **Active Directory (LDAP)** | Computer objects | Servers, workstations, OS, IP (via TCP probe) |
| **Microsoft Intune** | Managed devices | Enrolled endpoints and their compliance state |
| **AWS** | EC2 inventory | Instances and their metadata |
| **Cloud Temple (Shiva)** | IaaS VMware + OpenIaaS + Housing | VMs, ESXi/XCP-ng hosts, physical colocation devices + racks |

Features: cross-connector deduplication by hostname, priority-based field
merge, manual edit protection (`sources.fields = "manual"`).

### Access connectors (identity & account reviews)

22 connectors under `access/addons/generic/`, pulling accounts, groups/roles
and status for access reviews:

| Category | Connectors |
|----------|------------|
| **Directories / IdP** | Active Directory (LDAP), generic LDAP, Microsoft Entra ID, Microsoft 365, Keycloak, Okta, OneLogin, JumpCloud, Ping Identity, Google Workspace |
| **Cloud / IaaS** | AWS IAM, Cloud Temple IAM |
| **DevOps** | GitHub (org), GitLab, Azure DevOps |
| **Business SaaS** | Salesforce, ServiceNow, Slack, Jira/Confluence, Notion, HubSpot |
| **HR** | Generic HR feed (`hr_generic` — CSV/API, also syncs Pilot's directory) |

## Docker Image Hardening

All application images follow a hardened build pattern:

- **Multi-stage builds** (pip deps → tools → hardened runtime)
- **Non-root users** (UID 1000, `/usr/sbin/nologin`)
- **dumb-init** as PID 1 (zombie reaping, signal forwarding)
- **Read-only rootfs** (`read_only: true` in compose)
- **Capability drop** (`cap_drop: ALL`, `+NET_RAW` for Surface/nmap only)
- **no-new-privileges** security option
- **HEALTHCHECK** in Dockerfile (30s interval)
- **No curl/wget/git** in final layer (except where required by scanners)
- **Checksum-verified tool downloads** (trivy/gitleaks binaries in the AppSec
  image are verified against the official release sha256 sums at build time)

### Image pinning

Every image in `docker-compose.yml` is referenced by **content digest**
(`ghcr.io/cisotoolbox/ciso-<module>-suite:latest@sha256:…`): the tag stays
readable, but Docker resolves the digest, so a repointed `:latest` can never
silently change what runs. Refresh the pins at release time — a deliberate,
reviewed action that adopts each tag's current bytes:

```bash
bash tools/pin-images.sh            # re-pin every image to its current digest
bash tools/pin-images.sh --check    # CI gate: fail if any image is on a bare tag
```

`--check` is local and network-free; it only asserts that nothing runs on a
mutable tag. Images not yet published to GHCR (`ciso-postgres`,
`ciso-backup-agent`, `ciso-audit-suite` at the time of writing) stay on their
tag until released, and `pin-images.sh` pins them automatically once they are.

The same posture applies to the infrastructure containers:

- **nginx proxy**: read-only rootfs + tmpfs, `cap_drop: ALL` with only
  `NET_BIND_SERVICE`/`SETUID`/`SETGID`/`CHOWN`, `no-new-privileges`,
  `server_tokens off`, edge rate limiting on login/callback endpoints
  (10 req/min/IP, HTTP 429) and on scan/probe launches (30 req/min/IP)
- **PostgreSQL (×8)**: `cap_drop: ALL` + the 5 capabilities the official
  entrypoint needs (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`),
  `no-new-privileges`

Note: the edge rate limit on `/auth/login*` is defense at the proxy only —
the application-side `RateLimiter` (`appsec/src/rate_limit.py`) is currently
wired to the AI endpoints of 3 modules; wiring it to `/auth/login/token` in
each module's `routes/auth.py` is the recommended follow-up so direct
container access (bypassing the proxy) is throttled too.

### Secrets hygiene

- `.env` holds every secret of the stack — keep it `chmod 600` (done by
  `setup.sh`), never commit it.
- `JWT_SECRET`, `SERVICE_TOKEN`, `ENCRYPTION_KEY`, `DB_PASSWORD`: generate
  each with `openssl rand -hex 32` (hex 16 for `DB_PASSWORD`); one dedicated
  value per variable — do not reuse.
- `ENCRYPTION_KEY` is **required** (the compose refuses to interpolate
  without it). Rotating it requires re-entering stored connector credentials.

## Environment Variables

Key variables in `.env`:

| Variable | Required | Description |
|----------|----------|-------------|
| `DB_PASSWORD` | Yes | Shared PostgreSQL password |
| `JWT_SECRET` | Yes | JWT root secret (min 32 chars). Never signs anything directly — one key per module is derived from it with HKDF |
| `SERVICE_TOKEN` | Yes | Inter-module service token |
| `APP_URL` | Yes | Public URL (e.g. `https://ciso.example.com`) |
| `ENCRYPTION_KEY` | Yes | AES key for credential encryption at rest (connectors, SMTP password) — dedicated value, no JWT_SECRET fallback |
| `PILOT_MODULES` | Custom | Module subset for à-la-carte deployments (e.g. `risk,compliance`) |
| `PUBLIC_BASE_URL` | Email | Public URL used to absolutize links in outgoing emails (deadline digests) |
| `ENTRA_CLIENT_ID` | Auth | Microsoft Entra OAuth client ID |
| `GOOGLE_CLIENT_ID` | Auth | Google OAuth client ID |
| `OIDC_CLIENT_ID` | Auth | Generic OIDC client ID |

## Commands

```bash
# Start all
docker compose up -d

# Stop all
docker compose down

# View logs
docker compose logs -f pilot-app
docker compose logs -f access-app

# Rebuild a single module after code changes
docker compose up -d --build risk-app

# Pull latest images from GHCR
docker compose pull
docker compose up -d --force-recreate

# Reset all databases (destroys data)
docker compose down -v
docker compose up -d

# Check health
docker compose ps
```

## Production Deployment

1. **Domain + TLS**: replace self-signed cert in `certs/` with your CA-signed cert, or use a reverse proxy (Caddy, Traefik, cloud LB) upstream of nginx.

2. **Strong secrets**: `setup.sh` generates random values. Verify `JWT_SECRET` and `DB_PASSWORD` are at least 32 characters.

3. **OAuth**: configure redirect URIs with your production domain.

4. **Backups**: each module has its own PostgreSQL database. Back up with:
   ```bash
   docker exec ciso-pilot-db pg_dump -U pilot -d pilot > pilot-backup.sql
   ```

5. **Updates**:
   ```bash
   docker compose pull
   docker compose up -d --force-recreate
   ```
   Alembic migrations run automatically on container start.

## License

MIT — see [LICENSE](LICENSE).

Built by [CISOToolbox](https://www.cisotoolbox.org).
