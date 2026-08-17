# Security Policy

This repository is the **integrated suite** deployment: Pilot (SSO + consolidated
dashboard) plus the nine backend modules behind a single nginx edge, wired by
`docker-compose.yml`.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security
problem.**

Report it privately through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository. That channel is private
between you and the maintainers and produces a tracked advisory.

If you cannot use that channel, write to **security@cisotoolbox.org**.

<!-- MAINTAINER: enable "Private vulnerability reporting" in the repository
     settings before publishing. -->

Please include:

- the affected version or commit, and the deployment mode (`AUTH_MODE`)
- a description of the impact
- reproduction steps or a proof of concept
- any suggested mitigation

### What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement of your report | 5 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for high/critical issues | 90 days |

We follow **coordinated disclosure**: please give us a reasonable window to ship
a fix before publishing. We will credit you in the advisory unless you prefer to
remain anonymous.

## Supported versions

Only the latest released state of this repository receives security fixes. There
are no long-term-support branches.

## Scope

**In scope** — everything in this repository: each module's FastAPI backend
(`*/src/`) and frontend (`*/app/`), the database migrations (`*/alembic/`), the
edge configuration (`nginx.conf`), the orchestration (`docker-compose.yml`), the
backup/recovery agent (`backup-agent/`) and the setup tooling (`setup.sh`,
`tools/`).

**Out of scope**

- Deployments running with `AUTH_MODE=none`. That mode disables authentication
  by design and is documented as development/test only.
- Findings that require the attacker to already control the host, the container
  runtime, or the `.env` file.
- Vulnerabilities in third-party dependencies with no exploitable path in this
  code — report those upstream. They are tracked with `osv-scanner` (see
  `.github/workflows/`).
- Missing hardening headers on a deployment where the operator has replaced the
  bundled nginx edge with their own.

## Security model of the suite

- **Per-module derived keys.** Pilot is the only issuer, but there is no
  suite-wide token: Pilot mints one token **per module**, each signed with a key
  derived as `HKDF-SHA256(JWT_SECRET, info="ciso-module:<module>")` and scoped to
  that module's audience and cookie. Compromising one module yields neither
  `JWT_SECRET` nor any sibling's key (HKDF is one-way).
- **Secret strength enforced at boot.** An empty or sub-32-character
  `JWT_SECRET` refuses to start (`assert_auth_posture`); `ENCRYPTION_KEY` is
  required and must be a dedicated value distinct from `JWT_SECRET`.
- **Secrets encrypted at rest.** Connector credentials, AI keys, SMTP passwords
  and the like are stored AES-256-GCM encrypted (`settings_crypto.py`,
  `crypto.py`); `ENCRYPTION_KEY` is the data-at-rest key.
- **Session lifetime is tunable.** `JWT_EXPIRY_HOURS` (default 24) bounds how
  long a downgraded/deleted account keeps access; lower it for high-sensitivity
  deployments.
- **SSRF guard.** Outbound URLs fetched on a user's behalf go through the shared
  `ssrf_guard` / `resolve_safe_url`, which rejects loopback, link-local, cloud
  metadata and container-network addresses and pins the resolved IP against DNS
  rebinding.
- **Edge hardening.** nginx terminates TLS (1.2/1.3), rate-limits login/callback
  and scan endpoints, sets HSTS / X-Frame-Options / nosniff / Referrer-Policy /
  Permissions-Policy, hides `server_tokens`, and returns 404 on every
  `/internal` route so the Pilot↔module service channel is never edge-reachable.
- **Container hardening.** Images run non-root with `cap_drop: ALL` (only the
  capabilities each needs), `no-new-privileges`, read-only rootfs and pinned
  image digests.
- **Backup/recovery.** The recovery API is authenticated by `BACKUP_AGENT_TOKEN`
  and reachable only inside the compose network; the pgBackRest repository is
  encrypted with `BACKUP_CIPHER_PASS`. Both must be strong, non-placeholder
  values — the agent refuses to start otherwise.

## Hardening checklist for operators

1. Run `bash setup.sh` — it generates every secret (`JWT_SECRET`,
   `SERVICE_TOKEN`, `ENCRYPTION_KEY`, `DB_PASSWORD`, `BACKUP_CIPHER_PASS`,
   `BACKUP_AGENT_TOKEN`) with `openssl rand -hex 32`, one dedicated value each.
2. Keep `.env` out of version control and `chmod 600` (setup.sh does this);
   store `BACKUP_CIPHER_PASS` in your vault — losing it makes backups
   unreadable.
3. Serve the suite over HTTPS; set `APP_URL` to the `https://` URL and keep the
   real TLS key (`certs/key.pem`) `chmod 600`.
4. Lower `JWT_EXPIRY_HOURS` if you need a shorter revocation window.
5. Pin the images at release: `bash tools/pin-images.sh`, and gate CI with
   `bash tools/pin-images.sh --check`.
6. Keep the images up to date; run `bash tools/pin-images.sh` after each pull to
   re-pin, and watch the dependency/image scan workflows.
7. Snapshot the database volumes before every upgrade or migration.
