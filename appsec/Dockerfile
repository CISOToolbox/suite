# ┌──────────────────────────────────────────────────────────────────┐
# │  CISO Toolbox — AppSec hardened image                           │
# │  Multi-stage: pip deps → tools → hardened runtime               │
# │  Non-root (appsec:1000), read-only rootfs friendly,             │
# │  minimal packages, no compiler/shell utilities in final layer.  │
# └──────────────────────────────────────────────────────────────────┘

# ── Stage 1: pip dependencies ────────────────────────────────────
# Base image (DEP-07 / CNT-01): python:3.13-slim pinned by tag **and** by the
# multi-arch index digest below, so every build resolves to the exact same
# bits on amd64 and arm64. 3.13 closes the CPython CVEs that had no fix in
# the 3.12 line. Bump tag and digest together:
#   skopeo inspect docker://docker.io/library/python:<tag> --format '{{.Digest}}'
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS builder

WORKDIR /app
# requirements-lock.txt holds every package the image installs, transitives
# included, each at one version with its hashes: the build installs exactly
# what was resolved, never a newer release (requirements.txt lists what the
# module asks for; the lock is regenerated from it).
COPY requirements-lock.txt ./
RUN pip install --no-cache-dir --prefix=/install --require-hashes -r requirements-lock.txt

# ── Stage 2: security scanning tools ─────────────────────────────
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS tools

ARG TRIVY_VERSION=0.75.0
ARG GITLEAKS_VERSION=8.30.1
ARG OPENGREP_VERSION=1.30.0
ARG TARGETARCH

# Official release sha256 sums (CNT-05) — taken from the checksum files
# published alongside the GitHub releases:
#   trivy_0.75.0_checksums.txt / gitleaks_8.30.1_checksums.txt
# MUST be updated together with the version ARGs above.
ARG TRIVY_SHA256_AMD64=b6d7b944b6cbf4e7de5b4bc6c3635900c50fed53b64b77b99a5fbc3136cd1d5d
ARG TRIVY_SHA256_ARM64=23018f1f7136b8391bb300e2579bcf4759e3c64012856f51c0fb6fffe1ee3841
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
# Opengrep (SAST) publishes no checksum file: its binaries are signed with
# Cosign by the repository's release workflow. The signature of each binary
# was verified (cosign verify-blob, identity
# https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main,
# issuer https://token.actions.githubusercontent.com) before pinning these
# sha256. MUST be re-verified and updated together with OPENGREP_VERSION.
ARG OPENGREP_SHA256_AMD64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
ARG OPENGREP_SHA256_ARM64=a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
# SAST rules: the opengrep-rules repository (LGPL 2.1 + Commons Clause, archived
# upstream) at its last commit, embedded in the image — never fetched at scan
# time. sast/prepare_rules.py keeps the security rules and the LICENSE.
ARG SAST_RULES_COMMIT=f1d2b562b414783763fd02a6ed2736eaed622efa
ARG SAST_RULES_SHA256=9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && if [ "$TARGETARCH" = "arm64" ]; then \
         TRIVY_ARCH=ARM64; TRIVY_SHA=$TRIVY_SHA256_ARM64; \
         GL_ARCH=arm64;    GL_SHA=$GITLEAKS_SHA256_ARM64; \
         OG_ARCH=aarch64;  OG_SHA=$OPENGREP_SHA256_ARM64; \
       else \
         TRIVY_ARCH=64bit; TRIVY_SHA=$TRIVY_SHA256_AMD64; \
         GL_ARCH=x64;      GL_SHA=$GITLEAKS_SHA256_AMD64; \
         OG_ARCH=x86;      OG_SHA=$OPENGREP_SHA256_AMD64; \
       fi \
    && curl -fsSL -o /tmp/trivy.deb \
       "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.deb" \
    && echo "${TRIVY_SHA}  /tmp/trivy.deb" | sha256sum -c - \
    && dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
       "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    && echo "${GL_SHA}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && curl -fsSL -o /usr/local/bin/opengrep \
       "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${OG_ARCH}" \
    && echo "${OG_SHA}  /usr/local/bin/opengrep" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/opengrep \
    && curl -fsSL -o /tmp/sast-rules.tar.gz \
       "https://github.com/opengrep/opengrep-rules/archive/${SAST_RULES_COMMIT}.tar.gz" \
    && echo "${SAST_RULES_SHA256}  /tmp/sast-rules.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/sast-src && tar xzf /tmp/sast-rules.tar.gz -C /tmp/sast-src --strip-components=1 \
    && rm /tmp/sast-rules.tar.gz

# Rule tree + local-id → registry-name index, validated now: a malformed rule
# fails the build, not a scan.
COPY sast/ /tmp/sast/
RUN python3 /tmp/sast/prepare_rules.py /tmp/sast-src /tmp/sast/house /opt/sast-rules \
    && cd /opt/sast-rules \
    && HOME=/tmp LANG=C.UTF-8 opengrep scan --validate --disable-version-check -f rules -f house . \
    && rm -rf /tmp/sast-src /tmp/sast

# ── Stage 3: hardened runtime ────────────────────────────────────
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

LABEL org.opencontainers.image.title="ciso-appsec" \
      org.opencontainers.image.description="CISO Toolbox — AppSec module" \
      org.opencontainers.image.vendor="CISOToolbox" \
      org.opencontainers.image.source="https://github.com/CISOToolbox/suite" \
      org.opencontainers.image.licenses="MIT"

# Runtime system packages — no compilers, no curl/wget.
# git is needed by Trivy for repo scans + gitleaks.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init git \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -f /usr/bin/wget /usr/bin/curl 2>/dev/null || true

# Copy pip packages from builder — this brings in setuptools==83.0.0 as pinned in
# requirements.txt (DEP-05, 2 MODERATE).
# Do NOT re-install setuptools below this line. A `pip install "setuptools<81"`
# used to sit here and silently downgraded the image back to 80.10.2, reopening
# the advisories the pin closes while osv-scanner still read 83.0.0 in the
# manifest. The <81 bound was only the remedy suggested by the pkg_resources
# deprecation notice ("Refrain from using this package or pin to Setuptools<81");
# no package in this image imports pkg_resources unguarded (semantic_version and
# wrapt both fall back to importlib.metadata), so the bound is not needed.
COPY --from=builder /install /usr/local

# Copy tool binaries from the tools stage — only the static binaries
# land in the final layer, not curl/apt caches.
COPY --from=tools /usr/bin/trivy /usr/bin/trivy
COPY --from=tools /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=tools /usr/local/bin/opengrep /usr/local/bin/opengrep
COPY --from=tools /opt/sast-rules /opt/sast-rules

# Non-root user.
RUN useradd -r -m -u 1000 -s /usr/sbin/nologin appsec \
    && mkdir -p /app \
    && chown -R appsec:appsec /app

WORKDIR /app

COPY --chown=appsec:appsec src/ src/
COPY --chown=appsec:appsec app/ app/
COPY --chown=appsec:appsec alembic/ alembic/
COPY --chown=appsec:appsec alembic.ini .
COPY --chown=appsec:appsec docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAST_RULES_DIR=/opt/sast-rules


# Version identity (FEAT-29): baked at build, exposed via GET /api/version.
ARG PRODUCT_VERSION=dev
ARG BUILD_DATE=
ARG GIT_SHA=
ENV PRODUCT_VERSION=${PRODUCT_VERSION} \
    BUILD_DATE=${BUILD_DATE} \
    GIT_SHA=${GIT_SHA}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"]

USER appsec

ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
