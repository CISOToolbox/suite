# ┌──────────────────────────────────────────────────────────────────┐
# │  CISO Toolbox — Watch hardened image                            │
# │  Two-stage: pip deps → hardened runtime                         │
# │  Non-root (watch:1000), read-only rootfs friendly,              │
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
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: hardened runtime ────────────────────────────────────
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

LABEL org.opencontainers.image.title="ciso-watch" \
      org.opencontainers.image.description="CISO Toolbox — Watch (vulnerability monitoring)" \
      org.opencontainers.image.vendor="CISOToolbox" \
      org.opencontainers.image.source="https://github.com/CISOToolbox/demo-docker" \
      org.opencontainers.image.licenses="MIT"

# Runtime system packages — no compilers, no curl/wget.
# git is needed for the GHSA / OSSF-malicious-packages git mirrors
# we pull in phase 2.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init git \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -f /usr/bin/wget /usr/bin/curl 2>/dev/null || true

# Copy pip packages from builder — this brings in setuptools==83.0.0 as pinned in
# requirements.txt (DEP-05, 2 MODERATE).
# Do NOT re-install setuptools below this line. A `pip install "setuptools<81"`
# used to sit here (copy-pasted from the appsec image) and silently downgraded
# the image back to 80.10.2, reopening the advisories the pin closes while
# osv-scanner still read 83.0.0 in the manifest. Nothing in this image imports
# pkg_resources at all, so the bound was never justified here.
COPY --from=builder /install /usr/local

# Non-root user.
RUN useradd -r -m -u 1000 -s /usr/sbin/nologin watch \
    && mkdir -p /app \
    && chown -R watch:watch /app

WORKDIR /app

COPY --chown=watch:watch src/ src/
COPY --chown=watch:watch app/ app/
COPY --chown=watch:watch alembic/ alembic/
COPY --chown=watch:watch alembic.ini .
COPY --chown=watch:watch docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1


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

USER watch

ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
