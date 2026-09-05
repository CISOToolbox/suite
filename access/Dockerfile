# Base image (DEP-07 / CNT-01): python:3.13-slim pinned by tag **and** by the
# multi-arch index digest below, so every build resolves to the exact same
# bits on amd64 and arm64. 3.13 closes the CPython CVEs that had no fix in
# the 3.12 line. Bump tag and digest together:
#   skopeo inspect docker://docker.io/library/python:<tag> --format '{{.Digest}}'
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Dependencies of the generic connectors (ldap3, boto3, …). Each add-on ships
# its own requirements.txt; they are installed here so the connectors bundled
# below actually import.
#
# Why bundle them at all: unlike Surface, Access has no addons/core tier — all
# 23 connectors live under addons/generic. A "plain core build" therefore
# shipped an image with ZERO connectors, and nothing said so: the loader logs a
# warning at most, and the UI simply renders an empty type grid. The README
# documents these connectors as a standard Access feature and propagation sends
# them to the public standalone tree, so they belong in the image.
#
# addons/custom/<client>/ stays out, and is layered by Dockerfile.addons via
# shared/build-client-image.sh.
COPY addons/generic/ /tmp/addons/
# `find -exec … \;` returns 0 even when pip fails: a connector with broken
# deps produced a green image with an unusable add-on. The loop fails
# outright on the first failed install.
RUN for r in $(find /tmp/addons -name requirements.txt | sort); do \
      echo "── add-on deps: $r ──"; \
      pip install --no-cache-dir --prefix=/install -r "$r" || exit 1; \
    done \
    && rm -rf /tmp/addons

FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

WORKDIR /app
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY src/ src/
COPY app/ app/
# The loader walks /app/addons recursively (src/plugins/__init__.py) and
# tolerates a broken add-on with a warning rather than failing to boot.
COPY addons/generic/ addons/generic/
COPY alembic/ alembic/
COPY alembic.ini .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd -r -m -u 1000 -s /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

# PYTHONDONTWRITEBYTECODE: no .pyc writes (read-only rootfs compatible).
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

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
