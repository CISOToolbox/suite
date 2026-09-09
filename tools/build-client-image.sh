#!/usr/bin/env bash
# Build a per-client backend-module image = core + selected add-ons.
#
# Add-ons live under <module>/addons/{generic,custom/<client>}/
# and a client image is produced by selecting which addon subtrees to bake in
# at build time (overlay on the core image via <module>/Dockerfile.addons).
#
# Usage:
#   build-client-image.sh <client> [options]
# Options:
#   --module M         backend module (default: access; e.g. surface)
#   --addons a,b,...   addon subtrees under <module>/addons/ to include
#                      (default: "generic" + "custom/<client>" if it exists)
#   --exclude-core a,b core scanner add-ons to DROP from the image (a slim
#                      build) — e.g. --exclude-core shodan,cloud_buckets removes
#                      addons/core/shodan + addons/core/cloud_buckets
#   --base IMG         core base image to layer on
#                      (default: ciso-<module>:local, built unless --skip-core)
#   --tag TAG          image tag (default: local) -> ciso-<module>-<client>:TAG
#   --custom-dir DIR   external client add-on directory (the organization's
#                      own repository, e.g. <client>/<module>-addons/).
#                      Staged as addons/custom/<client>/ for the build, removed
#                      afterwards — the public tree never keeps client code.
#   --platforms P      build a MULTI-ARCH manifest (e.g. linux/amd64,linux/arm64)
#                      instead of the host arch only. Mandatory for GHCR:
#                      a single-arch image will not start on the other platform.
#   --skip-core        don't (re)build the core base; use --base as-is
#   --push             push the resulting image (use a full --tag ref)
#
# Examples:
#   build-client-image.sh acme
#   build-client-image.sh acme --addons custom/acme
#   build-client-image.sh acme-smb --module surface --addons generic/smb_scan
#   build-client-image.sh acme --base ghcr.io/cisotoolbox/ciso-access-suite:v0.3.6 \
#       --skip-core --tag v0.1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

[ $# -ge 1 ] || { sed -n '2,25p' "$0"; exit 1; }
client="$1"; shift

module="access"
addons=""
exclude_core=""
base=""
platforms=""
custom_dir=""
tag="local"
skip_core=false
push=false
langs=""   # i18n languages to bundle (e.g. "en" or "en fr"); default: i18n.conf
while [ $# -gt 0 ]; do
    case "$1" in
        --module) module="$2"; shift 2 ;;
        --addons) addons="$2"; shift 2 ;;
        --exclude-core) exclude_core="$2"; shift 2 ;;
        --base) base="$2"; shift 2 ;;
        --platforms) platforms="$2"; shift 2 ;;
        --custom-dir) custom_dir="$2"; shift 2 ;;
        --tag) tag="$2"; shift 2 ;;
        --langs) langs="$2"; shift 2 ;;
        --skip-core) skip_core=true; shift ;;
        --push) push=true; shift ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
done

# Layout-agnostic: works from a shared tools directory next to the module
# trees AND from the suite repo's tools/ directory (modules at the repo root).
if [ -d "$ROOT/../public/suite-modules" ]; then
    MOD_DIR="$ROOT/../public/suite-modules/$module"
else
    MOD_DIR="$ROOT/$module"
fi
[ -d "$MOD_DIR" ] || { echo "!! unknown module: $module ($MOD_DIR missing)"; exit 1; }
[ -f "$MOD_DIR/Dockerfile.addons" ] || { echo "!! $module has no Dockerfile.addons overlay"; exit 1; }

# Single EXIT handler: un-stage external client add-ons AND restore the
# multi-language app/ tree (bash keeps only one trap per signal).
_on_exit() {
    [ -n "${_custom_stage:-}" ] && rm -rf "$_custom_stage"
    [ -d "$MOD_DIR/.app-i18n-bak" ] && { rm -rf "$MOD_DIR/app"; mv "$MOD_DIR/.app-i18n-bak" "$MOD_DIR/app"; }
    return 0
}
trap _on_exit EXIT

# External client add-ons (the organization's repository) staged into the module tree for the
# duration of the build only.
if [ -n "$custom_dir" ]; then
    [ -d "$custom_dir" ] || { echo "!! --custom-dir not found: $custom_dir"; exit 1; }
    _custom_stage="$MOD_DIR/addons/custom/$client"
    rm -rf "$_custom_stage"; mkdir -p "$_custom_stage"
    cp -r "$custom_dir/." "$_custom_stage/"
    echo "── staged external client add-ons: $custom_dir -> addons/custom/$client ──"
    case ",$addons," in *",custom/$client,"*) : ;; *)
        [ -n "$addons" ] && addons="$addons,custom/$client" || addons="generic,custom/$client" ;;
    esac
fi
[ -n "$base" ] || base="ciso-${module}:local"

# Default selection: all generic addons + this client's custom dir if present.
if [ -z "$addons" ]; then
    addons="generic"
    [ -d "$MOD_DIR/addons/custom/$client" ] && addons="generic,custom/$client"
fi

# --tag accepts either a plain tag (the name is then composed automatically),
# or a full reference (ghcr.io/org/name:tag) to push directly.
case "$tag" in
    */*|*:*) img="$tag" ;;
    *)       img="ciso-${module}-${client}:${tag}" ;;
esac
stage="$MOD_DIR/.client-addons"

# 0. i18n packaging (optional): restrict the languages bundled into the
#    image. Applied on a backup of app/, restored on exit (trap) so the
#    multi-language source tree is never altered.
if [ -n "$langs" ]; then
    echo "── i18n packaging: langs=$langs ──"
    rm -rf "$MOD_DIR/.app-i18n-bak"; cp -r "$MOD_DIR/app" "$MOD_DIR/.app-i18n-bak"
    bash "$(cd "$(dirname "$0")" && pwd)/i18n-apply.sh" "$MOD_DIR/app" --langs "$langs"
fi

# 1. Core base (unless reusing an existing/pinned image).
# PRODUCT_VERSION is baked from <module>/VERSION (release contract, see the
# suite's RELEASING.md): version_common exposes it and the backup machinery
# refuses archives from a newer version, so "dev" must not reach a release.
prodver="dev"
[ -f "$MOD_DIR/VERSION" ] && prodver="$(tr -d '[:space:]' < "$MOD_DIR/VERSION")"
if ! $skip_core; then
    echo "── building core base $base (PRODUCT_VERSION=$prodver) ──"
    if [ -n "$platforms" ]; then
        podman manifest rm "$base" >/dev/null 2>&1 || true
        podman image exists "$base" && podman rmi -f "$base" >/dev/null 2>&1 || true
        podman build --platform "$platforms" --manifest "$base" \
            --build-arg PRODUCT_VERSION="$prodver" "$MOD_DIR"
    else
        docker build --build-arg PRODUCT_VERSION="$prodver" -t "$base" "$MOD_DIR"
    fi
fi

# 2. Stage the selected addon subtrees into the build context.
echo "── staging addons: $addons ──"
rm -rf "$stage"; mkdir -p "$stage"
IFS=',' read -ra sels <<< "$addons"
for s in "${sels[@]}"; do
    s="$(echo "$s" | xargs)"  # trim
    src="$MOD_DIR/addons/$s"
    [ -d "$src" ] || { echo "!! addon path not found: $module/addons/$s"; rm -rf "$stage"; exit 1; }
    mkdir -p "$stage/$s"
    cp -r "$src/." "$stage/$s/"
    # Strip build-time-only artifacts — a compiled-worker add-on (e.g. the Rust
    # SMB scanner) ships only its prebuilt bin/ at runtime; its source/build
    # trees (rust/target-*, node_modules, __pycache__) can be hundreds of MB and
    # must never bloat the image.
    find "$stage/$s" -type d \( -name target -o -name 'target-*' \
        -o -name node_modules -o -name __pycache__ -o -name .git \) \
        -prune -print0 2>/dev/null | xargs -0 rm -rf 2>/dev/null || true
done

# 3. Overlay the addons on the core (optionally dropping some core scanners).
excl_space="$(echo "$exclude_core" | tr ',' ' ' | xargs)"
[ -n "$excl_space" ] && echo "── excluding core add-ons: $excl_space ──"
echo "── building $img (base=$base) ──"
if [ -n "$platforms" ]; then
    # BASE is a manifest list: podman resolves the right arch per platform.
    podman manifest rm "$img" >/dev/null 2>&1 || true
    podman image exists "$img" && podman rmi -f "$img" >/dev/null 2>&1 || true
    podman build --platform "$platforms" --manifest "$img" \
        --build-arg BASE="$base" --build-arg EXCLUDE_CORE="$excl_space" \
        --build-arg PRODUCT_VERSION="$prodver" \
        -f "$MOD_DIR/Dockerfile.addons" "$MOD_DIR"
else
    docker build --build-arg BASE="$base" --build-arg EXCLUDE_CORE="$excl_space" \
        --build-arg PRODUCT_VERSION="$prodver" \
        -f "$MOD_DIR/Dockerfile.addons" -t "$img" "$MOD_DIR"
fi
rm -rf "$stage"

echo "✓ built $img"
if $push; then
    echo "── pushing $img ──"
    if [ -n "$platforms" ]; then
        podman manifest push --all "$img" "docker://$img"
    else
        docker push "$img"
    fi
    # Move `latest` too when the tag is a version, the way publish-images.sh
    # does for the suite images. Without this a client image kept a `latest`
    # frozen at whenever it was last built with that tag explicitly — six
    # weeks stale at a client site, and it once sent a debugging session chasing an
    # old image that a `docker pull` had silently produced.
    case "$img" in
        *:v[0-9]*)
            latest_ref="${img%:*}:latest"
            echo "── pushing $latest_ref ──"
            if [ -n "$platforms" ]; then
                podman manifest push --all "$img" "docker://$latest_ref"
            else
                docker tag "$img" "$latest_ref" && docker push "$latest_ref"
            fi
            ;;
    esac
fi
