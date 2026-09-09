#!/usr/bin/env bash
# Pre-tag guardrail for the distribution release model (see RELEASING.md).
#
# Checks, in order:
#   1. every module has a VERSION file, SemVer-shaped
#   2. the suite has one too
#   3. docker-compose pins, for every module service, a tag of that module's
#      version line: equal to its VERSION with --strict (release time),
#      otherwise at most equal — between a module release and the next suite
#      release, a module VERSION is legitimately ahead of its pin
#   4. the compatibility matrix in RELEASING.md has a row for the suite
#      version that agrees with the VERSION files, and CHANGELOG.md has the
#      section of the suite version
#   5. --remote : every tag the compose pins exists on the module's repository
#      and has a multi-arch image on GHCR (a repository that cannot be read
#      from here — private, no token — is a warning, the image is still checked)
#   6. --fresh  : every pinned image was built after the last commit that
#      changed the module's code (VERSION and CHANGELOG excluded).
#      Only meaningful where code commits precede the image builds; CI does
#      not use it.
#
# Usage: bash tools/release-check.sh [--remote] [--fresh] [--strict]
set -uo pipefail

REMOTE=0; FRESH=0; STRICT=0
for a in "$@"; do
    case "$a" in
        --remote) REMOTE=1 ;;
        --fresh)  REMOTE=1; FRESH=1 ;;
        --strict) STRICT=1 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODULES=(pilot risk compliance audit vendor asset access surface appsec watch)
SEMVER='^[0-9]+\.[0-9]+\.[0-9]+$'
fails=0

fail() { echo "  ✗ $*"; fails=$((fails + 1)); }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ! $*"; }
export GIT_TERMINAL_PROMPT=0

echo "── 1/6 module VERSION files ──"
for m in "${MODULES[@]}"; do
    [ -d "$m" ] || continue
    if [ ! -f "$m/VERSION" ]; then
        fail "$m: VERSION missing"; continue
    fi
    v="$(tr -d '[:space:]' < "$m/VERSION")"
    if [[ ! "$v" =~ $SEMVER ]]; then
        fail "$m: invalid VERSION ('$v')"
    else
        ok "$m $v"
    fi
done

echo "── 2/6 suite VERSION ──"
if [ ! -f VERSION ]; then
    fail "VERSION missing at the repository root"
    SUITE_V=""
else
    SUITE_V="$(tr -d '[:space:]' < VERSION)"
    if [[ ! "$SUITE_V" =~ $SEMVER ]]; then
        fail "invalid suite VERSION ('$SUITE_V')"
    else
        ok "suite $SUITE_V"
    fi
fi

echo "── 3/6 tags pinned in docker-compose.yml ──"
for m in "${MODULES[@]}"; do
    [ -f "$m/VERSION" ] || continue
    v="$(tr -d '[:space:]' < "$m/VERSION")"
    # image: ghcr.io/cisotoolbox/ciso-<m>-suite:<tag>[@sha256:…]
    ref="$(grep -oE "ciso-${m}(-suite)?:[A-Za-z0-9._-]+(@sha256:[a-f0-9]+)?" docker-compose.yml | head -1)"
    tag="$(printf '%s' "$ref" | cut -d: -f2 | cut -d@ -f1)"
    digest=""
    case "$ref" in *@sha256:*) digest=" (digest pinned)" ;; esac
    if [ -z "$ref" ]; then
        ok "$m: local build (no pinned image)"
    elif [ "$tag" = "latest" ]; then
        fail "$m: tag 'latest'$digest — publish the images, then pin v$v"
    elif [ "$tag" = "v$v" ]; then
        ok "$m pinned v$v$digest"
    elif [ "$STRICT" = 1 ]; then
        fail "$m: compose pins $tag, VERSION says $v (a release needs both equal)"
    elif [[ "${tag#v}" =~ $SEMVER ]] && [ "$(printf '%s\n%s\n' "${tag#v}" "$v" | sort -V | head -1)" = "${tag#v}" ]; then
        ok "$m pinned $tag, VERSION $v ahead (module released, suite not recut yet)"
    else
        fail "$m: compose pins $tag, newer than VERSION $v"
    fi
done

echo "── 4/6 compatibility matrix (RELEASING.md) and release notes (CHANGELOG.md) ──"
if [ -n "$SUITE_V" ]; then
    row="$(grep -E "^\| ${SUITE_V} \|" RELEASING.md | head -1)"
    if [ -z "$row" ]; then
        fail "no matrix row for suite $SUITE_V"
    else
        i=0
        bad=0
        # columns after the suite version, in header order
        IFS='|' read -ra cells <<< "${row#| }"
        for m in "${MODULES[@]}"; do
            i=$((i + 1))
            cell="$(echo "${cells[$i]:-}" | tr -d '[:space:]')"
            v="$(tr -d '[:space:]' < "$m/VERSION" 2>/dev/null || echo '?')"
            [ "$cell" = "$v" ] || { fail "matrix $m: row says '$cell', VERSION says '$v'"; bad=1; }
        done
        [ $bad -eq 0 ] && ok "matrix row consistent for $SUITE_V"
    fi
    if [ ! -f CHANGELOG.md ]; then
        fail "CHANGELOG.md missing — every release has its notes"
    elif grep -qE "^## ${SUITE_V}( |$)" CHANGELOG.md; then
        ok "CHANGELOG.md has the $SUITE_V section"
    else
        fail "no '## $SUITE_V' section in CHANGELOG.md — every release has its notes"
    fi
fi

if [ "$REMOTE" = 1 ] && ! command -v skopeo >/dev/null 2>&1; then
    echo "── 5/6 public tags and GHCR images ──"
    fail "skopeo is required for --remote (apt-get install skopeo)"
    REMOTE=0; FRESH=0
fi
# What the compose pins for a module (vX.Y.Z), or its VERSION when it is a
# local build — the pin is what a deployment gets, so the pin is what we check.
pinned_tag() {
    local ref
    ref="$(grep -vE '^[[:space:]]*#' docker-compose.yml | grep -oE "ciso-$1(-suite)?:v[0-9]+\.[0-9]+\.[0-9]+" | head -1)"
    if [ -n "$ref" ]; then printf '%s' "${ref##*:}"; else printf 'v%s' "$(tr -d '[:space:]' < "$1/VERSION")"; fi
}

# Distinct real architectures in a manifest list — attestation entries
# (unknown/unknown) do not count, a plain manifest counts as one.
arch_count() {
    local raw
    raw="$(timeout 60 skopeo inspect --raw "docker://$1" 2>/dev/null)" || { echo 0; return; }
    [ -n "$raw" ] || { echo 0; return; }
    if printf '%s' "$raw" | grep -q '"manifests"'; then
        printf '%s' "$raw" | grep -oE '"architecture":[[:space:]]*"[^"]+"' | grep -v unknown | sort -u | wc -l
    else
        echo 1
    fi
}

if [ "$REMOTE" = 1 ]; then
    echo "── 5/6 pinned tags on the module repositories and GHCR images ──"
    for m in "${MODULES[@]}"; do
        [ -f "$m/VERSION" ] || continue
        t="$(pinned_tag "$m")"
        refs="$(git ls-remote --tags "https://github.com/CISOToolbox/$m.git" "refs/tags/$t" 2>/dev/null)"; rc=$?
        if [ $rc -ne 0 ]; then
            warn "$m: repository CISOToolbox/$m not readable from here (private?) — tag $t not verified"
        elif printf '%s' "$refs" | grep -q .; then
            ok "$m: tag $t on CISOToolbox/$m"
        else
            fail "$m: no tag $t on CISOToolbox/$m — the pinned version is not released"
        fi
        img="ghcr.io/cisotoolbox/ciso-$m-suite:$t"
        n="$(arch_count "$img")"
        if [ "${n:-0}" -ge 2 ]; then
            ok "$m: image $img (${n} architectures)"
        elif [ "${n:-0}" = 1 ]; then
            fail "$m: image $img is single-architecture"
        else
            fail "$m: image $img not found on GHCR"
        fi
    done
fi

if [ "$FRESH" = 1 ]; then
    echo "── 6/6 image freshness (built after the module's last code commit) ──"
    for m in "${MODULES[@]}"; do
        [ -f "$m/VERSION" ] || continue
        img="ghcr.io/cisotoolbox/ciso-$m-suite:$(pinned_tag "$m")"
        created="$(timeout 60 skopeo inspect "docker://$img" 2>/dev/null | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["Created"][:19])
except Exception: print("")')"
        # Last commit that changed what goes INTO the image — the release commit
        # itself (VERSION, CHANGELOG) follows the build by design.
        # Both timestamps in UTC: skopeo's Created is UTC, git's default is not.
        last="$(TZ=UTC git log -1 --date=iso-strict-local --format=%cd -- "$m" ":!$m/VERSION" ":!$m/CHANGELOG.md" 2>/dev/null | cut -c1-19)"
        if [ -z "$created" ]; then
            fail "$m: build date not found for $img"
        elif [ -n "$last" ] && [[ "$created" < "$last" ]]; then
            fail "$m: image built $created, last code commit $last — recut the module release"
        else
            ok "$m: image built $created ≥ last code commit"
        fi
    done
fi

echo
if [ $fails -gt 0 ]; then
    echo "RELEASE-CHECK: $fails problem(s) — do not tag."
    exit 1
fi
echo "RELEASE-CHECK OK"
