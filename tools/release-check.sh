#!/usr/bin/env bash
# Pre-tag guardrail for the distribution release model (see RELEASING.md).
#
# Checks, in order:
#   1. every module has a VERSION file, SemVer-shaped
#   2. the suite has one too
#   3. docker-compose pins, for every module service, a tag that matches
#      that module's VERSION (or an explicit local/dev build)
#   4. the compatibility matrix in RELEASING.md has a row for the suite
#      version, and that row agrees with the VERSION files
#
# Propagation drift (rule 2 of RELEASING.md) is checked by the private
# propagation tooling, which does not ship in this repo — run
#   propagate.sh --all
# there and expect "drift 0" before tagging.
#
# Usage: bash tools/release-check.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODULES=(pilot risk compliance audit vendor asset access surface appsec watch)
SEMVER='^[0-9]+\.[0-9]+\.[0-9]+$'
fails=0

fail() { echo "  ✗ $*"; fails=$((fails + 1)); }
ok()   { echo "  ✓ $*"; }

echo "── 1/4 VERSION des modules ──"
for m in "${MODULES[@]}"; do
    [ -d "$m" ] || continue
    if [ ! -f "$m/VERSION" ]; then
        fail "$m : VERSION manquant"; continue
    fi
    v="$(tr -d '[:space:]' < "$m/VERSION")"
    if [[ ! "$v" =~ $SEMVER ]]; then
        fail "$m : VERSION invalide ('$v')"
    else
        ok "$m $v"
    fi
done

echo "── 2/4 VERSION de la suite ──"
if [ ! -f VERSION ]; then
    fail "VERSION manquant à la racine"
    SUITE_V=""
else
    SUITE_V="$(tr -d '[:space:]' < VERSION)"
    if [[ ! "$SUITE_V" =~ $SEMVER ]]; then
        fail "VERSION suite invalide ('$SUITE_V')"
    else
        ok "suite $SUITE_V"
    fi
fi

echo "── 3/4 tags épinglés dans docker-compose.yml ──"
for m in "${MODULES[@]}"; do
    [ -f "$m/VERSION" ] || continue
    v="$(tr -d '[:space:]' < "$m/VERSION")"
    # image: ghcr.io/cisotoolbox/ciso-<m>-suite:<tag>[@sha256:…]
    ref="$(grep -oE "ciso-${m}(-suite)?:[A-Za-z0-9._-]+(@sha256:[a-f0-9]+)?" docker-compose.yml | head -1)"
    tag="$(printf '%s' "$ref" | cut -d: -f2 | cut -d@ -f1)"
    digest=""
    case "$ref" in *@sha256:*) digest=" (digest épinglé)" ;; esac
    if [ -z "$ref" ]; then
        ok "$m : build local (pas d'image épinglée)"
    elif [ "$tag" = "latest" ]; then
        fail "$m : tag 'latest'$digest — publier les images puis épingler v$v"
    elif [ "$tag" != "v$v" ]; then
        fail "$m : compose épingle $tag, VERSION dit $v"
    else
        ok "$m épinglé v$v$digest"
    fi
done

echo "── 4/4 matrice de compatibilité (RELEASING.md) ──"
if [ -n "$SUITE_V" ]; then
    row="$(grep -E "^\| ${SUITE_V} \|" RELEASING.md | head -1)"
    if [ -z "$row" ]; then
        fail "aucune ligne de matrice pour la suite $SUITE_V"
    else
        i=0
        bad=0
        # columns after the suite version, in header order
        IFS='|' read -ra cells <<< "${row#| }"
        for m in "${MODULES[@]}"; do
            i=$((i + 1))
            cell="$(echo "${cells[$i]:-}" | tr -d '[:space:]')"
            v="$(tr -d '[:space:]' < "$m/VERSION" 2>/dev/null || echo '?')"
            [ "$cell" = "$v" ] || { fail "matrice $m : ligne dit '$cell', VERSION dit '$v'"; bad=1; }
        done
        [ $bad -eq 0 ] && ok "matrice cohérente pour $SUITE_V"
    fi
fi

echo
if [ $fails -gt 0 ]; then
    echo "RELEASE-CHECK: $fails problème(s) — ne pas tagger en l'état."
    exit 1
fi
echo "RELEASE-CHECK OK — pensez à vérifier 'drift 0' côté propagation avant le tag."
