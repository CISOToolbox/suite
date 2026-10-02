#!/usr/bin/env bash
# Applies the i18n packaging (i18n-package.py) to an app/ directory, following
# the i18n.conf config, overridable with --base / --langs.
#
# Usage:
#   i18n-apply.sh <app_dir>                      # uses i18n.conf
#   i18n-apply.sh <app_dir> --langs "en"         # override: EN only
#   i18n-apply.sh <app_dir> --base en --langs "en fr"
#
# ⚠️  Modifies <app_dir> IN PLACE (it strips languages). Run it on a build COPY,
#     never on the source tree if you want to keep every language.
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
app="${1:?usage: i18n-apply.sh <app_dir> [--base L] [--langs \"L1 L2\"]}"
shift

BASE="en"; LANGS="en fr"
[ -f "$SELF/i18n.conf" ] && . "$SELF/i18n.conf"

while [ $# -gt 0 ]; do
    case "$1" in
        --base)  BASE="$2";  shift 2 ;;
        --langs) LANGS="$2"; shift 2 ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done

# shellcheck disable=SC2086  # LANGS is deliberately split into words
python3 "$SELF/i18n-package.py" "$app" --base "$BASE" --langs $LANGS
