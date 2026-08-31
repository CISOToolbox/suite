#!/usr/bin/env bash
# Posture de deploiement de la suite — les 10 modules, a travers le proxy.
#
# Le meme fichier test_posture.py sert la suite et les depots standalone ;
# seul le conftest de chaque arbre change (URL, posture attendue, jeton).
#
# Usage: bash tests/run-posture.sh [module...]
#        E2E_PROXY=https://host:8443 bash tests/run-posture.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
MODULES=${*:-$(ls -d */tests/e2e 2>/dev/null | cut -d/ -f1)}

FAILED=0; CHECKED=0
for m in $MODULES; do
    [ -d "$m/tests/e2e" ] || continue
    CHECKED=$((CHECKED + 1))
    out=$( (cd "$m" && uv run --no-project --with pytest pytest tests/e2e -q 2>&1 | tail -1) )
    case "$out" in
        *failed*) echo "  FAIL  $m — $out"; FAILED=$((FAILED + 1)) ;;
        *)        echo "  OK    $m — $out" ;;
    esac
done

echo ""
# Meme regle que smoke-test.sh : ne rien avoir verifie n'est pas un succes.
if [ "$CHECKED" -eq 0 ]; then
    echo "POSTURE FAILED: no module has tests/e2e — nothing was verified"; exit 1
fi
[ "$FAILED" -gt 0 ] && { echo "POSTURE FAILED: $FAILED/$CHECKED module(s)"; exit 1; }
echo "POSTURE OK: $CHECKED module(s)"
