#!/usr/bin/env bash
# Suite deployment posture — the 10 modules, through the proxy.
#
# The same test_posture.py file serves both the suite and the standalone repos;
# only each tree's conftest changes (URL, expected posture, token).
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
# Same rule as smoke-test.sh: having verified nothing is not a success.
if [ "$CHECKED" -eq 0 ]; then
    echo "POSTURE FAILED: no module has tests/e2e — nothing was verified"; exit 1
fi
[ "$FAILED" -gt 0 ] && { echo "POSTURE FAILED: $FAILED/$CHECKED module(s)"; exit 1; }
echo "POSTURE OK: $CHECKED module(s)"
