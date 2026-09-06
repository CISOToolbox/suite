#!/usr/bin/env bash
# Mints one session JWT per module and writes them to tokens.json (gitignored).
#
# Each module signs with its own key, hence one token per module rather than a
# shared one. The account used is discovered in Pilot's directory: a valid JWT
# is not enough, `_is_active_upstream` asks Pilot whether the account is active,
# and refuses any email it does not know — which is what makes a test account
# present only in a single module's database unusable.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
OUT=tokens.json

# Containers are resolved against the running stack rather than through a
# fixed prefix: locally rebuilt services are renamed ciso2-<m> by the compose
# override while the pinned ones keep ciso-<m>, and the databases always stay
# ciso-<m>-db — no single prefix can match such a mixed stack. When both a
# ciso- and a ciso2- container exist for the same suffix, the ciso2- one (the
# local build under validation) wins. Set CISO_CONTAINER_PREFIX to pin one
# prefix when several stacks run side by side.
RUNNING="$(docker ps --format '{{.Names}}')"
resolve() {
    if [ -n "${CISO_CONTAINER_PREFIX:-}" ]; then
        printf '%s\n' "$RUNNING" | grep -E "^${CISO_CONTAINER_PREFIX}-$1\$" | head -1
    else
        printf '%s\n' "$RUNNING" | grep -E "^ciso2?-$1\$" | sort | tail -1
    fi
}

# An administrator that is genuinely active on the Pilot side. Discovered, never hard-coded.
PILOT_DB="$(resolve pilot-db)"
[ -n "$PILOT_DB" ] || { echo "no pilot database container running — is the suite up?" >&2; exit 1; }
EMAIL="${E2E_EMAIL:-$(docker exec "$PILOT_DB" psql -U pilot pilot -t -A \
        -c "select email from users where role='admin' order by created_at limit 1;" \
        2>/dev/null | tr -d ' \r')}"
if [ -z "$EMAIL" ]; then
    echo "no active admin found in Pilot's directory — is the suite running?" >&2
    exit 1
fi

echo "{" > "$OUT"
first=1
for m in access appsec asset audit compliance pilot risk surface vendor watch; do
    dbc=$(resolve "${m}-db"); appc=$(resolve "$m")
    [ -n "$dbc" ] && [ -n "$appc" ] || { echo "  skip ${m}: container not running" >&2; continue; }
    uid=$(docker exec "$dbc" psql -U "$m" "$m" -t -A \
          -c "select id from users where email='${EMAIL}';" 2>/dev/null | tr -d ' \r')
    [ -n "$uid" ] || { echo "  skip ${m}: ${EMAIL} unknown in its database" >&2; continue; }
    # Pilot federates the others: it has its own src/auth.py, whose create_jwt
    # additionally takes the list of allowed modules.
    if [ "$m" = "pilot" ]; then
        code="from src.auth import create_jwt
print(create_jwt('${uid}', '${EMAIL}', 'admin', [], None, ''))"
    else
        code="from src.auth_common import create_jwt
print(create_jwt('${uid}', '${EMAIL}', 'admin', {'${m}': 'admin'}))"
    fi
    tok=$(docker exec "$appc" python3 -c "
import sys; sys.path.insert(0,'/app')
${code}" 2>/dev/null | tail -1)
    [ -n "$tok" ] || { echo "  skip ${m}: could not mint a token" >&2; continue; }
    [ $first -eq 1 ] || echo "," >> "$OUT"
    printf '  "%s": "%s"' "$m" "$tok" >> "$OUT"
    first=0
done
echo "" >> "$OUT"; echo "}" >> "$OUT"

# The file holds administrator sessions valid for JWT_EXPIRY_HOURS (24 h by
# default). It is gitignored, but it stays readable on disk: restricting it is
# the bare minimum, deleting it after the run is better (`rm tokens.json`).
chmod 600 "$OUT"

n=$(grep -c '":' "$OUT")
echo "minted ${n} token(s) for ${EMAIL} → ${OUT}"
# Having minted nothing is not a success: the journey would skip everything and stay green.
[ "$n" -gt 0 ] || exit 1
