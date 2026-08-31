#!/usr/bin/env bash
# Frappe un JWT de session par module et les écrit dans tokens.json (gitignoré).
#
# Chaque module signe avec sa propre clé, d'où un jeton par module plutôt qu'un
# jeton partagé. Le compte utilisé est découvert dans l'annuaire de Pilot : un
# JWT valide ne suffit pas, `_is_active_upstream` demande à Pilot si le compte
# est actif, et refuse tout email qu'il ne connaît pas — c'est ce qui rend
# inutilisable un compte de test présent seulement dans la base d'un module.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
PREFIX="${CISO_CONTAINER_PREFIX:-ciso2}"
OUT=tokens.json

# Un administrateur réellement actif côté Pilot. Découvert, jamais codé en dur.
EMAIL="${E2E_EMAIL:-$(docker exec "${PREFIX}-pilot-db" psql -U pilot pilot -t -A \
        -c "select email from users where role='admin' order by created_at limit 1;" \
        2>/dev/null | tr -d ' \r')}"
if [ -z "$EMAIL" ]; then
    echo "no active admin found in Pilot's directory — is the suite running?" >&2
    exit 1
fi

echo "{" > "$OUT"
first=1
for m in access appsec asset audit compliance pilot risk surface vendor watch; do
    uid=$(docker exec "${PREFIX}-${m}-db" psql -U "$m" "$m" -t -A \
          -c "select id from users where email='${EMAIL}';" 2>/dev/null | tr -d ' \r')
    [ -n "$uid" ] || { echo "  skip ${m}: ${EMAIL} unknown in its database" >&2; continue; }
    # Pilot federe les autres : il a son propre src/auth.py, dont create_jwt
    # prend en plus la liste des modules autorises.
    if [ "$m" = "pilot" ]; then
        code="from src.auth import create_jwt
print(create_jwt('${uid}', '${EMAIL}', 'admin', [], None, ''))"
    else
        code="from src.auth_common import create_jwt
print(create_jwt('${uid}', '${EMAIL}', 'admin', {'${m}': 'admin'}))"
    fi
    tok=$(docker exec "${PREFIX}-${m}" python3 -c "
import sys; sys.path.insert(0,'/app')
${code}" 2>/dev/null | tail -1)
    [ -n "$tok" ] || { echo "  skip ${m}: could not mint a token" >&2; continue; }
    [ $first -eq 1 ] || echo "," >> "$OUT"
    printf '  "%s": "%s"' "$m" "$tok" >> "$OUT"
    first=0
done
echo "" >> "$OUT"; echo "}" >> "$OUT"

# Le fichier contient des sessions administrateur valides pendant
# JWT_EXPIRY_HOURS (24 h par defaut). Il est gitignore, mais il reste lisible
# sur le disque : le restreindre est le minimum, l'effacer apres la campagne
# est mieux (`rm tokens.json`).
chmod 600 "$OUT"

n=$(grep -c '":' "$OUT")
echo "minted ${n} token(s) for ${EMAIL} → ${OUT}"
# Ne rien avoir frappé n'est pas un succès : le parcours skiperait tout en vert.
[ "$n" -gt 0 ] || exit 1
