#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  pin-images.sh — pin every image in docker-compose.yml to its content digest
# ─────────────────────────────────────────────────────────────────────────────
#
#  A mutable tag (`:latest`, `:16`) can be repointed at a different image after
#  you have reviewed it, so a deployment is neither reproducible nor tamper-
#  evident. Pinning `name:tag@sha256:<digest>` freezes the exact bytes: the tag
#  stays for readability, the digest is what Docker actually resolves.
#
#  This script rewrites each `image:` line in docker-compose.yml in place,
#  resolving the tag to a digest with `skopeo inspect` (falls back to
#  `docker buildx imagetools inspect`). An image already carrying an `@sha256:`
#  is re-resolved from its tag, so re-running after a release refreshes the pin.
#  An image whose repository does not exist yet in the registry is reported and
#  left on its tag — pin it once it is published.
#
#  Run it at RELEASE time, from the suite root:
#      bash tools/pin-images.sh              # rewrite docker-compose.yml
#      bash tools/pin-images.sh --check      # report drift, change nothing (CI)
#
#  Exit: 0 = all resolvable images pinned (or in sync for --check),
#        1 = --check found an unpinned/stale image, 2 = setup error.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMPOSE="docker-compose.yml"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

[ -f "$COMPOSE" ] || { echo "ERROR: $COMPOSE not found (run from the suite root)" >&2; exit 2; }

# Pick ONE resolver up front. Trying skopeo then falling through to
# `docker buildx` on every miss made a not-yet-published image cost two slow
# network round-trips instead of one — skopeo's answer is authoritative.
if command -v skopeo >/dev/null 2>&1; then
  resolve() { timeout 45 skopeo inspect --format '{{.Digest}}' "docker://$1" 2>/dev/null || true; }
elif command -v docker >/dev/null 2>&1; then
  resolve() { timeout 45 docker buildx imagetools inspect "$1" 2>/dev/null | awk '/^Digest:/ {print $2; exit}'; }
else
  resolve() { :; }
fi

command -v skopeo >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 || {
  echo "ERROR: need skopeo or docker to resolve digests" >&2; exit 2; }


# Distinct image references, comment lines excluded (a commented example like
# `#   image: …:1.4.2@sha256:<digest>` must not be treated as a real service).
# The tag is kept; any existing digest is stripped so we can re-resolve.
mapfile -t refs < <(grep -vE '^[[:space:]]*#' "$COMPOSE" \
  | grep -oE 'image:[[:space:]]*[^[:space:]]+' \
  | sed -E 's/image:[[:space:]]*//; s/@sha256:[0-9a-f]+//' | sort -u)

# ── --check: local, network-free. Pinning exists to FREEZE a reviewed digest,
# so the check verifies every image carries an @sha256 — NOT that it matches
# the latest upstream digest (that would break CI whenever a floating tag like
# nginx:alpine moves, and "fixing" it would blind-adopt an unreviewed image).
if [ "$CHECK" = 1 ]; then
  unpinned=0
  while IFS= read -r ref; do
    if grep -E "image:[[:space:]]*$(printf '%s' "$ref" | sed 's/[][\.*^$/]/\\&/g')[[:space:]]*$" "$COMPOSE" >/dev/null 2>&1; then
      echo "  UNPINNED  $ref"; unpinned=$((unpinned+1))
    else
      echo "  pinned    ${ref##*/}"
    fi
  done < <(grep -vE '^[[:space:]]*#' "$COMPOSE" | grep -oE 'image:[[:space:]]*[^[:space:]]+' \
           | sed -E 's/image:[[:space:]]*//' | grep -v '@sha256:' | sort -u)
  echo "──"
  if [ "$unpinned" = 0 ]; then echo "every image is pinned to a digest"; exit 0; fi
  echo "$unpinned image(s) on a mutable tag — run 'bash tools/pin-images.sh' to pin them"; exit 1
fi

# ── default (write): resolve each tag to its current digest and pin it. This is
# a DELIBERATE release action — adopting a tag's current bytes after review.
changed=0 missing=0 already=0
for ref in "${refs[@]}"; do
  dg="$(resolve "$ref")"
  if [ -z "$dg" ]; then
    echo "  ??  $ref — not in the registry, left on its tag"
    missing=$((missing+1)); continue
  fi
  status="$(python3 - "$COMPOSE" "$ref" "$ref@$dg" <<'PY'
import re, sys
path, ref, pinned = sys.argv[1:4]
s = open(path).read()
pat = re.compile(r"(?m)^(\s*image:\s*)" + re.escape(ref) + r"(@sha256:[0-9a-f]+)?\s*$")
if not pat.search(s):
    print("SKIP"); sys.exit(0)
if all((m.group(2) or "") == "@" + pinned.split("@", 1)[1] for m in pat.finditer(s)):
    print("OK"); sys.exit(0)
open(path, "w").write(pat.sub(lambda m: m.group(1) + pinned, s))
print("PINNED")
PY
)"
  case "$status" in
    OK)     echo "  ok  ${ref##*/}"; already=$((already+1)) ;;
    PINNED) echo "  pin ${ref##*/} -> $dg"; changed=$((changed+1)) ;;
    SKIP)   : ;;  # only appeared on a comment line
  esac
done
echo "──"
echo "pinned $changed, already-current $already, not-in-registry $missing"
[ "$missing" != 0 ] && echo "NOTE: $missing image(s) not published yet — re-run after they are."
exit 0
