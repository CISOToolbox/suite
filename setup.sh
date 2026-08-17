#!/usr/bin/env bash
# ── CISO Toolbox — Initial Setup ─────────────────────────────
# Run once before first docker compose up
set -euo pipefail
cd "$(dirname "$0")"

echo "╔══════════════════════════════════════════════════╗"
echo "║  CISO Toolbox — Setup                             "
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 1. Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate secrets — a DEDICATED value for each trust domain
    JWT=$(openssl rand -hex 32)
    SVC=$(openssl rand -hex 32)
    ENC=$(openssl rand -hex 32)
    DBP=$(openssl rand -hex 16)
    # Backup secrets. The compose file only checks these are non-empty, so the
    # literal "change-me" from .env.example satisfied it — the stack booted with
    # a recovery token published in this repository, guarding an API that can
    # drop a live database, and a pgBackRest repo "encrypted" with a public
    # passphrase. Generated here, and the agent refuses to start on either.
    BCP=$(openssl rand -hex 32)
    BAT=$(openssl rand -hex 32)
    sed -i.bak "s/JWT_SECRET=change-me.*/JWT_SECRET=$JWT/" .env
    sed -i.bak "s/SERVICE_TOKEN=change-me.*/SERVICE_TOKEN=$SVC/" .env
    sed -i.bak "s/ENCRYPTION_KEY=change-me.*/ENCRYPTION_KEY=$ENC/" .env
    sed -i.bak "s/DB_PASSWORD=change-me.*/DB_PASSWORD=$DBP/" .env
    sed -i.bak "s/BACKUP_CIPHER_PASS=change-me.*/BACKUP_CIPHER_PASS=$BCP/" .env
    sed -i.bak "s/BACKUP_AGENT_TOKEN=change-me.*/BACKUP_AGENT_TOKEN=$BAT/" .env
    rm -f .env.bak
    echo "  .env created with generated secrets"
    echo "  ⚠ BACKUP_CIPHER_PASS encrypts every backup — losing it makes them"
    echo "    unreadable. Copy it into your vault now."
    echo "  → Edit .env to add your OAuth credentials"
else
    echo "  .env already exists"
    if ! grep -q "^ENCRYPTION_KEY=" .env; then
        echo "  ⚠ ENCRYPTION_KEY is missing from .env and is now REQUIRED."
        echo "    Add it manually:  openssl rand -hex 32"
        echo "    (If connector credentials are already stored, set it to your"
        echo "     current JWT_SECRET value first, then rotate.)"
    fi
    # An .env produced before these were generated still carries the public
    # placeholder. Rotating the token is free; rotating the cipher passphrase
    # is NOT — it orphans existing backups — so that one is only flagged.
    if grep -qE "^BACKUP_AGENT_TOKEN=(change-me|\s*$)" .env; then
        NEW=$(openssl rand -hex 32)
        sed -i.bak "s|^BACKUP_AGENT_TOKEN=.*|BACKUP_AGENT_TOKEN=$NEW|" .env
        rm -f .env.bak
        echo "  ✓ BACKUP_AGENT_TOKEN was still the placeholder — rotated."
    fi
    if grep -qE "^BACKUP_CIPHER_PASS=(change-me|\s*$)" .env; then
        echo "  ⚠ BACKUP_CIPHER_PASS is still the placeholder from .env.example."
        echo "    That value is public: your backup repository is NOT encrypted."
        echo "    Set a real one (openssl rand -hex 32), store it in your vault,"
        echo "    then re-create the stanzas — existing backups cannot be read"
        echo "    with a new passphrase. The backup agent refuses to start until"
        echo "    this is fixed."
    fi
fi

# .env holds every secret of the stack — keep it owner-readable only.
chmod 600 .env

# 2. Generate self-signed TLS cert for local dev
mkdir -p certs
if [ ! -f certs/cert.pem ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/key.pem -out certs/cert.pem \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "  TLS certificate generated (self-signed, valid 1 year)"
else
    echo "  TLS certificate already exists"
fi
# The TLS private key is a secret like .env — never world/group readable.
[ -f certs/key.pem ] && chmod 600 certs/key.pem

echo ""
echo "  Setup complete. Run:"
echo "    docker compose up -d"
echo ""
echo "  Then open: https://localhost"
