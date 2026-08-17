from __future__ import annotations

import json
import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_KEY = None
_SALT_LEN = 16
_NONCE_LEN = 12
_KDF_ITERATIONS = 310_000


_MIN_KEY_LEN = 32  # 32 bytes (256 bits) minimum — matches token_hex(32) = 64 chars


def _get_key() -> bytes:
    global _KEY
    if _KEY is None:
        raw = os.environ.get("ENCRYPTION_KEY", "")
        if not raw:
            raise RuntimeError(
                "ENCRYPTION_KEY environment variable must be set for plugin credential encryption. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(raw) < _MIN_KEY_LEN:
            raise RuntimeError(
                f"ENCRYPTION_KEY too short ({len(raw)} chars): minimum {_MIN_KEY_LEN}. "
                "Regenerate with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        _KEY = raw.encode()
    return _KEY


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ITERATIONS)
    return kdf.derive(passphrase)


def encrypt_config(data: dict) -> str:
    salt = os.urandom(_SALT_LEN)
    key = _derive(_get_key(), salt)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
    return b64encode(salt + nonce + ct).decode()


def decrypt_config(ciphertext: str) -> dict:
    raw = b64decode(ciphertext)
    salt = raw[:_SALT_LEN]
    nonce = raw[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ct = raw[_SALT_LEN + _NONCE_LEN:]
    key = _derive(_get_key(), salt)
    return json.loads(AESGCM(key).decrypt(nonce, ct, None))
