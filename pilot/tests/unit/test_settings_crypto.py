"""Lock the at-rest encryption of AppSettings secrets.

Pilot had no crypto module at all: the SMTP password, the AI provider keys and
the AWS / Graph / Proofpoint connector credentials sat in cleartext in
AppSettings.value, so a pg_dump — which shared/db-snapshot.sh makes routine —
handed them over as-is.

The riskiest part is not the cipher, it is the lazy migration: rows written
before encryption must keep working, and a value the current key can no longer
open must NOT be served as if it were plaintext. Both are pinned below.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("ENCRYPTION_KEY", "a" * 64)
    import importlib

    from src import settings_crypto
    importlib.reload(settings_crypto)
    return settings_crypto


class TestRoundTrip:
    def test_encrypt_then_decrypt(self, _key):
        assert _key.decrypt_setting(_key.encrypt_setting("sk-secret")) == "sk-secret"

    def test_ciphertext_does_not_contain_plaintext(self, _key):
        assert "sk-secret" not in _key.encrypt_setting("sk-secret")

    def test_two_encryptions_differ(self, _key):
        # Per-message random salt + nonce: identical input, different output.
        assert _key.encrypt_setting("same") != _key.encrypt_setting("same")

    def test_empty_stays_empty(self, _key):
        assert _key.encrypt_setting("") == ""
        assert _key.decrypt_setting("") == ""

    def test_never_double_wraps(self, _key):
        once = _key.encrypt_setting("v")
        assert _key.encrypt_setting(once) == once


class TestLazyMigration:
    def test_legacy_cleartext_is_returned_unchanged(self, _key):
        # A row written before encryption carries no marker.
        assert _key.decrypt_setting("legacy-plaintext-key") == "legacy-plaintext-key"

    def test_marker_distinguishes_the_two(self, _key):
        assert _key.is_encrypted(_key.encrypt_setting("x"))
        assert not _key.is_encrypted("legacy-plaintext-key")

    def test_undecryptable_is_not_served_as_plaintext(self, _key, monkeypatch):
        """After a key rotation the old ciphertext must yield "", not itself.

        Guessing by "try to decrypt, fall back to the raw value" would hand the
        base64 blob to the provider as if it were the credential — which is why
        the format carries an explicit marker.
        """
        ct = _key.encrypt_setting("secret")
        monkeypatch.setenv("ENCRYPTION_KEY", "b" * 64)
        import importlib

        from src import settings_crypto
        importlib.reload(settings_crypto)
        assert settings_crypto.decrypt_setting(ct) == ""


class TestKeyClassification:
    @pytest.mark.parametrize("key", [
        "ai_key_anthropic", "ai_key_openai", "ai_secret_bedrock", "ai_custom_key",
        "smtp_password", "smtp.password", "shodan.api_key", "shodan_api_key",
        "connector_aws_secret_access_key", "connector_m365_client_secret",
    ])
    def test_credentials_are_secret(self, _key, key):
        assert _key.is_secret_key(key)

    @pytest.mark.parametrize("key", [
        "ai_provider", "ai_model", "ai_region_bedrock", "demo_mode",
        "connector_aws_region", "shodan.last_check_at",
    ])
    def test_configuration_stays_readable(self, _key, key):
        # Encrypting these would only make debugging harder — they are not
        # credentials.
        assert not _key.is_secret_key(key)


class TestEncryptOrPlain:
    def test_encrypts_when_key_present(self, _key):
        ct = _key.encrypt_setting_or_plain("hunter2")
        assert _key.is_encrypted(ct)
        assert _key.decrypt_setting(ct) == "hunter2"

    def test_degrades_to_plaintext_without_key(self, _key, monkeypatch):
        # Standalone deployments without ENCRYPTION_KEY keep their historical
        # behavior instead of failing the SMTP write.
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr(_key, "_KEY", None)
        assert _key.encrypt_setting_or_plain("hunter2") == "hunter2"
