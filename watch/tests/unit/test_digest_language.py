"""The digest is written in English unless French is asked for.

The digest, its subjects and the prompts of the threat brief were French
only: every recipient got a French mail, whatever the language of the
product. They now exist in both languages, English being the one a missing
or unknown language gets; `WATCH_DIGEST_LANG=fr` keeps the French digest.
"""
import asyncio
import html
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import digest  # noqa: E402


def _group():
    day = datetime(2026, 11, 2, tzinfo=timezone.utc)
    return SimpleNamespace(
        primary=SimpleNamespace(id=uuid.uuid4(), source="nvd", external_id="CVE-2026-0001",
                                title="Remote code execution", summary="A flaw."),
        severity="critical", kev_listed=True, ransomware_known=True,
        urgency="PATCH_IMMEDIATELY", risk_score=97.0, max_cvss=9.8, max_epss=0.5,
        sources=["nvd", "kev"], cve_id="CVE-2026-0001",
        timeline=SimpleNamespace(nvd_published=day, kev_date_added=day, patch_lag_days=3,
                                 ransomware_label="Known"),
    )


def _page(language=None, **kwargs):
    if language is not None:
        kwargs["language"] = language
    return html.unescape(digest.render_vuln_digest_html("MedSecure", [_group()], {}, **kwargs))


_ENGLISH = ("Hello,", "Vulnerabilities</strong> digest of the scope", "Critical vulnerabilities (1)",
            "CRITICAL", "PATCH IMMEDIATELY · risk 97", "KEV — exploited", "RANSOMWARE",
            "NVD published:", "Added to KEV:", "NVD→KEV lag:</b> 3 d", "digest sent automatically")
_FRENCH = ("Bonjour,", "du périmètre", "Vulnérabilités critiques (1)", "CRITIQUE",
           "PATCHER IMMÉDIATEMENT · risque 97", "KEV — exploité", "RANÇONGICIEL",
           "Publié NVD :", "Ajout KEV :", "Délai NVD→KEV :</b> 3 j", "digest envoyé automatiquement")


@pytest.mark.parametrize("language", [None, "en", "", "de"])
def test_the_vulnerability_digest_is_english_unless_french_is_asked(language):
    page = _page(language)
    for text in _ENGLISH:
        assert text in page
    for text in _FRENCH:
        assert text not in page


def test_the_vulnerability_digest_is_french_when_asked():
    page = _page("fr")
    for text in _FRENCH:
        assert text in page
    for text in _ENGLISH:
        assert text not in page


def test_an_empty_digest_says_so_in_its_language():
    assert "No critical vulnerability was published" in html.unescape(
        digest.render_vuln_digest_html("MedSecure", [], {}, user_name="Ada"))
    assert "Aucune vulnérabilité critique" in html.unescape(
        digest.render_vuln_digest_html("MedSecure", [], {}, language="fr"))


def test_the_threat_digest_and_the_preview_follow_the_language():
    assert "threat watch</strong> of the scope" in digest.render_threat_digest_html("MedSecure", "", [])
    assert "veille menaces</strong> du périmètre" in digest.render_threat_digest_html(
        "MedSecure", "", [], language="fr")
    preview = html.unescape(digest.render_html("MedSecure", [], {}, threat_skipped="no_ai"))
    assert "Preview of the Watch digest" in preview
    assert "your account has no AI access" in preview


def _shape(texts):
    return {key: _shape(value) if isinstance(value, dict) else None for key, value in texts.items()}


def test_both_languages_carry_the_same_texts():
    assert _shape(digest._L["en"]) == _shape(digest._L["fr"])


@pytest.mark.parametrize("setting,language", [
    (None, "en"), ("", "en"), ("en", "en"), ("fr", "fr"), ("FR", "fr"), ("fr-FR", "fr"), ("de", "en"),
    ("fr_FR", "fr"), (" fr ", "fr"),
])
def test_the_digest_language_is_a_setting(monkeypatch, setting, language):
    if setting is None:
        monkeypatch.delenv("WATCH_DIGEST_LANG", raising=False)
    else:
        monkeypatch.setenv("WATCH_DIGEST_LANG", setting)
    assert digest._digest_language() == language


def test_the_threat_brief_is_asked_in_the_language_of_the_digest():
    english = digest._threat_brief_system("en")
    assert english.startswith("OUTPUT RULE")
    assert "You are a cyber threat-intelligence analyst" in english
    assert "Tu es" not in english
    assert digest._threat_brief_system("") == english
    french = digest._threat_brief_system("fr")
    assert french.startswith("RÈGLE ABSOLUE DE SORTIE")
    assert "Tu es analyste" in french
    assert "Write the note in English" in digest._threat_brief_user("ctx", 7, "en")
    assert "Produis la note en français" in digest._threat_brief_user("ctx", 7, "fr")


def test_the_context_of_a_scope_is_passed_as_written():
    message = digest._threat_brief_user("  Stack: {k8s} and 100% {0}  ", 7, "en")
    assert "CONTEXT (written by the CISO):\nStack: {k8s} and 100% {0}\n" in message
    assert "last 7 days only" in message


def test_the_two_methodologies_have_the_same_structure():
    """A rule added to one language and not to the other is a brief that
    differs with the language."""
    def outline(text):
        return ([line.split(" ")[0] for line in text.splitlines() if line.startswith("#")],
                re.findall(r"<h2 style=\"color:(#[0-9a-f]{6})", text),
                len(re.findall(r"^\s*(?:-|\d+\.) ", text, flags=re.M)))
    assert outline(digest._THREAT_BRIEF_SYSTEM_EN) == outline(digest._THREAT_BRIEF_SYSTEM_FR)
    assert digest._THREAT_BRIEF_SYSTEM_EN


# ── What is sent: the setting reaches the mail, its subject and the brief ──

class _Db:
    """The session of a send: no account behind the address, one run stamped."""

    def __init__(self):
        self.added = []

    async def execute(self, _statement):
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        pass


def _send(monkeypatch, language, send, **scope):
    """Run one send with the module set to `language`; return (mails, db, asked)."""
    day = datetime(2026, 11, 2, tzinfo=timezone.utc)
    mails, asked = [], []

    async def since_for(*_args):
        return day

    async def alerts_for_scope(*_args):
        return []

    async def build_analyses(*_args):
        return {}

    async def render_threat_brief(_db, _scope, _since, language):
        asked.append(language)
        return "<p>brief</p>", []

    monkeypatch.setattr(digest, "_DIGEST_LANGUAGE", language)
    monkeypatch.setattr(digest, "_since_for", since_for)
    monkeypatch.setattr(digest, "_alerts_for_scope", alerts_for_scope)
    monkeypatch.setattr(digest, "group_alerts", lambda _alerts: [_group()])
    monkeypatch.setattr(digest, "_build_analyses", build_analyses)
    monkeypatch.setattr(digest, "_render_threat_brief", render_threat_brief)
    monkeypatch.setattr(digest, "_send_smtp",
                        lambda to, subject, body: mails.append((subject, html.unescape(body))) or (True, ""))
    db = _Db()
    target = SimpleNamespace(id=uuid.uuid4(), name="MedSecure", **scope)
    assert asyncio.run(send(db, target, "ciso@medsecure.example", "2026-11-02", day)) is True
    return mails, db, asked


@pytest.mark.parametrize("language, subject, body", [
    ("en", "1 critical vulnerability", "Critical vulnerabilities (1)"),
    ("fr", "1 vuln. critique", "Vulnérabilités critiques (1)"),
])
def test_the_vulnerability_digest_is_sent_in_the_language_of_the_module(monkeypatch, language, subject, body):
    mails, db, _ = _send(monkeypatch, language, digest._send_vuln_digest)
    assert len(mails) == 1
    assert subject in mails[0][0] and "MedSecure" in mails[0][0]
    assert body in mails[0][1]
    # what is kept of the run is the mail that left
    assert body in html.unescape(db.added[0].body_html)


@pytest.mark.parametrize("language, body", [
    ("en", "threat watch</strong> of the scope"),
    ("fr", "veille menaces</strong> du périmètre"),
])
def test_the_threat_digest_is_sent_in_the_language_of_the_module(monkeypatch, language, body):
    mails, _, asked = _send(monkeypatch, language, digest._send_threat_digest,
                            threat_prompt="Medical devices, hosted in France")
    assert asked == [language]
    assert mails[0][0] == digest._L[language]["subject_threat"].format(scope="MedSecure")
    assert body in mails[0][1]


@pytest.mark.parametrize("language", ["en", "fr"])
def test_the_analyses_of_a_digest_are_asked_in_its_language(monkeypatch, language):
    # The analysis of an alert is kept per language: asked in another one
    # than the digest, the card would mix the two.
    asked = []

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    async def generate_or_get(_db, alert, _user, force=False, language="en"):
        asked.append(language)
        return SimpleNamespace(alert_id=alert.id)

    monkeypatch.setattr(digest, "_DIGEST_LANGUAGE", language)
    monkeypatch.setattr(digest, "async_session", _Session)
    monkeypatch.setattr(digest, "generate_or_get", generate_or_get)
    group = _group()
    analyses = asyncio.run(digest._build_analyses(None, [group]))
    assert asked == [language]
    assert list(analyses) == [group.primary.id]


@pytest.mark.parametrize("language, body, asked_for", [
    ("en", "Critical vulnerabilities (1)", ["en"]),
    ("fr", "Vulnérabilités critiques (1)", ["fr"]),
])
def test_the_preview_shows_the_digest_in_the_language_of_the_module(monkeypatch, language, body, asked_for):
    from src.routes import digest as route

    scope = SimpleNamespace(id=uuid.uuid4(), name="MedSecure",
                            threat_prompt="Medical devices, hosted in France")
    asked = []

    async def user_scopes(*_args):
        return [scope]

    async def alerts_for_scope(*_args):
        return []

    async def render_threat_brief(_db, _scope, _since, language):
        asked.append(language)
        return "<p>brief</p>", []

    monkeypatch.setattr(route, "_DIGEST_LANGUAGE", language)
    monkeypatch.setattr(route, "_user_scopes", user_scopes)
    monkeypatch.setattr(route, "_alerts_for_scope", alerts_for_scope)
    monkeypatch.setattr(route, "group_alerts", lambda _alerts: [_group()])
    monkeypatch.setattr(route, "_render_threat_brief", render_threat_brief)
    monkeypatch.setattr(route, "_check_ai_access", lambda _user: None)
    monkeypatch.setattr(route, "_preview_limiter", route.RateLimiter())
    page = asyncio.run(route.preview_digest(scope_id=None, user=None, db=None))
    assert body in html.unescape(page.body.decode("utf-8"))
    assert asked == asked_for
