"""The language asked of the model is read whatever its spelling.

`fr-FR` is what a browser sends and ` fr ` what a setting may hold: both are
French, like `fr` and `FR`. Anything else is English. The routes are called
too: each one hands the language of its request to the prompt.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("MODULE_NAME", "asset")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import ai  # noqa: E402
from src.routes.ai import _asset_system  # noqa: E402

FRENCH = ["fr", "FR", "fr-FR", "fr_FR", " fr ", "Fr-fr"]
ENGLISH = ["en", "EN", "en-GB", "", None, "de"]


@pytest.mark.parametrize("language", FRENCH)
def test_the_assistant_is_asked_in_french(language):
    assert "Respond in French" in _asset_system(language=language)


@pytest.mark.parametrize("language", ENGLISH)
def test_the_assistant_is_asked_in_english(language):
    system = _asset_system(language=language)
    assert "Respond in English" in system
    assert "French" not in system


# What a route receives: the spelling is read by the tests above.
SENT_FRENCH = ["fr-FR", " FR "]
SENT_ENGLISH = ["en", "", "de"]


class _Asked(Exception):
    """Raised by the fake provider: the handler stops once its prompt is known."""


def _asked_by(monkeypatch, handler, body, db=None):
    """The text the route hands to the model for `body`."""
    asked = {}

    async def provider_model(_db):
        return "anthropic", "a-model"

    async def complete(_db, system, user_prompt, _provider, _model):
        asked["text"] = system + "\n" + user_prompt
        raise _Asked

    monkeypatch.setattr(ai, "_check_ai_access", lambda _user: None)
    monkeypatch.setattr(ai, "_check_rate_limit", lambda _key: None)
    monkeypatch.setattr(ai, "_runtime_provider_model", provider_model)
    monkeypatch.setattr(ai, "_provider_complete", complete)
    with pytest.raises(_Asked):
        asyncio.run(handler(body, user=None, db=db))
    return asked["text"]


ROUTES = [
    (ai.asset_suggest_description, ai.AssetDescriptionRequest),
    (ai.asset_suggest_principe, ai.AssetPrincipeRequest),
    (ai.asset_suggest_raci, ai.AssetRaciRequest),
    (ai.asset_suggest_policies, ai.AssetPoliciesRequest),
]


@pytest.mark.parametrize("handler,request_model", ROUTES)
@pytest.mark.parametrize("language", SENT_FRENCH)
def test_a_route_asks_for_french(monkeypatch, handler, request_model, language):
    asked = _asked_by(monkeypatch, handler, request_model(nom="Server", language=language))
    assert "Respond in French" in asked


@pytest.mark.parametrize("handler,request_model", ROUTES)
@pytest.mark.parametrize("language", SENT_ENGLISH)
def test_a_route_asks_for_english(monkeypatch, handler, request_model, language):
    asked = _asked_by(monkeypatch, handler, request_model(nom="Server", language=language))
    assert "Respond in English" in asked and "French" not in asked


@pytest.mark.parametrize("handler,request_model", ROUTES)
def test_a_route_without_a_language_asks_for_english(monkeypatch, handler, request_model):
    asked = _asked_by(monkeypatch, handler, request_model(nom="Server"))
    assert "Respond in English" in asked and "French" not in asked
