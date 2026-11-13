"""The analysis of an alert is asked, and cached, in the language requested,
whatever its spelling.

`fr-FR` is what a browser sends and ` fr ` what a setting may hold: both are
French, like `fr` and `FR`. Anything else is English. The cache holds one row
per language: a French spelling must read and write the `fr` row, and the row
found is what is returned.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.sql import operators

os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import analysis  # noqa: E402

FRENCH = ["fr", "FR", "fr-FR", "fr_FR", " fr ", "Fr-fr"]
ENGLISH = ["en", "EN", "en-GB", "", None, "de"]


def _alert():
    return SimpleNamespace(
        id=uuid.uuid4(), source="nvd", external_id="CVE-2026-0001", title="Remote code execution",
        summary="A flaw.", severity="critical", cvss_score=9.8, cvss_vector="", epss_score=0.5,
        kev_listed=True, modified_at=None, affected_json=[], references_json=[],
    )


def _language_read(query):
    """The language the cache query asks for: an equality, among conditions that all hold."""
    where = query.whereclause
    assert where.operator is operators.and_, where.operator
    for clause in where.clauses:
        if clause.left.name == "language":
            assert clause.operator is operators.eq, clause.operator
            return clause.right.value
    return None


class _Db:
    """A cache that remembers the language it was read for; empty unless given a row."""

    def __init__(self, cached=None):
        self.cached = cached
        self.added = []
        self.read = []

    async def execute(self, query):
        self.read.append(_language_read(query))
        return SimpleNamespace(scalar_one_or_none=lambda: self.cached)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        pass

    async def refresh(self, _row):
        pass


def _generate(monkeypatch, language):
    asked = {}

    async def provider_model(_db):
        return "anthropic", "a-model"

    async def call(_db, *, system, **_kwargs):
        asked["system"] = system
        return '{"executive_summary": "x"}'

    monkeypatch.setattr(analysis, "_runtime_provider_model", provider_model)
    monkeypatch.setattr(analysis, "call_llm_text", call)
    db = _Db()
    row = asyncio.run(analysis.generate_or_get(db, _alert(), None, language=language))
    return asked["system"], db.read, row.language


@pytest.mark.parametrize("language", FRENCH)
def test_a_french_spelling_gets_the_french_prompt_and_the_french_row(monkeypatch, language):
    system, read, stored = _generate(monkeypatch, language)
    assert system == analysis._SYSTEM_PROMPT_FR
    assert read == ["fr"]
    assert stored == "fr"


@pytest.mark.parametrize("language", ENGLISH)
def test_anything_else_gets_the_english_prompt_and_the_english_row(monkeypatch, language):
    system, read, stored = _generate(monkeypatch, language)
    assert system == analysis._SYSTEM_PROMPT_EN
    assert read == ["en"]
    assert stored == "en"


def test_the_row_found_for_the_language_is_returned_without_asking_the_model(monkeypatch):
    cached = SimpleNamespace(language="fr")

    async def no_model(*_args, **_kwargs):
        raise AssertionError("the model is asked although the analysis is cached")

    monkeypatch.setattr(analysis, "_runtime_provider_model", no_model)
    monkeypatch.setattr(analysis, "call_llm_text", no_model)
    db = _Db(cached)
    assert asyncio.run(analysis.generate_or_get(db, _alert(), None, language="fr-FR")) is cached
    assert db.read == ["fr"]
    assert db.added == []


@pytest.mark.parametrize("language", FRENCH)
def test_the_prompt_alone_reads_a_french_spelling(language):
    assert analysis._system_prompt(language) == analysis._SYSTEM_PROMPT_FR
