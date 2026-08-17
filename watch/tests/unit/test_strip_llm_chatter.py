"""Tests for the threat-brief LLM-chatter stripper.

Claude with ``web_search`` regularly narrates the workflow before
emitting the HTML brief. ``_strip_llm_chatter`` must trim that
preamble (and any trailing wrap-up text) so the email body starts
on a real HTML tag.
"""
from __future__ import annotations

from src.digest import _strip_llm_chatter


def test_strips_leading_workflow_narration():
    raw = (
        "Je vais lancer toutes les recherches en parallèle pour couvrir "
        "l'ensemble de la stack et du secteur.\n\n"
        "Toutes les recherches sont terminées. Je dispose de suffisamment "
        "d'information pour produire la note. Voici le rapport complet en "
        "HTML : ---\n\n"
        "<p>Synthèse de la période</p>"
        "<h2>P1</h2><p>contenu</p>"
    )
    out = _strip_llm_chatter(raw)
    assert out.startswith("<p>Synthèse")
    assert "Je vais lancer" not in out
    assert "---" not in out


def test_passthrough_when_already_clean():
    raw = "<p>Direct content</p><h2>X</h2><p>Y</p>"
    assert _strip_llm_chatter(raw) == raw


def test_strips_trailing_wrap_up_text():
    raw = "<h2>X</h2><p>A</p>\n\nLe rapport ci-dessus couvre la période."
    assert _strip_llm_chatter(raw) == "<h2>X</h2><p>A</p>"


def test_empty_input_passes_through():
    assert _strip_llm_chatter("") == ""


def test_no_html_at_all_returns_input_unchanged():
    # Defensive: if Claude failed to emit HTML at all, prefer showing
    # whatever it returned over an empty brief.
    raw = "No HTML at all just text"
    assert _strip_llm_chatter(raw) == raw


def test_h2_first_when_no_paragraph_preamble():
    raw = (
        "Voici la note demandée :\n\n"
        "<h2 style=\"color:#c0392b\">🔴 Priorité 1</h2>"
        "<p>contenu</p>"
    )
    out = _strip_llm_chatter(raw)
    assert out.startswith('<h2 style="color:#c0392b">')
    assert "Voici la note" not in out
