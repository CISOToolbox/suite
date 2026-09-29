"""Unit tests for the custom asset type cleaning.

`_clean_custom_types()` runs on every save and import and on every read of a
project. The colour of a type is rendered into a style attribute, so only a
``#rrggbb`` value may come out of it; anything else becomes the default colour
instead of failing the save.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

from routes.projects import DEFAULT_TYPE_COLOR, _clean_custom_types  # noqa: E402


def _color(value):
    return _clean_custom_types([{"id": "t", "label": "T", "color": value}])[0]["color"]


def test_a_valid_colour_is_kept_lower_cased():
    assert _color("#94A3B8") == "#94a3b8"
    assert _color(" #2563eb ") == "#2563eb"
    assert _color("#aabbcc\n") == "#aabbcc"


@pytest.mark.parametrize("value", [
    "#fff",                       # short form: not what a colour input holds
    "var(--ct-ink-2)",            # a CSS variable is not data
    'red" onmouseover="x',        # leaves the attribute
    "red;position:fixed",         # chains a declaration, fits in 16 chars
    "#aabbcc;top:0",              # valid prefix, trailing declaration
    "",
    None,
    123,
    ["#aabbcc"],
])
def test_anything_else_becomes_the_default(value):
    assert _color(value) == DEFAULT_TYPE_COLOR


def test_a_missing_colour_gets_the_default():
    assert _clean_custom_types([{"id": "t"}])[0]["color"] == DEFAULT_TYPE_COLOR


def test_entries_are_normalised_and_deduplicated():
    out = _clean_custom_types([
        {"id": " Reseau ", "label": "Réseau", "color": "#123456"},
        {"id": "reseau", "label": "doublon"},
        {"label": "sans id"},
        "not a dict",
    ])
    assert out == [{"id": "reseau", "label": "Réseau", "label_en": "", "color": "#123456"}]


def test_a_non_list_gives_an_empty_list():
    assert _clean_custom_types(None) == []
    assert _clean_custom_types({"id": "t"}) == []
