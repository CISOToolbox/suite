"""Unit tests for the renewal email digest renderer.

build_digest_html() is the email body sent by the renewal scheduler. Asset
names come from user input, so the renderer MUST html-escape them (XSS into
the mail client). The day-count label and the urgency colour are the other
behaviours worth locking.
"""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from renewal_scheduler import _days_label, build_digest_html  # noqa: E402

TODAY = date(2026, 6, 8)


def _due(asset_nom="Serveur", kind="support", date_iso="2026-07-01", days=23):
    return {"asset_id": "A-1", "asset_nom": asset_nom, "kind": kind,
            "date": date_iso, "days": days}


def test_header_shows_count():
    html = build_digest_html([_due(), _due()], TODAY)
    assert "Asset deadlines — 2" in html


def test_kind_labels_are_human_readable():
    html = build_digest_html(
        [_due(kind="licence"), _due(kind="support"), _due(kind="vie")], TODAY)
    assert "Software license" in html
    assert "Hardware support" in html
    assert "End of life" in html


def test_asset_name_is_html_escaped():
    html = build_digest_html([_due(asset_nom="<script>alert(1)</script>")], TODAY)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_overdue_uses_red_and_near_term_orange():
    overdue = build_digest_html([_due(days=-5)], TODAY)
    assert "#dc2626" in overdue  # red
    near = build_digest_html([_due(days=10)], TODAY)
    assert "#f97316" in near  # orange (<= 30 d)
    far = build_digest_html([_due(days=80)], TODAY)
    assert "#eab308" in far  # yellow (> 30 d)


def test_days_label_phrasing():
    assert _days_label(0) == "today"
    assert _days_label(-3) == "3 day(s) overdue"
    assert _days_label(12) == "in 12 day(s)"


def test_digest_is_a_table_with_one_row_per_due():
    html = build_digest_html([_due(), _due(), _due()], TODAY)
    assert html.count("<tr>") == 3  # one row per deadline (header uses <thead>/<th>)


def test_generated_texts_spell_license_like_the_interface():
    """`licence` is a key of the data model; a text the scheduler writes — a
    mail, the title and the note of a generated measure — reads "license"."""
    import ast
    import renewal_scheduler

    tree = ast.parse(open(renewal_scheduler.__file__, encoding="utf-8").read())
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    texts = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in docstrings
        and " " in node.value and "licence" in node.value.lower()
    ]
    assert not texts, texts
