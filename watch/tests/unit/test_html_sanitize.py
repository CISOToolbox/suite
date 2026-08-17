"""Lock the allow-list sanitiser applied to LLM-generated digest HTML.

The brief is produced by a model running with web search enabled, so it is
untrusted twice over: the threat_prompt is written by a scope owner, and a
search result can carry an indirect injection. What it replaced was a replace()
over six literals, which none of the event-handler vectors below matched.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.html_sanitize import safe_url, sanitize_html  # noqa: E402


class TestEventHandlersStripped:
    """The vectors the previous deny-list let straight through."""

    @pytest.mark.parametrize("payload", [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)></svg>',
        '<body onload=alert(1)>',
        '<div onmouseover="evil()">t</div>',
        '<p ONCLICK="evil()">t</p>',
        '<input onfocus=alert(1) autofocus>',
    ])
    def test_no_handler_survives(self, payload):
        out = sanitize_html(payload)
        assert "onerror" not in out.lower()
        assert "onload" not in out.lower()
        assert "onclick" not in out.lower()
        assert "onmouseover" not in out.lower()
        assert "onfocus" not in out.lower()
        assert "alert" not in out or "<" not in out


class TestDangerousTagsDropped:
    def test_script_content_removed_not_pasted(self):
        # Dropping only the tag would paste the script body as visible text.
        out = sanitize_html("<script>alert(1)</script>hello")
        assert "alert" not in out
        assert "hello" in out

    def test_style_content_removed(self):
        out = sanitize_html("<style>body{background:url(x)}</style>rest")
        assert "background" not in out
        assert "rest" in out

    @pytest.mark.parametrize("tag", ["iframe", "object", "embed", "svg", "img", "form"])
    def test_embedding_tags_dropped(self, tag):
        out = sanitize_html(f'<{tag} src="//evil.example"></{tag}>')
        assert f"<{tag}" not in out

    def test_conditional_comment_dropped(self):
        out = sanitize_html("<!--[if IE]><script>x</script><![endif]-->ok")
        assert "script" not in out
        assert "ok" in out


class TestUrlSchemes:
    @pytest.mark.parametrize("bad", [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "java\tscript:alert(1)",      # control chars smuggle the scheme past naive checks
        "data:text/html,<h1>x</h1>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "//evil.example/path",         # protocol-relative: inherits https, off-origin
    ])
    def test_unsafe_scheme_rejected(self, bad):
        assert safe_url(bad) == ""

    @pytest.mark.parametrize("good", [
        "https://example.org/a",
        "http://example.org/a",
        "mailto:someone@example.org",
        "/relative/path",
    ])
    def test_safe_url_kept(self, good):
        assert safe_url(good) == good

    def test_anchor_keeps_text_drops_bad_href(self):
        out = sanitize_html('<a href="javascript:alert(1)">click</a>')
        assert "javascript" not in out.lower()
        assert "click" in out

    def test_anchor_keeps_good_href(self):
        out = sanitize_html('<a href="https://example.org/x">ok</a>')
        assert 'href="https://example.org/x"' in out


class TestContentPreserved:
    def test_formatting_survives(self):
        out = sanitize_html("<p>Some <strong>bold</strong> and <em>italic</em></p>")
        assert out == "<p>Some <strong>bold</strong> and <em>italic</em></p>"

    def test_lists_and_tables_survive(self):
        out = sanitize_html("<ul><li>a</li><li>b</li></ul>")
        assert out == "<ul><li>a</li><li>b</li></ul>"

    def test_unbalanced_input_is_closed(self):
        out = sanitize_html("<div><b>unclosed")
        assert out == "<div><b>unclosed</b></div>"

    def test_text_is_escaped(self):
        out = sanitize_html("5 < 6 & 7 > 2")
        assert "&lt;" in out and "&amp;" in out

    def test_empty_input(self):
        assert sanitize_html("") == ""
        assert sanitize_html(None) == ""
