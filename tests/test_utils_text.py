"""Tests for mimir.utils.text — shared text-processing utilities."""

from __future__ import annotations

from mimir.utils.text import normalize_text, snippet, strip_html


# ── strip_html ──────────────────────────────────────────────────


class TestStripHtml:
    def test_removes_tags(self):
        assert strip_html("<p>Hello <b>world</b></p>") == "Hello world"

    def test_collapses_whitespace(self):
        assert strip_html("<p>Hello</p>   <p>world</p>") == "Hello world"

    def test_unescapes_entities(self):
        # &lt; &gt; become < > which is then stripped as a tag
        assert strip_html("&amp;") == "&"
        assert strip_html("Tom &amp; Jerry") == "Tom & Jerry"

    def test_empty_string(self):
        assert strip_html("") == ""

    def test_no_html(self):
        assert strip_html("plain text") == "plain text"

    def test_nested_tags(self):
        result = strip_html("<div><span>nested</span> <em>content</em></div>")
        assert "nested" in result
        assert "content" in result
        assert "<" not in result


# ── normalize_text ──────────────────────────────────────────────


class TestNormalizeText:
    def test_strips_tags_and_collapses(self):
        result = normalize_text("<p>Hello</p>\n\n<p>world</p>")
        assert result == "Hello world"

    def test_unescapes_entities(self):
        assert normalize_text("&amp;") == "&"

    def test_empty_string(self):
        assert normalize_text("") == ""

    def test_whitespace_normalization(self):
        assert normalize_text("  foo   bar  ") == "foo bar"

    def test_tabs_and_newlines(self):
        assert normalize_text("foo\t\nbar") == "foo bar"


# ── snippet ──────────────────────────────────────────────────────


class TestSnippet:
    def test_short_text_unchanged(self):
        text = "short"
        assert snippet(text) == "short"

    def test_exact_limit(self):
        text = "x" * 400
        assert snippet(text) == text

    def test_truncates_with_ellipsis(self):
        text = "x" * 500
        result = snippet(text)
        assert result.endswith("...")
        assert len(result) <= 403  # 400 + "..."

    def test_custom_limit(self):
        text = "hello world this is a test"
        result = snippet(text, limit=10)
        assert result.endswith("...")
        assert len(result) <= 13

    def test_strips_whitespace(self):
        assert snippet("  hello  ") == "hello"

    def test_empty_string(self):
        assert snippet("") == ""
