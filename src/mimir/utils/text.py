"""Shared text-processing utilities.

Consolidates HTML stripping and whitespace normalisation that was
duplicated across ``connectors/__init__._strip_html`` and
``connectors/rss._normalize_text``.
"""

from __future__ import annotations

import html as html_mod
import re

_TAG_RE = re.compile(r"<[^>]+>")
_MULTI_WS_RE = re.compile(r"\s{2,}")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    if not text:
        return ""
    out = html_mod.unescape(text)
    if "<" in out and ">" in out:
        out = _TAG_RE.sub(" ", out)
    out = _MULTI_WS_RE.sub(" ", out).strip()
    return out


def normalize_text(value: str) -> str:
    """HTML-unescape, strip tags, and collapse all whitespace."""
    if not value:
        return ""
    out = html_mod.unescape(value)
    if "<" in out and ">" in out:
        out = _TAG_RE.sub(" ", out)
    out = _WS_RE.sub(" ", out).strip()
    return out


def snippet(text: str, limit: int = 400) -> str:
    """Truncate *text* to *limit* characters with an ellipsis."""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."
