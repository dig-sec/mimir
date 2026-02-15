"""Shared datetime parsing and UTC conversion helpers.

Consolidates the various _parse_datetime / _parse_iso_datetime /
_iso_to_dt / _epoch_ms_to_dt implementations that were previously
duplicated across connectors, routes, runner, and lake modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional


def parse_iso_datetime(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string (with or without ``Z`` suffix) to UTC.

    Returns *None* on invalid or empty input rather than raising.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_rfc2822_or_iso(value: str) -> Optional[datetime]:
    """Parse an RFC-2822 or ISO-8601 date string to UTC.

    Tries RFC-2822 first (common in RSS feeds), then falls back to
    :func:`parse_iso_datetime`.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        pass
    return parse_iso_datetime(text)


def epoch_ms_to_datetime(epoch_ms: Any) -> Optional[datetime]:
    """Convert epoch-milliseconds (e.g. Feedly timestamps) to UTC datetime."""
    if epoch_ms is None:
        return None
    try:
        ts = int(epoch_ms) / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def to_utc(dt: datetime) -> datetime:
    """Ensure a datetime is UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
