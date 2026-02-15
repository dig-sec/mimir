"""Tests for mimir.utils.datetime — shared datetime parsing helpers."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from mimir.utils.datetime import (
    epoch_ms_to_datetime,
    parse_iso_datetime,
    parse_rfc2822_or_iso,
    to_utc,
)


# ── parse_iso_datetime ──────────────────────────────────────────


class TestParseIsoDatetime:
    def test_basic_iso_z(self):
        dt = parse_iso_datetime("2026-02-12T10:30:00Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 2
        assert dt.day == 12
        assert dt.hour == 10
        assert dt.minute == 30
        assert dt.tzinfo == timezone.utc

    def test_iso_with_offset(self):
        dt = parse_iso_datetime("2026-06-15T14:00:00+02:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 12  # 14:00+02:00 → 12:00 UTC

    def test_naive_datetime_treated_as_utc(self):
        dt = parse_iso_datetime("2026-01-01T00:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_datetime_object_passthrough(self):
        original = datetime(2026, 3, 1, 8, tzinfo=timezone.utc)
        dt = parse_iso_datetime(original)
        assert dt is original

    def test_naive_datetime_object_gets_utc(self):
        naive = datetime(2026, 3, 1, 8)
        dt = parse_iso_datetime(naive)
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 8

    def test_none_returns_none(self):
        assert parse_iso_datetime(None) is None

    def test_empty_string_returns_none(self):
        assert parse_iso_datetime("") is None
        assert parse_iso_datetime("   ") is None

    def test_invalid_string_returns_none(self):
        assert parse_iso_datetime("not-a-date") is None

    def test_whitespace_stripped(self):
        dt = parse_iso_datetime("  2026-02-12T10:30:00Z  ")
        assert dt is not None
        assert dt.year == 2026


# ── parse_rfc2822_or_iso ────────────────────────────────────────


class TestParseRfc2822OrIso:
    def test_rfc2822_date(self):
        dt = parse_rfc2822_or_iso("Tue, 15 Jun 2026 14:00:00 +0000")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 6
        assert dt.day == 15
        assert dt.tzinfo == timezone.utc

    def test_rfc2822_with_offset(self):
        dt = parse_rfc2822_or_iso("Tue, 15 Jun 2026 14:00:00 +0200")
        assert dt is not None
        assert dt.hour == 12  # converted to UTC

    def test_falls_back_to_iso(self):
        dt = parse_rfc2822_or_iso("2026-06-15T14:00:00Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.tzinfo == timezone.utc

    def test_empty_returns_none(self):
        assert parse_rfc2822_or_iso("") is None
        assert parse_rfc2822_or_iso(None) is None

    def test_garbage_returns_none(self):
        assert parse_rfc2822_or_iso("not a date at all") is None


# ── epoch_ms_to_datetime ────────────────────────────────────────


class TestEpochMsToDatetime:
    def test_valid_epoch_ms(self):
        # 2024-02-12T10:30:00 UTC in ms
        ms = 1707735000000
        dt = epoch_ms_to_datetime(ms)
        assert dt is not None
        assert dt.year == 2024
        assert dt.tzinfo == timezone.utc

    def test_string_epoch_ms(self):
        dt = epoch_ms_to_datetime("1707735000000")
        assert dt is not None
        assert dt.year == 2024

    def test_none_returns_none(self):
        assert epoch_ms_to_datetime(None) is None

    def test_invalid_returns_none(self):
        assert epoch_ms_to_datetime("not-a-number") is None

    def test_zero_epoch(self):
        dt = epoch_ms_to_datetime(0)
        assert dt is not None
        assert dt.year == 1970


# ── to_utc ──────────────────────────────────────────────────────


class TestToUtc:
    def test_naive_gets_utc(self):
        naive = datetime(2026, 1, 1, 12)
        result = to_utc(naive)
        assert result.tzinfo == timezone.utc
        assert result.hour == 12

    def test_utc_passthrough(self):
        utc_dt = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        result = to_utc(utc_dt)
        assert result is utc_dt

    def test_offset_converted(self):
        eastern = timezone(timedelta(hours=-5))
        dt = datetime(2026, 1, 1, 12, tzinfo=eastern)
        result = to_utc(dt)
        assert result.tzinfo == timezone.utc
        assert result.hour == 17  # 12:00-05:00 → 17:00 UTC
