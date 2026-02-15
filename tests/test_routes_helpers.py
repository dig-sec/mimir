"""Tests for mimir.api.routes._helpers — route-level helper functions.

Tests the pure/deterministic helpers directly to avoid the heavy
routes-import machinery that test_routes_worker_status.py uses.
"""

from __future__ import annotations

import importlib
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest


# ── Helpers to import _helpers without triggering the full route init ─


def _import_helpers(monkeypatch):
    """Import routes._helpers with mocked singletons."""
    import mimir.storage.factory as factory

    monkeypatch.setattr(factory, "create_graph_store", lambda s: MagicMock())
    monkeypatch.setattr(factory, "create_run_store", lambda s: MagicMock())
    monkeypatch.setattr(factory, "create_metrics_store", lambda s: MagicMock())

    # Clear cached modules so we get a fresh import
    for key in list(sys.modules):
        if key.startswith("mimir.api.routes"):
            sys.modules.pop(key, None)

    return importlib.import_module("mimir.api.routes._helpers")


# ── bucket_start ────────────────────────────────────────────────


class TestBucketStart:
    def test_day(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 6, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "day")
        assert result == datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)

    def test_week_monday(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        # 2026-06-15 is a Monday
        dt = datetime(2026, 6, 18, 10, 0, 0, tzinfo=timezone.utc)  # Thursday
        result = h.bucket_start(dt, "week")
        assert result.weekday() == 0  # Monday
        assert result.day == 15

    def test_month(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 6, 18, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "month")
        assert result == datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_quarter_q1(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 2, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "quarter")
        assert result == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_quarter_q2(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 5, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "quarter")
        assert result == datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_quarter_q3(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "quarter")
        assert result == datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_quarter_q4(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "quarter")
        assert result == datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_year(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 6, 18, 10, 0, 0, tzinfo=timezone.utc)
        result = h.bucket_start(dt, "year")
        assert result == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_naive_datetime_treated_as_utc(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        dt = datetime(2026, 6, 15, 14, 30)
        result = h.bucket_start(dt, "day")
        assert result.tzinfo == timezone.utc


# ── parse_window_bounds ─────────────────────────────────────────


class TestParseWindowBounds:
    def test_full_iso_timestamps(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        since, until = h.parse_window_bounds(
            "2026-06-01T00:00:00Z", "2026-06-30T23:59:59Z"
        )
        assert since is not None
        assert until is not None
        assert since.year == 2026
        assert until.day == 30

    def test_date_only_gets_default_times(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        since, until = h.parse_window_bounds("2026-06-01", "2026-06-30")
        assert since is not None
        assert until is not None
        assert since.hour == 0
        assert until.hour == 23
        assert until.minute == 59

    def test_none_inputs_return_none(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h.parse_window_bounds(None, None) == (None, None)
        assert h.parse_window_bounds("", "") == (None, None)
        assert h.parse_window_bounds("2026-06-01T00:00:00Z", None) == (None, None)

    def test_invalid_date_raises_400(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            h.parse_window_bounds("not-a-date", "also-not-a-date")
        assert exc_info.value.status_code == 400


# ── _worker_health_for_state ────────────────────────────────────


class TestWorkerHealthForState:
    def test_running_is_ok(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("running") == "ok"

    def test_sleeping_is_ok(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("sleeping") == "ok"

    def test_error_is_err(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("error") == "err"

    def test_disabled_is_warn(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("disabled") == "warn"

    def test_stale_is_warn(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("stale") == "warn"

    def test_starting_is_pending(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("starting") == "pending"

    def test_unknown_state_is_pending(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("banana") == "pending"

    def test_empty_string_is_pending(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("") == "pending"

    def test_case_insensitive(self, monkeypatch):
        h = _import_helpers(monkeypatch)
        assert h._worker_health_for_state("Running") == "ok"
        assert h._worker_health_for_state("ERROR") == "err"
