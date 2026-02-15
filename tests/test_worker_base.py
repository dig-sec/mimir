"""Tests for mimir.worker._base — connector-worker base infrastructure."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mimir.worker._base import (
    CycleSummary,
    PreflightResult,
    _shutdown,
    run_connector_loop,
)


# ── Data-class defaults ─────────────────────────────────────────


class TestPreflightResult:
    def test_defaults(self):
        pf = PreflightResult()
        assert pf.ok is True
        assert pf.reason == ""
        assert pf.interval_seconds == 0.0
        assert pf.extra_heartbeat == {}

    def test_disabled(self):
        pf = PreflightResult(ok=False, reason="not configured")
        assert pf.ok is False
        assert pf.reason == "not configured"


class TestCycleSummary:
    def test_defaults(self):
        cs = CycleSummary()
        assert cs.log_message == ""
        assert cs.heartbeat_details == {}
        assert list(cs.errors) == []

    def test_with_errors(self):
        cs = CycleSummary(errors=["err1", "err2"])
        assert len(cs.errors) == 2


# ── run_connector_loop ──────────────────────────────────────────


def _fake_settings():
    return SimpleNamespace(log_level="WARNING")


def _make_heartbeat():
    hb = MagicMock()
    hb.update = MagicMock()
    return hb


def test_loop_exits_when_preflight_fails(tmp_path):
    """Worker should exit immediately with a disabled heartbeat update."""
    pf = PreflightResult(ok=False, reason="missing token")
    calls = []

    def preflight(settings):
        calls.append("preflight")
        return pf

    def run_cycle(settings, since, until, heartbeat):
        calls.append("cycle")
        return CycleSummary()

    with (
        patch("mimir.worker._base.get_settings", _fake_settings),
        patch("mimir.worker._base.WorkerHeartbeat", lambda s, n: _make_heartbeat()),
    ):
        asyncio.run(
            run_connector_loop(
                worker_name="test-worker",
                preflight=preflight,
                run_cycle=run_cycle,
            )
        )

    assert "preflight" in calls
    assert "cycle" not in calls  # should never have been called


def test_loop_runs_at_least_one_cycle_then_shuts_down(tmp_path):
    """Worker should execute run_cycle and then stop on shutdown signal."""
    cycles_run = []
    hb = _make_heartbeat()

    def preflight(settings):
        return PreflightResult(ok=True, interval_seconds=600)

    def run_cycle(settings, since, until, heartbeat):
        cycles_run.append(1)
        # Trigger shutdown after the first cycle
        _shutdown.set()
        return CycleSummary(
            log_message="synced 5 items",
            heartbeat_details={"items": 5},
        )

    with (
        patch("mimir.worker._base.get_settings", _fake_settings),
        patch("mimir.worker._base.WorkerHeartbeat", lambda s, n: hb),
    ):
        _shutdown.clear()
        asyncio.run(
            run_connector_loop(
                worker_name="test-worker",
                preflight=preflight,
                run_cycle=run_cycle,
            )
        )

    assert len(cycles_run) == 1
    # Heartbeat should have been called with "stopped" at the end
    final_call = hb.update.call_args_list[-1]
    assert final_call[0][0] == "stopped"


def test_loop_handles_cycle_exception_gracefully(tmp_path):
    """An exception in run_cycle should not crash the loop."""
    call_count = []
    hb = _make_heartbeat()

    def preflight(settings):
        return PreflightResult(ok=True, interval_seconds=0.01)

    def run_cycle(settings, since, until, heartbeat):
        call_count.append(1)
        if len(call_count) == 1:
            raise RuntimeError("sync failed")
        # Stop after a successful second cycle
        _shutdown.set()
        return CycleSummary(log_message="recovered")

    with (
        patch("mimir.worker._base.get_settings", _fake_settings),
        patch("mimir.worker._base.WorkerHeartbeat", lambda s, n: hb),
    ):
        _shutdown.clear()
        asyncio.run(
            run_connector_loop(
                worker_name="test-worker",
                preflight=preflight,
                run_cycle=run_cycle,
            )
        )

    assert len(call_count) == 2  # ran twice, survived the error
    # The heartbeat should have recorded an "error" state
    error_calls = [
        c for c in hb.update.call_args_list if c[0][0] == "error"
    ]
    assert len(error_calls) >= 1


def test_loop_uses_lookback(tmp_path):
    """lookback_minutes_fn should influence the 'since' parameter."""
    captured_since = []
    hb = _make_heartbeat()

    def preflight(settings):
        return PreflightResult(ok=True, interval_seconds=600)

    def run_cycle(settings, since, until, heartbeat):
        captured_since.append(since)
        _shutdown.set()
        return CycleSummary()

    with (
        patch("mimir.worker._base.get_settings", _fake_settings),
        patch("mimir.worker._base.WorkerHeartbeat", lambda s, n: hb),
    ):
        _shutdown.clear()
        asyncio.run(
            run_connector_loop(
                worker_name="test-worker",
                preflight=preflight,
                run_cycle=run_cycle,
                lookback_minutes_fn=lambda s: 60,
            )
        )

    assert len(captured_since) == 1
    since = captured_since[0]
    # 'since' should be roughly 60 minutes before 'now'
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    diff = (now - since).total_seconds()
    assert 3500 < diff < 3700  # ~60 min ± tolerance
