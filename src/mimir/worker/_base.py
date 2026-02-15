"""Connector-worker base infrastructure.

Provides :func:`run_connector_loop` which encapsulates the full lifecycle
shared by every periodic connector worker:

* Signal-based graceful shutdown (``SIGINT`` / ``SIGTERM``)
* Heartbeat state machine
* Async-to-thread sync dispatch
* Configurable sleep/poll interval

Individual workers only need to supply a small ``ConnectorWorkerSpec``
describing preflight checks, the sync callable, and result logging.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Sequence

from ..config import Settings, get_settings
from .heartbeat import WorkerHeartbeat

logger = logging.getLogger(__name__)

# ── Shutdown primitives ─────────────────────────────────────────────

_shutdown = asyncio.Event()


def _handle_signal(worker_name: str) -> None:
    logger.info("%s: shutdown signal received", worker_name)
    _shutdown.set()


def install_signal_handlers(
    loop: asyncio.AbstractEventLoop,
    worker_name: str,
) -> None:
    """Install SIGINT/SIGTERM handlers with portable fallback."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, worker_name)
        except (NotImplementedError, RuntimeError, ValueError):
            try:
                signal.signal(sig, lambda *_: _handle_signal(worker_name))
            except (ValueError, OSError):
                logger.warning(
                    "%s: unable to install signal handler for %s",
                    worker_name,
                    sig.name,
                )


# ── Preflight result ────────────────────────────────────────────────


@dataclass
class PreflightResult:
    """Returned by a worker's preflight check.

    *ok=False* means the worker should exit immediately.
    """

    ok: bool = True
    reason: str = ""
    interval_seconds: float = 0.0
    extra_heartbeat: Dict[str, Any] = field(default_factory=dict)


# ── Sync-cycle callback protocol ───────────────────────────────────


@dataclass
class CycleSummary:
    """Compact summary a sync callback returns after each cycle."""

    log_message: str = ""
    heartbeat_details: Dict[str, Any] = field(default_factory=dict)
    errors: Sequence[str] = ()


SyncCallable = Callable[
    ...,
    CycleSummary,
]


# ── Main loop ───────────────────────────────────────────────────────


async def run_connector_loop(
    *,
    worker_name: str,
    preflight: Callable[[Settings], PreflightResult],
    run_cycle: Callable[
        [Settings, datetime, datetime, WorkerHeartbeat],
        CycleSummary,
    ],
    lookback_minutes_fn: Optional[Callable[[Settings], int]] = None,
) -> None:
    """Generic connector-worker event loop.

    Parameters
    ----------
    worker_name:
        Human-readable ID used for logging and heartbeat files
        (e.g. ``"feedly-worker"``).
    preflight:
        Called once at startup.  Must return a :class:`PreflightResult`
        indicating whether to proceed and at what interval.
    run_cycle:
        Called each iteration with ``(settings, since, until, heartbeat)``.
        Runs inside ``asyncio.to_thread`` so it may perform blocking I/O.
    lookback_minutes_fn:
        Optional callable ``settings → int`` that returns the lookback
        window in minutes.  Defaults to 0 (``since == until``).
    """
    settings = get_settings()
    heartbeat = WorkerHeartbeat(settings, worker_name)
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    # ── Preflight ───────────────────────────────────────────────
    pf = preflight(settings)
    if not pf.ok:
        logger.info("%s: disabled (%s). Exiting.", worker_name, pf.reason)
        heartbeat.update("disabled", {"reason": pf.reason})
        return

    interval = pf.interval_seconds
    lookback = lookback_minutes_fn(settings) if lookback_minutes_fn else 0
    lookback = max(lookback, 0)

    loop = asyncio.get_running_loop()
    install_signal_handlers(loop, worker_name)

    logger.info(
        "%s started — interval=%ds, lookback=%dm",
        worker_name,
        int(interval),
        lookback,
    )
    heartbeat.update(
        "running",
        {
            "interval_seconds": int(interval),
            "lookback_minutes": lookback,
            **pf.extra_heartbeat,
        },
    )

    # ── Main loop ───────────────────────────────────────────────
    while not _shutdown.is_set():
        cycle_end = datetime.now(timezone.utc)
        since = cycle_end - timedelta(minutes=lookback)

        heartbeat.update(
            "running",
            {
                "cycle_started_at": cycle_end.isoformat(),
                "since": since.isoformat(),
            },
        )

        try:
            summary = await asyncio.to_thread(
                run_cycle,
                settings,
                since,
                cycle_end,
                heartbeat,
            )
            if summary.log_message:
                logger.info("%s: %s", worker_name, summary.log_message)
            heartbeat.update(
                "running",
                {
                    "cycle_started_at": cycle_end.isoformat(),
                    **summary.heartbeat_details,
                },
            )
            if summary.errors:
                for err in list(summary.errors)[:5]:
                    logger.warning("%s sync error: %s", worker_name, err)
        except Exception:
            logger.exception("%s sync cycle failed", worker_name)
            heartbeat.update(
                "error",
                {
                    "cycle_started_at": cycle_end.isoformat(),
                },
            )

        # ── Sleep / shutdown ────────────────────────────────────
        try:
            heartbeat.update("sleeping", {"next_run_in_seconds": int(interval)})
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("%s stopped", worker_name)
    heartbeat.update("stopped")
