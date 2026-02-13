"""Template skeleton for future connector workers.

Copy this file to ``<connector>_worker.py`` and replace the TODO blocks.

Design constraints:
- one process per connector type
- periodic pull with lookback window
- graceful shutdown (SIGINT / SIGTERM)
- blocking connector client work runs in ``asyncio.to_thread(...)``
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from ..config import get_settings
from ..storage.factory import create_graph_store, create_run_store

logger = logging.getLogger(__name__)
_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("Connector worker: shutdown signal received")
    _shutdown.set()


def _run_sync_once(
    *,
    settings: Any,
    graph_store: Any,
    run_store: Any,
    since: datetime,
    until: datetime,
) -> Dict[str, Any]:
    """Run one connector sync cycle.

    TODO:
    - call your connector sync function here
    - return a compact summary dict for logs/metrics
    """
    raise NotImplementedError("Replace _run_sync_once with connector sync logic")


async def connector_worker_loop() -> None:
    """Generic connector worker loop."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    # TODO: replace with connector-specific preflight checks.
    # Example:
    # if not settings.my_connector_enabled:
    #     logger.info("My connector worker disabled. Exiting.")
    #     return

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    interval_seconds = max(settings.sync_interval_minutes, 1) * 60
    lookback_minutes = max(settings.sync_lookback_minutes, 0)

    logger.info(
        "Connector worker started: interval=%dm lookback=%dm",
        interval_seconds // 60,
        lookback_minutes,
    )

    while not _shutdown.is_set():
        cycle_end = datetime.now(timezone.utc)
        cycle_start = cycle_end - timedelta(minutes=lookback_minutes)

        try:
            summary = await asyncio.to_thread(
                _run_sync_once,
                settings=settings,
                graph_store=graph_store,
                run_store=run_store,
                since=cycle_start,
                until=cycle_end,
            )
            logger.info("Connector sync complete: %s", summary)
        except Exception:
            logger.exception("Connector sync failed")

        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=interval_seconds)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("Connector worker stopped")


def main() -> None:
    asyncio.run(connector_worker_loop())


if __name__ == "__main__":
    main()
