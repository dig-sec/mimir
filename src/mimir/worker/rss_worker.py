"""RSS threat feed worker.

Periodically pulls public RSS/Atom feeds and queues unseen entries for LLM
extraction. Designed for no-license/no-auth public feed ingestion.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Optional

from ..config import get_settings
from ..connectors.rss import pull_from_rss_feeds
from ..storage.factory import create_run_store
from .heartbeat import WorkerHeartbeat

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("RSS worker: shutdown signal received")
    _shutdown.set()


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Install shutdown handlers with a portable fallback."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except (NotImplementedError, RuntimeError, ValueError):
            try:
                signal.signal(sig, lambda *_: _handle_signal())
            except (ValueError, OSError):
                logger.warning(
                    "RSS worker: unable to install signal handler for %s",
                    sig.name,
                )


async def rss_worker_loop() -> None:
    settings = get_settings()
    heartbeat = WorkerHeartbeat(settings, "rss-worker")
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    if not settings.rss_worker_enabled:
        logger.info("RSS worker: disabled (RSS_WORKER_ENABLED=0). Exiting.")
        heartbeat.update("disabled", {"reason": "RSS_WORKER_ENABLED=0"})
        return

    feeds = settings.rss_worker_feeds_list
    if not feeds:
        logger.info("RSS worker: disabled (no RSS_WORKER_FEEDS configured). Exiting.")
        heartbeat.update("disabled", {"reason": "no RSS_WORKER_FEEDS configured"})
        return

    interval_minutes = settings.rss_worker_interval_minutes
    interval = interval_minutes * 60
    if interval <= 0:
        logger.info(
            "RSS worker: disabled (RSS_WORKER_INTERVAL_MINUTES=%d). Exiting.",
            interval_minutes,
        )
        heartbeat.update(
            "disabled",
            {
                "reason": "RSS_WORKER_INTERVAL_MINUTES<=0",
                "interval_minutes": interval_minutes,
            },
        )
        return

    run_store = create_run_store(settings)

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop)

    logger.info(
        "RSS worker started — interval=%dm, feeds=%d, lookback_hours=%d",
        interval_minutes,
        len(feeds),
        settings.rss_worker_lookback_hours,
    )
    heartbeat.update(
        "running",
        {
            "interval_minutes": interval_minutes,
            "feeds_count": len(feeds),
            "lookback_hours": settings.rss_worker_lookback_hours,
        },
    )

    while not _shutdown.is_set():
        cycle_started_at = datetime.now(timezone.utc).isoformat()
        cycle_error: Optional[str] = None
        heartbeat.update(
            "running",
            {
                "cycle_started_at": cycle_started_at,
                "feeds_count": len(feeds),
            },
        )

        try:
            result = await asyncio.to_thread(
                pull_from_rss_feeds,
                run_store,
                settings,
                feeds,
                lookback_hours=settings.rss_worker_lookback_hours,
                max_items_per_feed=settings.rss_worker_max_items_per_feed,
                min_text_chars=settings.rss_worker_min_text_chars,
                timeout_seconds=settings.rss_worker_timeout_seconds,
            )
            logger.info(
                "RSS sync done: %d feeds, %d seen, %d queued, %d existing, %d old",
                result.feeds_scanned,
                result.items_seen,
                result.runs_queued,
                result.skipped_existing,
                result.skipped_old,
            )
            heartbeat.update(
                "running",
                {
                    "cycle_started_at": cycle_started_at,
                    "feeds_scanned": result.feeds_scanned,
                    "items_seen": result.items_seen,
                    "runs_queued": result.runs_queued,
                    "skipped_existing": result.skipped_existing,
                    "skipped_old": result.skipped_old,
                    "errors": len(result.errors),
                },
            )
            for err in result.errors[:5]:
                logger.warning("RSS sync error: %s", err)
        except Exception as exc:
            logger.exception("RSS sync failed")
            cycle_error = str(exc) or type(exc).__name__
            heartbeat.update(
                "error",
                {
                    "cycle_started_at": cycle_started_at,
                    "error": cycle_error[:200],
                },
            )

        try:
            if cycle_error:
                heartbeat.update(
                    "error",
                    {
                        "cycle_started_at": cycle_started_at,
                        "error": cycle_error[:200],
                        "next_run_in_seconds": interval,
                    },
                )
            else:
                heartbeat.update("sleeping", {"next_run_in_seconds": interval})
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("RSS worker stopped")
    heartbeat.update("stopped")


def main() -> None:
    asyncio.run(rss_worker_loop())


if __name__ == "__main__":
    main()
