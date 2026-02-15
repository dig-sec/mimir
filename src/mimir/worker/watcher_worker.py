"""Watcher (Thales CERT) connector worker.

Standalone worker process that periodically syncs threat-intelligence data
from a Watcher instance (trending keywords, data leaks, typosquatting
domains, monitored sites) into the Mimir knowledge graph.

The worker:
* Runs on its own schedule (``WATCHER_WORKER_INTERVAL_MINUTES``, default 30)
* Uses a lookback window (``WATCHER_WORKER_LOOKBACK_MINUTES``) to catch
  missed records
* Directly imports structured entities via the Watcher REST API
  without LLM processing
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..connectors.watcher import sync_watcher
from ..storage.factory import create_graph_store
from .heartbeat import WorkerHeartbeat

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("Watcher worker: shutdown signal received")
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
                    "Watcher worker: unable to install signal handler for %s",
                    sig.name,
                )


async def watcher_worker_loop() -> None:
    """Periodically sync Watcher threat data into the knowledge graph."""
    settings = get_settings()
    heartbeat = WorkerHeartbeat(settings, "watcher-worker")
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    if not settings.watcher_worker_enabled:
        logger.info("Watcher worker: disabled (WATCHER_WORKER_ENABLED=0). Exiting.")
        heartbeat.update("disabled", {"reason": "WATCHER_WORKER_ENABLED=0"})
        return

    if not settings.watcher_base_url:
        logger.warning("Watcher worker: no WATCHER_BASE_URL configured. Exiting.")
        heartbeat.update("disabled", {"reason": "no WATCHER_BASE_URL configured"})
        return

    interval_minutes = settings.watcher_worker_interval_minutes
    interval = interval_minutes * 60
    if interval <= 0:
        logger.info(
            "Watcher worker: disabled (WATCHER_WORKER_INTERVAL_MINUTES=%d). Exiting.",
            interval_minutes,
        )
        heartbeat.update(
            "disabled",
            {
                "reason": "WATCHER_WORKER_INTERVAL_MINUTES<=0",
                "interval_minutes": interval_minutes,
            },
        )
        return

    lookback_minutes = max(settings.watcher_worker_lookback_minutes, 0)
    graph_store = create_graph_store(settings)

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop)

    modules = []
    if settings.watcher_pull_trendy_words:
        modules.append("trendy_words")
    if settings.watcher_pull_data_leaks:
        modules.append("data_leaks")
    if settings.watcher_pull_dns_twisted:
        modules.append("dns_twisted")
    if settings.watcher_pull_site_monitoring:
        modules.append("site_monitoring")

    logger.info(
        "Watcher worker started — interval=%dm, lookback=%dm, "
        "base_url=%s, modules=%s",
        interval_minutes,
        lookback_minutes,
        settings.watcher_base_url,
        ",".join(modules),
    )
    heartbeat.update(
        "running",
        {
            "interval_minutes": interval_minutes,
            "lookback_minutes": lookback_minutes,
            "base_url": settings.watcher_base_url,
            "modules": modules,
        },
    )

    while not _shutdown.is_set():
        cycle_end = datetime.now(timezone.utc)
        since = cycle_end - timedelta(minutes=lookback_minutes)

        heartbeat.update(
            "running",
            {
                "cycle_started_at": cycle_end.isoformat(),
                "since": since.isoformat(),
            },
        )

        try:
            result = await asyncio.to_thread(
                sync_watcher,
                settings=settings,
                graph_store=graph_store,
                since=since,
                until=cycle_end,
            )
            logger.info(
                "Watcher sync complete: %d trendy, %d leaks, %d twisted, "
                "%d sites, %d entities, %d relations",
                result.trendy_words_processed,
                result.data_leaks_processed,
                result.dns_twisted_processed,
                result.sites_processed,
                result.entities_created,
                result.relations_created,
            )
            heartbeat.update(
                "running",
                {
                    "cycle_started_at": cycle_end.isoformat(),
                    "trendy_words": result.trendy_words_processed,
                    "data_leaks": result.data_leaks_processed,
                    "dns_twisted": result.dns_twisted_processed,
                    "sites": result.sites_processed,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                    "errors": len(result.errors),
                },
            )
            if result.errors:
                for err in result.errors[:5]:
                    logger.warning("Watcher sync error: %s", err)
        except Exception:
            logger.exception("Watcher sync cycle failed")
            heartbeat.update(
                "error",
                {"cycle_started_at": cycle_end.isoformat()},
            )

        # Wait for next cycle or shutdown
        try:
            heartbeat.update(
                "sleeping",
                {"next_run_in_seconds": interval},
            )
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("Watcher worker stopped")
    heartbeat.update("stopped")


def main() -> None:
    asyncio.run(watcher_worker_loop())


if __name__ == "__main__":
    main()
