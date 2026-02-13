"""Feedly connector worker.

Standalone worker process that periodically syncs Feedly articles from
Elasticsearch into the Wellspring graph.  Replaces the inline Feedly
sync that previously ran inside the API scheduler.

The worker:
* Runs on its own schedule (``FEEDLY_WORKER_INTERVAL_MINUTES``, default 30)
* Uses a lookback window (``SYNC_LOOKBACK_MINUTES``) to catch missed articles
* Queues article text for LLM extraction when ``FEEDLY_QUEUE_FOR_LLM=1``
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..connectors import sync_feedly_index
from ..storage.factory import create_graph_store, create_run_store

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("Feedly worker: shutdown signal received")
    _shutdown.set()


async def feedly_worker_loop() -> None:
    """Periodically sync Feedly articles from Elasticsearch."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    if not settings.elastic_connector_enabled:
        logger.info(
            "Feedly worker: disabled (ELASTIC_CONNECTOR_ENABLED=0). Exiting."
        )
        return

    if not settings.elastic_connector_hosts_list:
        logger.warning("Feedly worker: no connector hosts configured. Exiting.")
        return

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    interval = settings.feedly_worker_interval_minutes * 60
    queue_for_llm = settings.feedly_queue_for_llm

    logger.info(
        "Feedly worker started — interval=%dm, lookback=%dm, queue_for_llm=%s",
        settings.feedly_worker_interval_minutes,
        settings.sync_lookback_minutes,
        queue_for_llm,
    )

    while not _shutdown.is_set():
        cycle_end = datetime.now(timezone.utc)
        since = cycle_end - timedelta(minutes=settings.sync_lookback_minutes)
        indices = settings.elastic_connector_indices_list or ["feedly_news"]

        for index_name in indices:
            if _shutdown.is_set():
                break
            try:
                result = await asyncio.to_thread(
                    sync_feedly_index,
                    settings=settings,
                    graph_store=graph_store,
                    run_store=run_store if queue_for_llm else None,
                    index_name=index_name,
                    since=since,
                    until=cycle_end,
                    max_articles=0,
                    queue_for_llm=queue_for_llm,
                )
                logger.info(
                    "Feedly sync %s: %d articles, %d entities, %d relations",
                    index_name,
                    result.articles_processed,
                    result.entities_created,
                    result.relations_created,
                )
            except Exception:
                logger.exception("Feedly sync failed for index %s", index_name)

        # Wait for next cycle or shutdown
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("Feedly worker stopped")


def main() -> None:
    asyncio.run(feedly_worker_loop())


if __name__ == "__main__":
    main()
