"""Elasticsearch source connector worker.

Standalone worker process that periodically pulls documents from
configured Elasticsearch source indices and queues them for LLM
extraction via the RunStore.

The worker:
* Runs on its own schedule (``ELASTIC_WORKER_INTERVAL_MINUTES``, default 30)
* Uses ``pull_from_elasticsearch()`` from ``elastic_source.sync``
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal

from ..config import get_settings
from ..elastic_source.client import ElasticsearchSourceClient
from ..elastic_source.sync import pull_from_elasticsearch
from ..storage.factory import create_run_store

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("Elasticsearch worker: shutdown signal received")
    _shutdown.set()


def _create_source_client(settings) -> ElasticsearchSourceClient:
    """Build an ElasticsearchSourceClient from connector settings."""
    return ElasticsearchSourceClient(
        hosts=settings.elastic_connector_hosts_list,
        username=settings.elastic_connector_user,
        password=settings.elastic_connector_password,
        verify_certs=settings.elastic_connector_verify_certs,
        timeout=settings.elastic_connector_timeout_seconds,
    )


async def elastic_worker_loop() -> None:
    """Periodically pull documents from Elasticsearch source indices."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    if not settings.elastic_connector_enabled:
        logger.info(
            "Elasticsearch worker: disabled (ELASTIC_CONNECTOR_ENABLED=0). Exiting."
        )
        return

    if not settings.elastic_connector_hosts_list:
        logger.warning(
            "Elasticsearch worker: no connector hosts configured. Exiting."
        )
        return

    run_store = create_run_store(settings)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    interval = settings.elastic_worker_interval_minutes * 60

    # Exclude Feedly indices so we don't double-queue articles that the
    # Feedly worker already handles with its own structured extraction.
    all_indices = settings.elastic_connector_indices_list or []
    exclude = set(settings.elastic_worker_exclude_indices_list)
    indices = [i for i in all_indices if i not in exclude]

    if not indices:
        logger.info(
            "Elasticsearch worker: no indices left after excluding %s. Exiting.",
            exclude or "(none)",
        )
        return

    logger.info(
        "Elasticsearch source worker started — interval=%dm, indices=%s",
        settings.elastic_worker_interval_minutes,
        indices,
    )

    while not _shutdown.is_set():
        client = None
        try:
            client = _create_source_client(settings)
            result = await asyncio.to_thread(
                pull_from_elasticsearch,
                client,
                run_store,
                settings,
                indices,
                max_per_index=500,
                lookback_minutes=settings.elastic_connector_lookback_minutes,
                min_text_chars=settings.elastic_connector_min_text_chars,
            )
            logger.info(
                "Elasticsearch sync done: %d indexes, %d docs, %d queued, %d skipped",
                result.indexes_scanned,
                result.documents_seen,
                result.runs_queued,
                result.skipped_existing,
            )
            if result.errors:
                for err in result.errors[:5]:
                    logger.warning("ES sync error: %s", err)
        except Exception:
            logger.exception("Elasticsearch sync failed")
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

        # Wait for next cycle or shutdown
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("Elasticsearch source worker stopped")


def main() -> None:
    asyncio.run(elastic_worker_loop())


if __name__ == "__main__":
    main()
