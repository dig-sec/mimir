"""Feedly connector worker.

Standalone worker process that periodically syncs Feedly articles from
Elasticsearch into the Mimir graph.  Replaces the inline Feedly
sync that previously ran inside the API scheduler.

The worker:
* Runs on its own schedule (``FEEDLY_WORKER_INTERVAL_MINUTES``, default 30)
* Uses a lookback window (``ELASTIC_CONNECTOR_LOOKBACK_MINUTES``) to catch missed
  articles
* Queues article text for LLM extraction when ``FEEDLY_QUEUE_FOR_LLM=1``
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from ..config import Settings
from ..connectors import sync_feedly_index
from ..storage.factory import create_graph_store, create_run_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.elastic_connector_enabled:
        return PreflightResult(ok=False, reason="ELASTIC_CONNECTOR_ENABLED=0")
    if not settings.elastic_connector_hosts_list:
        return PreflightResult(ok=False, reason="no connector hosts configured")
    interval = settings.feedly_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"FEEDLY_WORKER_INTERVAL_MINUTES={interval}"
        )
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={
            "queue_for_llm": settings.feedly_queue_for_llm,
            "indices": settings.elastic_connector_indices_list or ["feedly_news"],
        },
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    queue_for_llm = settings.feedly_queue_for_llm
    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings) if queue_for_llm else None
    indices = settings.elastic_connector_indices_list or ["feedly_news"]
    errors: list[str] = []

    for index_name in indices:
        try:
            result = sync_feedly_index(
                settings=settings,
                graph_store=graph_store,
                run_store=run_store,
                index_name=index_name,
                since=since,
                until=until,
                max_articles=0,
                queue_for_llm=queue_for_llm,
            )
            heartbeat.update(
                "running",
                {
                    "last_index": index_name,
                    "articles_processed": result.articles_processed,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                },
            )
        except Exception as exc:
            logger.exception("Feedly sync failed for index %s", index_name)
            errors.append(f"{index_name}: {exc}")
            heartbeat.update("error", {"last_index": index_name})

    return CycleSummary(
        log_message=f"synced {len(indices)} indices",
        heartbeat_details={"indices": indices},
        errors=errors,
    )


async def feedly_worker_loop() -> None:
    """Periodically sync Feedly articles from Elasticsearch."""
    await run_connector_loop(
        worker_name="feedly-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
        lookback_minutes_fn=lambda s: s.elastic_connector_lookback_minutes,
    )


def main() -> None:
    asyncio.run(feedly_worker_loop())


if __name__ == "__main__":
    main()
