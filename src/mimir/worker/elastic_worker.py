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
from datetime import datetime

from ..config import Settings
from ..elastic_source.client import ElasticsearchSourceClient
from ..elastic_source.sync import pull_from_elasticsearch
from ..storage.factory import create_run_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)


def _create_source_client(settings: Settings) -> ElasticsearchSourceClient:
    """Build an ElasticsearchSourceClient from connector settings."""
    return ElasticsearchSourceClient(
        hosts=settings.elastic_connector_hosts_list,
        username=settings.elastic_connector_user,
        password=settings.elastic_connector_password,
        verify_certs=settings.elastic_connector_verify_certs,
        timeout=settings.elastic_connector_timeout_seconds,
    )


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.elastic_connector_enabled:
        return PreflightResult(ok=False, reason="ELASTIC_CONNECTOR_ENABLED=0")
    if not settings.elastic_connector_hosts_list:
        return PreflightResult(ok=False, reason="no connector hosts configured")
    interval = settings.elastic_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"ELASTIC_WORKER_INTERVAL_MINUTES={interval}"
        )
    # Exclude Feedly indices to avoid double-processing.
    all_indices = settings.elastic_connector_indices_list or []
    exclude = set(settings.elastic_worker_exclude_indices_list)
    indices = [i for i in all_indices if i not in exclude]
    if not indices:
        return PreflightResult(ok=False, reason="no indices left after exclusions")
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={"indices": indices},
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    all_indices = settings.elastic_connector_indices_list or []
    exclude = set(settings.elastic_worker_exclude_indices_list)
    indices = [i for i in all_indices if i not in exclude]

    run_store = create_run_store(settings)
    client = _create_source_client(settings)
    try:
        result = pull_from_elasticsearch(
            client,
            run_store,
            settings,
            indices,
            max_per_index=500,
            lookback_minutes=settings.elastic_connector_lookback_minutes,
            min_text_chars=settings.elastic_connector_min_text_chars,
        )
        return CycleSummary(
            log_message=(
                f"{result.indexes_scanned} indexes, {result.documents_seen} docs, "
                f"{result.runs_queued} queued, {result.skipped_existing} skipped"
            ),
            heartbeat_details={
                "indexes_scanned": result.indexes_scanned,
                "documents_seen": result.documents_seen,
                "runs_queued": result.runs_queued,
                "skipped_existing": result.skipped_existing,
            },
            errors=result.errors if hasattr(result, "errors") else [],
        )
    finally:
        try:
            client.close()
        except Exception:
            pass


async def elastic_worker_loop() -> None:
    """Periodically pull documents from Elasticsearch source indices."""
    await run_connector_loop(
        worker_name="elastic-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
    )


def main() -> None:
    asyncio.run(elastic_worker_loop())


if __name__ == "__main__":
    main()
