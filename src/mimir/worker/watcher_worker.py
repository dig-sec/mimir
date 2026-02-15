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
from datetime import datetime

from ..config import Settings
from ..connectors.watcher import sync_watcher
from ..storage.factory import create_graph_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.watcher_worker_enabled:
        return PreflightResult(ok=False, reason="WATCHER_WORKER_ENABLED=0")
    if not settings.watcher_base_url:
        return PreflightResult(ok=False, reason="no WATCHER_BASE_URL configured")
    interval = settings.watcher_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"WATCHER_WORKER_INTERVAL_MINUTES={interval}"
        )
    modules = []
    if settings.watcher_pull_trendy_words:
        modules.append("trendy_words")
    if settings.watcher_pull_data_leaks:
        modules.append("data_leaks")
    if settings.watcher_pull_dns_twisted:
        modules.append("dns_twisted")
    if settings.watcher_pull_site_monitoring:
        modules.append("site_monitoring")
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={
            "base_url": settings.watcher_base_url,
            "modules": modules,
        },
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    graph_store = create_graph_store(settings)
    result = sync_watcher(
        settings=settings,
        graph_store=graph_store,
        since=since,
        until=until,
    )
    return CycleSummary(
        log_message=(
            f"{result.trendy_words_processed} trendy, "
            f"{result.data_leaks_processed} leaks, "
            f"{result.dns_twisted_processed} twisted, "
            f"{result.sites_processed} sites, "
            f"{result.entities_created} entities, "
            f"{result.relations_created} relations"
        ),
        heartbeat_details={
            "trendy_words": result.trendy_words_processed,
            "data_leaks": result.data_leaks_processed,
            "dns_twisted": result.dns_twisted_processed,
            "sites": result.sites_processed,
            "entities_created": result.entities_created,
            "relations_created": result.relations_created,
        },
        errors=result.errors,
    )


async def watcher_worker_loop() -> None:
    """Periodically sync Watcher threat data into the knowledge graph."""
    await run_connector_loop(
        worker_name="watcher-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
        lookback_minutes_fn=lambda s: s.watcher_worker_lookback_minutes,
    )


def main() -> None:
    asyncio.run(watcher_worker_loop())


if __name__ == "__main__":
    main()
