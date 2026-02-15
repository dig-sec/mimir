"""OpenCTI connector worker.

Standalone worker process that periodically syncs entities, relations,
and reports from OpenCTI into the Mimir graph.

The worker:
* Runs on its own schedule (``OPENCTI_WORKER_INTERVAL_MINUTES``, default 30)
* Pulls a default CTI entity set from OpenCTI GraphQL API
* Optionally queues report text for LLM extraction
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from ..config import Settings
from ..opencti.client import OpenCTIClient
from ..opencti.sync import OPENCTI_DEFAULT_ENTITY_TYPES, pull_from_opencti
from ..storage.factory import create_graph_store, create_run_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)

DEFAULT_ENTITY_TYPES = list(OPENCTI_DEFAULT_ENTITY_TYPES)


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.opencti_url or not settings.opencti_token:
        return PreflightResult(ok=False, reason="OPENCTI_URL / OPENCTI_TOKEN not set")
    interval = settings.opencti_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"OPENCTI_WORKER_INTERVAL_MINUTES={interval}"
        )
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={"opencti_url": settings.opencti_url},
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)
    client = OpenCTIClient(settings.opencti_url, settings.opencti_token)
    try:

        def _progress(msg: str) -> None:
            heartbeat.update("running", {"progress": msg[:200]})

        result = pull_from_opencti(
            client,
            graph_store,
            entity_types=DEFAULT_ENTITY_TYPES,
            max_per_type=0,
            run_store=run_store,
            settings=settings,
            progress_cb=_progress,
        )
        return CycleSummary(
            log_message=(
                f"{result.entities_pulled} entities, "
                f"{result.relations_pulled} relations"
            ),
            heartbeat_details={
                "entities_pulled": result.entities_pulled,
                "relations_pulled": result.relations_pulled,
            },
        )
    finally:
        try:
            client.close()
        except Exception:
            pass


async def opencti_worker_loop() -> None:
    """Periodically sync entities and relations from OpenCTI."""
    await run_connector_loop(
        worker_name="opencti-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
    )


def main() -> None:
    asyncio.run(opencti_worker_loop())


if __name__ == "__main__":
    main()
