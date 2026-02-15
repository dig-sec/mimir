"""GVM (Greenbone Vulnerability Management) connector worker.

Standalone worker process that periodically syncs vulnerability scan results
from GVM/OpenVAS via the GMP protocol into the Mimir knowledge graph.

The worker:
* Runs on its own schedule (``GVM_WORKER_INTERVAL_MINUTES``, default 30)
* Uses a lookback window (``GVM_WORKER_LOOKBACK_MINUTES``) to catch
  missed results
* Directly extracts structured entities (hosts, ports, services,
  vulnerabilities, CVEs, technologies) without LLM processing
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from ..config import Settings
from ..connectors.gvm import sync_gvm
from ..storage.factory import create_graph_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.gvm_worker_enabled:
        return PreflightResult(ok=False, reason="GVM_WORKER_ENABLED=0")
    interval = settings.gvm_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"GVM_WORKER_INTERVAL_MINUTES={interval}"
        )
    conn_target = (
        settings.gvm_socket_path
        if settings.gvm_connection_type == "unix"
        else f"{settings.gvm_host}:{settings.gvm_port}"
    )
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={
            "connection_type": settings.gvm_connection_type,
            "connection_target": conn_target,
        },
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    graph_store = create_graph_store(settings)
    result = sync_gvm(
        settings=settings,
        graph_store=graph_store,
        since=since,
        until=until,
    )
    return CycleSummary(
        log_message=(
            f"{result.results_processed} results, {result.hosts_seen} hosts, "
            f"{result.entities_created} entities, {result.relations_created} relations"
        ),
        heartbeat_details={
            "results_processed": result.results_processed,
            "hosts_seen": result.hosts_seen,
            "entities_created": result.entities_created,
            "relations_created": result.relations_created,
            "skipped_low_qod": result.skipped_low_qod,
        },
        errors=result.errors,
    )


async def gvm_worker_loop() -> None:
    """Periodically sync GVM scan results into the knowledge graph."""
    await run_connector_loop(
        worker_name="gvm-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
        lookback_minutes_fn=lambda s: s.gvm_worker_lookback_minutes,
    )


def main() -> None:
    asyncio.run(gvm_worker_loop())


if __name__ == "__main__":
    main()
