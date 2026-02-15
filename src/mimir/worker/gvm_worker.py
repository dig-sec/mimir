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
import signal
from datetime import datetime, timedelta, timezone

from ..config import get_settings
from ..connectors.gvm import sync_gvm
from ..storage.factory import create_graph_store
from .heartbeat import WorkerHeartbeat

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("GVM worker: shutdown signal received")
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
                    "GVM worker: unable to install signal handler for %s",
                    sig.name,
                )


async def gvm_worker_loop() -> None:
    """Periodically sync GVM scan results into the knowledge graph."""
    settings = get_settings()
    heartbeat = WorkerHeartbeat(settings, "gvm-worker")
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    if not settings.gvm_worker_enabled:
        logger.info("GVM worker: disabled (GVM_WORKER_ENABLED=0). Exiting.")
        heartbeat.update("disabled", {"reason": "GVM_WORKER_ENABLED=0"})
        return

    interval_minutes = settings.gvm_worker_interval_minutes
    interval = interval_minutes * 60
    if interval <= 0:
        logger.info(
            "GVM worker: disabled (GVM_WORKER_INTERVAL_MINUTES=%d). Exiting.",
            interval_minutes,
        )
        heartbeat.update(
            "disabled",
            {
                "reason": "GVM_WORKER_INTERVAL_MINUTES<=0",
                "interval_minutes": interval_minutes,
            },
        )
        return

    lookback_minutes = max(settings.gvm_worker_lookback_minutes, 0)
    graph_store = create_graph_store(settings)

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop)

    conn_target = (
        settings.gvm_socket_path
        if settings.gvm_connection_type == "unix"
        else f"{settings.gvm_host}:{settings.gvm_port}"
    )

    logger.info(
        "GVM worker started — interval=%dm, lookback=%dm, connection=%s (%s)",
        interval_minutes,
        lookback_minutes,
        settings.gvm_connection_type,
        conn_target,
    )
    heartbeat.update(
        "running",
        {
            "interval_minutes": interval_minutes,
            "lookback_minutes": lookback_minutes,
            "connection_type": settings.gvm_connection_type,
            "connection_target": conn_target,
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
                sync_gvm,
                settings=settings,
                graph_store=graph_store,
                since=since,
                until=cycle_end,
            )
            logger.info(
                "GVM sync complete: %d results, %d hosts, %d entities, %d relations",
                result.results_processed,
                result.hosts_seen,
                result.entities_created,
                result.relations_created,
            )
            heartbeat.update(
                "running",
                {
                    "cycle_started_at": cycle_end.isoformat(),
                    "results_processed": result.results_processed,
                    "hosts_seen": result.hosts_seen,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                    "skipped_low_qod": result.skipped_low_qod,
                    "errors": len(result.errors),
                },
            )
            if result.errors:
                for err in result.errors[:5]:
                    logger.warning("GVM sync error: %s", err)
        except Exception:
            logger.exception("GVM sync cycle failed")
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

    logger.info("GVM worker stopped")
    heartbeat.update("stopped")


def main() -> None:
    asyncio.run(gvm_worker_loop())


if __name__ == "__main__":
    main()
