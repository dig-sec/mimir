"""OpenCTI connector worker.

Standalone worker process that periodically syncs entities, relations,
and reports from OpenCTI into the Wellspring graph.  Replaces the
inline OpenCTI sync that previously ran inside the API scheduler.

The worker:
* Runs on its own schedule (``OPENCTI_WORKER_INTERVAL_MINUTES``, default 30)
* Pulls a default CTI entity set from OpenCTI GraphQL API
* Optionally queues report text for LLM extraction
* Gracefully shuts down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal

from ..config import get_settings
from ..opencti.client import OpenCTIClient
from ..opencti.sync import pull_from_opencti
from ..storage.factory import create_graph_store, create_run_store

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()

DEFAULT_ENTITY_TYPES = [
    "Malware",
    "Threat-Actor",
    "Attack-Pattern",
    "Tool",
    "Vulnerability",
    "Campaign",
    "Intrusion-Set",
    "Indicator",
    "Infrastructure",
    "Course-Of-Action",
    "Report",
]


def _handle_signal() -> None:
    logger.info("OpenCTI worker: shutdown signal received")
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
                    "OpenCTI worker: unable to install signal handler for %s",
                    sig.name,
                )


async def opencti_worker_loop() -> None:
    """Periodically sync entities and relations from OpenCTI."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    if not settings.opencti_url or not settings.opencti_token:
        logger.info(
            "OpenCTI worker: disabled (OPENCTI_URL / OPENCTI_TOKEN not set). Exiting."
        )
        return

    interval_minutes = settings.opencti_worker_interval_minutes
    interval = interval_minutes * 60
    if interval <= 0:
        logger.info(
            "OpenCTI worker: disabled (OPENCTI_WORKER_INTERVAL_MINUTES=%d). Exiting.",
            interval_minutes,
        )
        return

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop)

    logger.info(
        "OpenCTI worker started — interval=%dm, url=%s",
        interval_minutes,
        settings.opencti_url,
    )

    while not _shutdown.is_set():
        client = None
        try:
            client = OpenCTIClient(settings.opencti_url, settings.opencti_token)
            result = await asyncio.to_thread(
                pull_from_opencti,
                client,
                graph_store,
                entity_types=DEFAULT_ENTITY_TYPES,
                max_per_type=0,
                run_store=run_store,
                settings=settings,
            )
            logger.info(
                "OpenCTI sync done: %d entities, %d relations",
                result.entities_pulled,
                result.relations_pulled,
            )
        except Exception:
            logger.exception("OpenCTI sync failed")
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

    logger.info("OpenCTI worker stopped")


def main() -> None:
    asyncio.run(opencti_worker_loop())


if __name__ == "__main__":
    main()
