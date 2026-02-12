"""Periodic sync scheduler for Feedly and OpenCTI ingestion.

Runs Feedly CTI pull and OpenCTI pull every ``SYNC_INTERVAL_MINUTES``
(default 30).  Each cycle uses a lookback window of
``SYNC_LOOKBACK_MINUTES`` (default 60, i.e. 1 hour) so there's overlap
to catch anything missed.  Filesystem scan is intentionally excluded —
that remains manual.

The scheduler is started via the FastAPI lifespan in ``app.py``.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import Settings
    from ..storage.base import GraphStore
    from ..storage.run_store import RunStore

logger = logging.getLogger(__name__)


async def run_sync_loop(
    settings: "Settings",
    graph_store: "GraphStore",
    run_store: "RunStore",
) -> None:
    """Run Feedly + OpenCTI sync in a loop every ``sync_interval_minutes``."""
    from ..connectors import sync_feedly_index
    from ..opencti.client import OpenCTIClient
    from ..opencti.sync import pull_from_opencti

    interval = settings.sync_interval_minutes * 60  # seconds
    if interval <= 0:
        logger.info("Sync scheduler disabled (SYNC_INTERVAL_MINUTES=0)")
        return

    logger.info(
        "Sync scheduler started — every %d min, lookback %d min",
        settings.sync_interval_minutes,
        settings.sync_lookback_minutes,
    )

    while True:
        await asyncio.sleep(interval)

        cycle_end = datetime.now(timezone.utc)
        since = cycle_end - timedelta(
            minutes=settings.sync_lookback_minutes,
        )

        # ── Feedly ────────────────────────────────────────────
        if settings.elastic_connector_enabled and settings.elastic_connector_hosts_list:
            indices = settings.elastic_connector_indices_list or ["feedly_news"]
            logger.info(
                "Scheduled Feedly sync (since %s, until %s) across %d index(es)...",
                since.isoformat(),
                cycle_end.isoformat(),
                len(indices),
            )
            for index_name in indices:
                try:
                    feedly_result = await asyncio.to_thread(
                        sync_feedly_index,
                        settings=settings,
                        graph_store=graph_store,
                        run_store=None,
                        index_name=index_name,
                        since=since,
                        until=cycle_end,
                        max_articles=0,
                        queue_for_llm=False,
                    )
                    logger.info(
                        "Scheduled Feedly sync %s done: %d articles, %d entities, %d rels",
                        index_name,
                        feedly_result.articles_processed,
                        feedly_result.entities_created,
                        feedly_result.relations_created,
                    )
                except Exception:
                    logger.exception("Scheduled Feedly sync failed for index %s", index_name)
        elif settings.elastic_connector_hosts_list and not settings.elastic_connector_enabled:
            logger.debug("Scheduled Feedly sync disabled by ELASTIC_CONNECTOR_ENABLED=0")

        # ── OpenCTI ───────────────────────────────────────────
        if settings.opencti_url and settings.opencti_token:
            logger.info("Scheduled OpenCTI sync...")
            client = None
            try:
                client = OpenCTIClient(settings.opencti_url, settings.opencti_token)
                opencti_result = await asyncio.to_thread(
                    pull_from_opencti,
                    client,
                    graph_store,
                    entity_types=[
                        "Malware", "Threat-Actor", "Attack-Pattern", "Tool",
                        "Vulnerability", "Campaign", "Intrusion-Set",
                        "Indicator", "Infrastructure", "Course-Of-Action", "Report",
                    ],
                    max_per_type=0,
                    run_store=run_store,
                    settings=settings,
                )
                logger.info(
                    "Scheduled OpenCTI sync done: %d entities, %d rels",
                    opencti_result.entities_pulled,
                    opencti_result.relations_pulled,
                )
            except Exception:
                logger.exception("Scheduled OpenCTI sync failed")
            finally:
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass

        logger.info("Next sync in %d minutes", settings.sync_interval_minutes)
