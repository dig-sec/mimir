"""RSS threat feed worker.

Periodically pulls public RSS/Atom feeds and queues unseen entries for LLM
extraction. Designed for no-license/no-auth public feed ingestion.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from ..config import Settings
from ..connectors.rss import pull_from_rss_feeds
from ..storage.factory import create_run_store
from ._base import CycleSummary, PreflightResult, WorkerHeartbeat, run_connector_loop

logger = logging.getLogger(__name__)


def _preflight(settings: Settings) -> PreflightResult:
    if not settings.rss_worker_enabled:
        return PreflightResult(ok=False, reason="RSS_WORKER_ENABLED=0")
    feeds = settings.rss_worker_feeds_list
    if not feeds:
        return PreflightResult(ok=False, reason="no RSS_WORKER_FEEDS configured")
    interval = settings.rss_worker_interval_minutes
    if interval <= 0:
        return PreflightResult(
            ok=False, reason=f"RSS_WORKER_INTERVAL_MINUTES={interval}"
        )
    return PreflightResult(
        ok=True,
        interval_seconds=interval * 60,
        extra_heartbeat={
            "feeds_count": len(feeds),
            "lookback_hours": settings.rss_worker_lookback_hours,
        },
    )


def _run_cycle(
    settings: Settings,
    since: datetime,
    until: datetime,
    heartbeat: WorkerHeartbeat,
) -> CycleSummary:
    feeds = settings.rss_worker_feeds_list
    run_store = create_run_store(settings)
    result = pull_from_rss_feeds(
        run_store,
        settings,
        feeds,
        lookback_hours=settings.rss_worker_lookback_hours,
        max_items_per_feed=settings.rss_worker_max_items_per_feed,
        min_text_chars=settings.rss_worker_min_text_chars,
        timeout_seconds=settings.rss_worker_timeout_seconds,
    )
    return CycleSummary(
        log_message=(
            f"{result.feeds_scanned} feeds, {result.items_seen} seen, "
            f"{result.runs_queued} queued, {result.skipped_existing} existing, "
            f"{result.skipped_old} old"
        ),
        heartbeat_details={
            "feeds_scanned": result.feeds_scanned,
            "items_seen": result.items_seen,
            "runs_queued": result.runs_queued,
            "skipped_existing": result.skipped_existing,
            "skipped_old": result.skipped_old,
            "errors": len(result.errors),
        },
        errors=result.errors,
    )


async def rss_worker_loop() -> None:
    """Periodically pull public RSS/Atom feeds."""
    await run_connector_loop(
        worker_name="rss-worker",
        preflight=_preflight,
        run_cycle=_run_cycle,
    )


def main() -> None:
    asyncio.run(rss_worker_loop())


if __name__ == "__main__":
    main()
