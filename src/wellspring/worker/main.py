from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from ..config import get_settings
from ..pipeline.runner import process_run
from ..storage.factory import create_graph_store, create_metrics_store, create_run_store
from ..storage.metrics_store import MetricsStore

logger = logging.getLogger(__name__)


async def metrics_rollup_loop(metrics_store: MetricsStore) -> None:
    settings = get_settings()
    if not settings.metrics_rollup_enabled:
        logger.info("Metrics rollup disabled (METRICS_ROLLUP_ENABLED=0)")
        return

    interval = max(settings.metrics_rollup_interval_seconds, 30)
    lookback_days = max(settings.metrics_rollup_lookback_days, 1)
    min_confidence = max(0.0, min(settings.metrics_rollup_min_confidence, 1.0))

    logger.info(
        "Metrics rollup enabled: interval=%ss lookback_days=%s min_confidence=%.2f",
        interval,
        lookback_days,
        min_confidence,
    )
    while True:
        try:
            summary = await asyncio.to_thread(
                metrics_store.rollup_daily_threat_actor_stats,
                lookback_days,
                min_confidence,
                None,
            )
            logger.info(
                "Metrics rollup complete: %d docs, %d buckets, %d actors",
                int(summary.get("docs_written", 0)),
                int(summary.get("buckets_written", 0)),
                int(summary.get("actors_total", 0)),
            )
        except Exception:
            logger.exception("Metrics rollup failed")
        await asyncio.sleep(interval)


async def worker_loop() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)
    metrics_store = create_metrics_store(settings)

    metrics_task = asyncio.create_task(metrics_rollup_loop(metrics_store))

    recovered = run_store.recover_stale_runs()
    if recovered:
        logger.info("Recovered %d stale run(s) back to pending", recovered)

    try:
        while True:
            run = run_store.claim_next_run()
            if not run:
                await asyncio.sleep(2)
                continue
            logger.info("Processing run %s", run.run_id)
            try:
                await process_run(run.run_id, graph_store, run_store, settings)
                run_store.update_run_status(run.run_id, "completed")
                logger.info("Run %s completed", run.run_id)
            except Exception as exc:
                run_store.update_run_status(run.run_id, "failed", error=str(exc))
                logger.exception("Run %s failed", run.run_id)
    finally:
        metrics_task.cancel()
        with suppress(asyncio.CancelledError):
            await metrics_task


def main() -> None:
    asyncio.run(worker_loop())


if __name__ == "__main__":
    main()
