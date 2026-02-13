"""LLM extraction worker.

Dedicated worker process that polls the RunStore queue for pending
extraction runs and processes them through the LLM pipeline.  This is
the primary bottleneck in the system, so it's designed to:

* Run as its own process (one or more replicas)
* Process multiple chunks concurrently via ``LLM_WORKER_CONCURRENCY``
* Share a single ``OllamaClient`` across concurrent chunk tasks
* Gracefully shut down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal
from contextlib import suppress

from ..config import get_settings
from ..pipeline.runner import process_run
from ..storage.factory import create_graph_store, create_metrics_store, create_run_store
from ..storage.metrics_store import MetricsStore

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _handle_signal() -> None:
    logger.info("Shutdown signal received, finishing current work...")
    _shutdown.set()


async def metrics_rollup_loop(metrics_store: MetricsStore) -> None:
    """Periodic metrics rollup (co-located with LLM worker for convenience)."""
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
    while not _shutdown.is_set():
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
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            return  # shutdown requested
        except asyncio.TimeoutError:
            pass  # loop again


async def llm_worker_loop() -> None:
    """Main loop: claim runs from queue and process with LLM."""
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)
    metrics_store = create_metrics_store(settings)

    # Set up graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    concurrency = settings.llm_worker_concurrency
    poll_interval = settings.llm_worker_poll_seconds

    logger.info(
        "LLM extraction worker started — concurrency=%d, poll_interval=%ds",
        concurrency,
        poll_interval,
    )

    # Recover any stale runs from previous crashes
    recovered = run_store.recover_stale_runs()
    if recovered:
        logger.info("Recovered %d stale run(s) back to pending", recovered)

    # Start metrics rollup only if this replica is the designated leader.
    # When scaling llm-workers (--scale llm-worker=N), set
    # METRICS_ROLLUP_LEADER=1 on exactly one replica to avoid duplicate
    # rollup writes.  Default is "1" (single-replica backward compat).
    import os
    is_rollup_leader = os.getenv("METRICS_ROLLUP_LEADER", "1").strip().lower() in {
        "1", "true", "yes", "on",
    }
    if is_rollup_leader:
        metrics_task = asyncio.create_task(metrics_rollup_loop(metrics_store))
    else:
        logger.info("Metrics rollup disabled on this replica (METRICS_ROLLUP_LEADER!=1)")
        metrics_task = asyncio.create_task(asyncio.sleep(0))  # no-op placeholder

    # Semaphore to limit concurrent LLM extractions
    sem = asyncio.Semaphore(concurrency)
    active_tasks: set[asyncio.Task] = set()

    async def _process_one(run_id: str) -> None:
        async with sem:
            if _shutdown.is_set():
                return
            logger.info("Processing run %s", run_id)
            try:
                await process_run(run_id, graph_store, run_store, settings)
                run_store.update_run_status(run_id, "completed")
                logger.info("Run %s completed", run_id)
            except Exception as exc:
                run_store.update_run_status(run_id, "failed", error=str(exc))
                logger.exception("Run %s failed", run_id)

    try:
        while not _shutdown.is_set():
            # Clean up finished tasks
            done = {t for t in active_tasks if t.done()}
            active_tasks -= done

            # Claim work up to concurrency limit
            available_slots = concurrency - len(active_tasks)
            claimed = 0
            for _ in range(available_slots):
                run = run_store.claim_next_run()
                if not run:
                    break
                task = asyncio.create_task(_process_one(run.run_id))
                active_tasks.add(task)
                claimed += 1

            if claimed == 0:
                # No work available, wait before polling again
                try:
                    await asyncio.wait_for(
                        _shutdown.wait(), timeout=poll_interval
                    )
                    break  # shutdown
                except asyncio.TimeoutError:
                    pass
            else:
                # Give tasks a moment to start, then loop to claim more
                await asyncio.sleep(0.1)

        # Wait for all active tasks to finish
        if active_tasks:
            logger.info(
                "Shutdown: waiting for %d active extraction(s) to finish...",
                len(active_tasks),
            )
            await asyncio.gather(*active_tasks, return_exceptions=True)

    finally:
        metrics_task.cancel()
        with suppress(asyncio.CancelledError):
            await metrics_task

    logger.info("LLM extraction worker stopped")


def main() -> None:
    asyncio.run(llm_worker_loop())


if __name__ == "__main__":
    main()
