"""LLM extraction worker.

Dedicated worker process that polls the RunStore queue for pending
extraction runs and processes them through the LLM pipeline.  This is
the primary bottleneck in the system, so it's designed to:

* Run as its own process (one or more replicas)
* Process multiple extraction runs concurrently via ``LLM_WORKER_CONCURRENCY``
* Gracefully shut down on SIGINT/SIGTERM
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from contextlib import suppress

import httpx

from ..config import get_settings, validate_settings
from ..pipeline.runner import run_sync
from ..storage.factory import create_graph_store, create_metrics_store, create_run_store
from ..storage.metrics_store import MetricsStore
from .heartbeat import WorkerHeartbeat

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


async def _check_ollama_health(base_url: str, timeout: float) -> bool:
    """Check if Ollama is available and responding.
    
    Returns True if healthy, False if unreachable.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{base_url}/api/tags")
            return response.status_code == 200
    except Exception as exc:
        logger.debug("Ollama health check failed: %s", exc)
        return False


def _handle_signal() -> None:
    logger.info("Shutdown signal received, finishing current work...")
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
                logger.warning("Unable to install signal handler for %s", sig.name)


async def metrics_rollup_loop(metrics_store: MetricsStore) -> None:
    """Periodic metrics rollup (co-located with LLM worker for convenience)."""
    settings = get_settings()
    if not settings.metrics_rollup_enabled:
        logger.info("Metrics rollup disabled (METRICS_ROLLUP_ENABLED=0)")
        return

    interval = max(settings.metrics_rollup_interval_seconds, 30)
    lookback_days = max(settings.metrics_rollup_lookback_days, 1)
    min_confidence = max(0.0, min(settings.metrics_rollup_min_confidence, 1.0))
    cti_enabled = settings.cti_rollup_enabled
    cti_lookback_days = max(settings.cti_rollup_lookback_days, 1)

    logger.info(
        (
            "Metrics rollup enabled: interval=%ss lookback_days=%s "
            "min_confidence=%.2f cti_enabled=%s cti_lookback_days=%s"
        ),
        interval,
        lookback_days,
        min_confidence,
        cti_enabled,
        cti_lookback_days,
    )
    while not _shutdown.is_set():
        threat_actor_summary = None
        pir_summary = None
        cti_summary = None

        # Wrap each rollup independently so failures don't cascade
        try:
            threat_actor_summary = await asyncio.to_thread(
                metrics_store.rollup_daily_threat_actor_stats,
                lookback_days,
                min_confidence,
                None,
            )
        except Exception:
            logger.exception("Threat actor metrics rollup failed")

        try:
            pir_summary = await asyncio.to_thread(
                metrics_store.rollup_daily_pir_stats,
                lookback_days,
                min_confidence,
                None,
            )
        except Exception:
            logger.exception("PIR metrics rollup failed")

        if cti_enabled:
            cti_rollup_fn = getattr(metrics_store, "rollup_daily_cti_assessments", None)
            if callable(cti_rollup_fn):
                try:
                    cti_summary = await asyncio.to_thread(
                        cti_rollup_fn,
                        cti_lookback_days,
                        min_confidence,
                        None,
                        max(settings.cti_decay_half_life_days, 1),
                    )
                except Exception:
                    logger.exception("CTI metrics rollup failed")

        # Log summary of completed rollups
        if threat_actor_summary or pir_summary or cti_summary:
            logger.info(
                (
                    "Metrics rollup complete:%s%s%s"
                ),
                (
                    f" threat_actor={int(threat_actor_summary.get('docs_written', 0))} docs/"
                    f"{int(threat_actor_summary.get('buckets_written', 0))} buckets/"
                    f"{int(threat_actor_summary.get('actors_total', 0))} actors"
                    if threat_actor_summary
                    else ""
                ),
                (
                    f" pir={int(pir_summary.get('docs_written', 0))} docs/"
                    f"{int(pir_summary.get('buckets_written', 0))} buckets/"
                    f"{int(pir_summary.get('entities_total', 0))} entities"
                    if pir_summary
                    else ""
                ),
                (
                    f" cti={int(cti_summary.get('docs_written', 0))} docs/"
                    f"{int(cti_summary.get('buckets_written', 0))} buckets/"
                    f"{int(cti_summary.get('assessments_total', 0))} assessments"
                    if cti_summary
                    else ""
                ),
            )
        else:
            logger.warning("All metrics rollups failed")

        # Wait for next interval
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=interval)
            return  # shutdown requested
        except asyncio.TimeoutError:
            pass  # loop again


async def llm_worker_loop() -> None:
    """Main loop: claim runs from queue and process with LLM."""
    settings = get_settings()
    heartbeat = WorkerHeartbeat(settings, "llm-worker")
    logging.basicConfig(level=settings.log_level)
    _shutdown.clear()

    # Validate settings at startup
    try:
        validate_settings(settings)
    except ValueError as exc:
        logger.error("Configuration error: %s", exc)
        heartbeat.update("error", {"reason": f"config error: {exc}"})
        return

    # Check Ollama is available before starting
    logger.info("Checking Ollama availability at %s...", settings.ollama_base_url)
    heartbeat.update("starting", {"ollama_base_url": settings.ollama_base_url})
    try:
        is_healthy = await asyncio.wait_for(
            _check_ollama_health(
                settings.ollama_base_url,
                settings.startup_health_check_timeout_seconds,
            ),
            timeout=settings.startup_health_check_timeout_seconds,
        )
        if not is_healthy:
            logger.error(
                "Ollama at %s returned unhealthy status; unable to proceed",
                settings.ollama_base_url,
            )
            heartbeat.update(
                "error",
                {
                    "reason": "ollama unhealthy",
                    "ollama_base_url": settings.ollama_base_url,
                },
            )
            return
    except asyncio.TimeoutError:
        logger.error(
            "Ollama health check timed out at %s; unable to proceed",
            settings.ollama_base_url,
        )
        heartbeat.update(
            "error",
            {"reason": "ollama health timeout", "ollama_base_url": settings.ollama_base_url},
        )
        return
    except Exception as exc:
        logger.error("Ollama health check failed: %s; unable to proceed", exc)
        heartbeat.update(
            "error",
            {
                "reason": f"ollama health check failed: {exc}",
                "ollama_base_url": settings.ollama_base_url,
            },
        )
        return

    logger.info("Ollama is healthy and ready")

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)
    metrics_store = create_metrics_store(settings)

    # Set up graceful shutdown
    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop)

    configured_concurrency = settings.llm_worker_concurrency
    concurrency = max(configured_concurrency, 1)
    if configured_concurrency < 1:
        logger.warning(
            "Invalid LLM_WORKER_CONCURRENCY=%d, using 1",
            configured_concurrency,
        )

    configured_poll_interval = settings.llm_worker_poll_seconds
    poll_interval = max(configured_poll_interval, 1)
    if configured_poll_interval < 1:
        logger.warning(
            "Invalid LLM_WORKER_POLL_SECONDS=%d, using 1",
            configured_poll_interval,
        )

    logger.info(
        "LLM extraction worker started — concurrency=%d, poll_interval=%ds",
        concurrency,
        poll_interval,
    )
    heartbeat.update(
        "running",
        {"concurrency": concurrency, "poll_interval_seconds": poll_interval},
    )

    # Recover any stale runs from previous crashes
    try:
        recovered = await asyncio.wait_for(
            asyncio.to_thread(run_store.recover_stale_runs),
            timeout=settings.startup_health_check_timeout_seconds,
        )
        if recovered:
            logger.info("Recovered %d stale run(s) back to pending", recovered)
    except asyncio.TimeoutError:
        logger.warning(
            "Stale run recovery timed out after %.0fs, continuing anyway",
            settings.startup_health_check_timeout_seconds,
        )
    except Exception:
        logger.exception("Failed to recover stale runs at startup")

    # Purge very old pending runs that will never be processed
    if settings.max_pending_age_days > 0:
        try:
            purged = await asyncio.wait_for(
                asyncio.to_thread(
                    run_store.purge_stale_pending_runs,
                    settings.max_pending_age_days,
                ),
                timeout=settings.startup_health_check_timeout_seconds,
            )
            if purged:
                logger.info(
                    "Purged %d stale pending run(s) older than %d days",
                    purged,
                    settings.max_pending_age_days,
                )
        except asyncio.TimeoutError:
            logger.warning(
                "Stale pending run purge timed out after %.0fs, continuing anyway",
                settings.startup_health_check_timeout_seconds,
            )
        except Exception:
            logger.exception("Failed to purge stale pending runs at startup")

    # Start metrics rollup only if this replica is the designated leader.
    # When scaling llm-workers (--scale llm-worker=N), set
    # METRICS_ROLLUP_LEADER=1 on exactly one replica to avoid duplicate
    # rollup writes.  Default is "1" (single-replica backward compat).
    import os

    is_rollup_leader = os.getenv("METRICS_ROLLUP_LEADER", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if is_rollup_leader:
        metrics_task = asyncio.create_task(metrics_rollup_loop(metrics_store))
    else:
        logger.info(
            "Metrics rollup disabled on this replica (METRICS_ROLLUP_LEADER!=1)"
        )
        metrics_task = asyncio.create_task(asyncio.sleep(0))  # no-op placeholder

    # Semaphore to limit concurrent LLM extractions
    sem = asyncio.Semaphore(concurrency)
    active_tasks: set[asyncio.Task] = set()
    last_heartbeat_at = 0.0

    async def _process_one(run_id: str) -> None:
        async with sem:
            if _shutdown.is_set():
                try:
                    await asyncio.to_thread(
                        run_store.update_run_status, run_id, "pending"
                    )
                except Exception:
                    logger.exception(
                        "Shutdown: failed to requeue run %s back to pending", run_id
                    )
                return
            logger.info("Processing run %s", run_id)
            try:
                await asyncio.to_thread(
                    run_sync,
                    run_id,
                    graph_store,
                    run_store,
                    settings,
                )
            except Exception as exc:
                error_msg = (
                    str(exc) if str(exc) else f"{type(exc).__name__} (no detail)"
                )
                try:
                    await asyncio.to_thread(
                        run_store.update_run_status,
                        run_id,
                        "failed",
                        error_msg,
                    )
                except Exception:
                    logger.exception("Run %s failed and status update failed", run_id)
                else:
                    logger.exception("Run %s failed: %s", run_id, error_msg)
                # Purge document text even on failure to reclaim storage
                try:
                    await asyncio.to_thread(run_store.purge_document_text, run_id)
                except Exception:
                    logger.debug("Run %s: failed to purge document text", run_id)
                return

            try:
                await asyncio.to_thread(
                    run_store.update_run_status, run_id, "completed"
                )
            except Exception:
                logger.exception(
                    "Run %s processed but failed to mark completed", run_id
                )
            else:
                logger.info("Run %s completed", run_id)

            # Purge document text after successful completion to reclaim storage
            try:
                await asyncio.to_thread(run_store.purge_document_text, run_id)
            except Exception:
                logger.debug("Run %s: failed to purge document text", run_id)

    try:
        while not _shutdown.is_set():
            # Clean up finished tasks
            done = {t for t in active_tasks if t.done()}
            for task in done:
                with suppress(asyncio.CancelledError):
                    task_exc = task.exception()
                    if task_exc:
                        logger.error("LLM worker task crashed", exc_info=task_exc)
            active_tasks -= done

            # Claim work up to concurrency limit
            available_slots = concurrency - len(active_tasks)
            claimed = 0
            for _ in range(available_slots):
                try:
                    run = await asyncio.to_thread(run_store.claim_next_run)
                except Exception:
                    logger.exception("Failed to claim next run")
                    break
                if not run:
                    break
                task = asyncio.create_task(_process_one(run.run_id))
                active_tasks.add(task)
                claimed += 1

            if claimed == 0:
                # No work available, wait before polling again
                now = time.monotonic()
                if now - last_heartbeat_at >= max(float(poll_interval), 2.0):
                    is_active = len(active_tasks) > 0
                    heartbeat.update(
                        "running" if is_active else "sleeping",
                        {
                            "poll_interval_seconds": poll_interval,
                            "active_tasks": len(active_tasks),
                            "concurrency": concurrency,
                        },
                    )
                    last_heartbeat_at = now
                try:
                    await asyncio.wait_for(_shutdown.wait(), timeout=poll_interval)
                    break  # shutdown
                except asyncio.TimeoutError:
                    pass
            else:
                now = time.monotonic()
                if now - last_heartbeat_at >= 2.0:
                    heartbeat.update(
                        "running",
                        {
                            "claimed_last_loop": claimed,
                            "active_tasks": len(active_tasks),
                            "concurrency": concurrency,
                        },
                    )
                    last_heartbeat_at = now
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
    heartbeat.update("stopped")


def main() -> None:
    asyncio.run(llm_worker_loop())


if __name__ == "__main__":
    main()
