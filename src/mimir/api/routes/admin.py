"""Admin & operations routes — tasks, metrics, stats, data-quality, watched-folders."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Query

from ..tasks import TaskStatus, task_manager
from ._helpers import (
    build_cti_summary,
    build_worker_statuses,
    graph_store,
    metrics_store,
)
from ._helpers import parse_iso_datetime as _parse_iso_datetime
from ._helpers import (
    run_store,
    settings,
)
from ._helpers import to_utc as _to_utc

router = APIRouter()


# ── Task management ──────────────────────────────────────────────


@router.get("/api/tasks")
def list_tasks():
    """List all background tasks."""
    tasks = task_manager.list_all()
    return [
        {
            "id": t.id,
            "kind": t.kind,
            "status": t.status.value,
            "progress": t.progress,
            "started_at": t.started_at,
            "finished_at": t.finished_at,
            "error": t.error,
            "detail": t.detail,
        }
        for t in reversed(tasks)
    ]


@router.get("/api/tasks/{task_id}")
def get_task(task_id: str):
    """Get status of a background task."""
    t = task_manager.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "id": t.id,
        "kind": t.kind,
        "status": t.status.value,
        "progress": t.progress,
        "started_at": t.started_at,
        "finished_at": t.finished_at,
        "error": t.error,
        "detail": t.detail,
    }


# ── Metrics rollup ──────────────────────────────────────────────


@router.post("/api/metrics/rollup")
async def trigger_metrics_rollup(
    lookback_days: int = Query(
        default=settings.metrics_rollup_lookback_days, ge=1, le=3650
    ),
    min_confidence: float = Query(
        default=settings.metrics_rollup_min_confidence, ge=0.0, le=1.0
    ),
    include_cti: bool = Query(default=True),
    source_uri: Optional[str] = Query(default=None),
):
    """Run daily metrics rollups (threat-actor + PIR + optional CTI) in background."""
    task = task_manager.create(
        "metrics_rollup",
        {
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "include_cti": include_cti,
            "source_uri": source_uri,
        },
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting metrics rollup..."
    )

    def _run_sync():
        try:
            task_manager.update(
                task.id,
                status=TaskStatus.RUNNING,
                progress="Rolling up threat-actor metrics...",
            )
            threat_actor_summary = metrics_store.rollup_daily_threat_actor_stats(
                lookback_days=lookback_days,
                min_confidence=min_confidence,
                source_uri=source_uri,
            )
            task_manager.update(
                task.id,
                status=TaskStatus.RUNNING,
                progress=(
                    f"Threat-actor rollup done "
                    f"({threat_actor_summary.get('docs_written', 0)} docs). "
                    "Rolling up PIR metrics..."
                ),
            )
            pir_summary = metrics_store.rollup_daily_pir_stats(
                lookback_days=lookback_days,
                min_confidence=min_confidence,
                source_uri=source_uri,
            )
            cti_summary = None
            cti_rollup_fn = getattr(metrics_store, "rollup_daily_cti_assessments", None)
            if include_cti and callable(cti_rollup_fn):
                task_manager.update(
                    task.id,
                    status=TaskStatus.RUNNING,
                    progress=(
                        f"PIR rollup done "
                        f"({pir_summary.get('docs_written', 0)} docs). "
                        "Rolling up CTI assessments..."
                    ),
                )
                cti_summary = cti_rollup_fn(
                    lookback_days=lookback_days,
                    min_confidence=min_confidence,
                    source_uri=source_uri,
                    decay_half_life_days=settings.cti_decay_half_life_days,
                )
            summary = {
                "threat_actor": threat_actor_summary,
                "pir": pir_summary,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "include_cti": include_cti,
                "source_uri": source_uri,
            }
            if cti_summary is not None:
                summary["cti"] = cti_summary
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    "Done: "
                    f"{threat_actor_summary.get('docs_written', 0)} threat-actor docs, "
                    f"{pir_summary.get('docs_written', 0)} PIR docs"
                    + (
                        f", {cti_summary.get('docs_written', 0)} CTI docs"
                        if cti_summary is not None
                        else ""
                    )
                ),
                detail=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            task_manager.update(
                task.id,
                status=TaskStatus.FAILED,
                error=str(exc),
                finished_at=datetime.utcnow().isoformat(),
            )

    async def _run():
        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


# ── Stats ────────────────────────────────────────────────────────


@router.get("/api/stats")
async def get_stats(source_uri: Optional[str] = Query(default=None)):
    """Quick graph stats with throughput (with timeout handling)."""
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    metrics_error = None
    cti_metrics_error = None
    pir_metrics_error = None
    try:
        metrics = metrics_store.get_rollup_overview(days=30, source_uri=source_uri)
    except Exception as exc:
        metrics = None
        metrics_error = str(exc)
    try:
        cti_metrics = metrics_store.get_cti_overview(days=30, source_uri=source_uri)
    except Exception as exc:
        cti_metrics = None
        cti_metrics_error = str(exc)

    pir_last_rollup_at = None
    pir_last_rollup_dt = None
    pir_rollup_age_seconds = None
    try:
        pir_overview_fn = getattr(metrics_store, "get_pir_trending_summary", None)
        if callable(pir_overview_fn):
            pir_data = pir_overview_fn(days=30, source_uri=source_uri)
            if isinstance(pir_data, dict):
                pir_last_rollup_at = pir_data.get("generated_at")
    except Exception as exc:
        pir_metrics_error = str(exc)

    stale_threshold_seconds = (
        settings.metrics_rollup_stale_seconds
        if settings.metrics_rollup_stale_seconds > 0
        else max(settings.metrics_rollup_interval_seconds * 2, 1800)
    )
    last_rollup_at = (
        metrics.get("last_rollup_at") if isinstance(metrics, dict) else None
    )
    cti_last_rollup_at = (
        cti_metrics.get("rollup_last_generated_at")
        if isinstance(cti_metrics, dict)
        else None
    )
    last_rollup_dt = _parse_iso_datetime(last_rollup_at)
    cti_last_rollup_dt = _parse_iso_datetime(cti_last_rollup_at)
    pir_last_rollup_dt = _parse_iso_datetime(pir_last_rollup_at)
    rollup_age_seconds = None
    cti_rollup_age_seconds = None
    if last_rollup_dt:
        rollup_age_seconds = max(
            int((datetime.now(timezone.utc) - _to_utc(last_rollup_dt)).total_seconds()),
            0,
        )
    if cti_last_rollup_dt:
        cti_rollup_age_seconds = max(
            int(
                (
                    datetime.now(timezone.utc) - _to_utc(cti_last_rollup_dt)
                ).total_seconds()
            ),
            0,
        )
    if pir_last_rollup_dt:
        pir_rollup_age_seconds = max(
            int(
                (
                    datetime.now(timezone.utc) - _to_utc(pir_last_rollup_dt)
                ).total_seconds()
            ),
            0,
        )

    metrics_has_data = isinstance(metrics, dict) and (
        (metrics.get("active_actors") or 0) > 0 or last_rollup_at is not None
    )
    cti_has_data = isinstance(cti_metrics, dict) and (
        (cti_metrics.get("docs_total") or cti_metrics.get("assessments_total") or 0) > 0
        or cti_last_rollup_at is not None
    )
    pir_has_data = pir_last_rollup_at is not None

    is_stale = metrics_error is not None or (
        metrics_has_data
        and (
            not last_rollup_dt
            or (
                rollup_age_seconds is not None
                and rollup_age_seconds > stale_threshold_seconds
            )
        )
    )
    cti_is_stale = cti_metrics_error is not None or (
        cti_has_data
        and (
            not cti_last_rollup_dt
            or (
                cti_rollup_age_seconds is not None
                and cti_rollup_age_seconds > stale_threshold_seconds
            )
        )
    )
    pir_is_stale = pir_metrics_error is not None or (
        pir_has_data
        and (
            not pir_last_rollup_dt
            or (
                pir_rollup_age_seconds is not None
                and pir_rollup_age_seconds > stale_threshold_seconds
            )
        )
    )

    entity_type_counts: Dict[str, int] = {}
    es_client = getattr(graph_store, "client", None)
    es_indices = getattr(graph_store, "indices", None)
    if es_client is not None and es_indices is not None:
        try:
            loop = asyncio.get_event_loop()
            agg_resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: es_client.search(
                        index=es_indices.entities,
                        size=0,
                        aggs={"types": {"terms": {"field": "type", "size": 100}}},
                    ),
                ),
                timeout=3.0,
            )
            for bucket in (
                agg_resp.get("aggregations", {}).get("types", {}).get("buckets", [])
            ):
                entity_type_counts[bucket["key"]] = bucket["doc_count"]
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    return {
        "entities": graph_store.count_entities(),
        "relations": graph_store.count_relations(),
        "entity_type_counts": entity_type_counts,
        "runs_total": run_store.count_runs(),
        "runs_pending": run_store.count_runs(status="pending"),
        "runs_running": run_store.count_runs(status="running"),
        "runs_completed": run_store.count_runs(status="completed"),
        "runs_failed": run_store.count_runs(status="failed"),
        "rate_per_hour": run_store.count_runs(status="completed", since=one_hour_ago),
        "metrics": metrics,
        "cti_metrics": build_cti_summary(cti_metrics),
        "metrics_status": {
            "source_uri": source_uri,
            "last_rollup_at": last_rollup_at,
            "rollup_age_seconds": rollup_age_seconds,
            "stale_threshold_seconds": stale_threshold_seconds,
            "is_stale": is_stale,
            "has_data": metrics_has_data,
            "error": metrics_error,
        },
        "cti_metrics_status": {
            "source_uri": source_uri,
            "last_rollup_at": cti_last_rollup_at,
            "rollup_age_seconds": cti_rollup_age_seconds,
            "stale_threshold_seconds": stale_threshold_seconds,
            "is_stale": cti_is_stale,
            "has_data": cti_has_data,
            "error": cti_metrics_error,
        },
        "pir_metrics_status": {
            "source_uri": source_uri,
            "last_rollup_at": pir_last_rollup_at,
            "rollup_age_seconds": pir_rollup_age_seconds,
            "stale_threshold_seconds": stale_threshold_seconds,
            "is_stale": pir_is_stale,
            "has_data": pir_has_data,
            "error": pir_metrics_error,
        },
        "workers": build_worker_statuses(),
    }


# ── Data quality ────────────────────────────────────────────────


@router.get("/api/data-quality")
def data_quality(
    days: int = Query(default=30, ge=1, le=3650),
    source_uri: Optional[str] = Query(default=None),
):
    """Data quality summary for provenance/relation coverage."""
    quality_fn = getattr(graph_store, "get_data_quality_summary", None)
    if not callable(quality_fn):
        raise HTTPException(
            status_code=501,
            detail="Data quality summary is only available on Elasticsearch backend",
        )
    return quality_fn(days=days, source_uri=source_uri)


# ── Watched folders ─────────────────────────────────────────────


@router.get("/api/watched-folders")
async def get_watched_folders():
    """Return configured watched folders and their file counts (with timeout)."""
    import pathlib

    def count_files_in_dir(d: str) -> int:
        try:
            root = pathlib.Path(d)
            if not root.is_dir():
                return 0
            count = 0
            for _ in root.rglob("*"):
                if _.is_file():
                    count += 1
                    if count > 10000:
                        return 10001
            return count
        except (PermissionError, OSError):
            return 0

    dirs = settings.watched_folders_list
    result = []

    executor = ThreadPoolExecutor(max_workers=2)
    loop = asyncio.get_event_loop()

    try:
        for d in dirs:
            root = pathlib.Path(d)
            try:
                count = await asyncio.wait_for(
                    loop.run_in_executor(executor, count_files_in_dir, d), timeout=2.0
                )
            except asyncio.TimeoutError:
                count = None

            item = {
                "name": root.name or str(root),
                "exists": root.is_dir(),
                "file_count": count if count is not None else 0,
            }
            if settings.expose_local_paths:
                item["path"] = d
            result.append(item)
    finally:
        executor.shutdown(wait=False)

    return result


# ── Stale-run recovery ──────────────────────────────────────────


@router.post("/api/recover-stale-runs")
def recover_stale_runs():
    """Reset runs stuck in 'running' back to 'pending'."""
    count = run_store.recover_stale_runs()
    return {"recovered": count}
