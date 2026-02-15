"""Connector pull routes — manual one-shot syncs for each data source."""

from __future__ import annotations

import os
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query

from ...connectors import sync_feedly_index
from ...connectors.aikg import ingest_aikg_triples, parse_aikg_file
from ...connectors.gvm import sync_gvm
from ...connectors.rss import pull_from_rss_feeds
from ...connectors.watcher import sync_watcher
from ...elastic_source import pull_from_elasticsearch
from ...opencti.sync import OPENCTI_DEFAULT_ENTITY_TYPES, pull_from_opencti
from ...schemas import ExtractionRun
from ...stix.importer import ingest_stix_bundle, parse_stix_file
from ..tasks import TaskStatus, task_manager
from ._helpers import (
    extract_text,
    get_elastic_connector_client,
    get_opencti_client,
    graph_store,
    is_stix_bundle,
    run_store,
    settings,
)

router = APIRouter()


# ── Individual connector pulls ───────────────────────────────────


@router.post("/api/opencti/pull")
async def opencti_pull(
    entity_types: List[str] = Query(default=list(OPENCTI_DEFAULT_ENTITY_TYPES)),
    max_per_type: int = Query(
        default=0, ge=0, le=10000, description="0 = fetch all (no limit)"
    ),
):
    """Pull entities from OpenCTI as a background task."""
    client = get_opencti_client()
    if not client:
        raise HTTPException(
            status_code=503,
            detail="OpenCTI not configured (set OPENCTI_URL and OPENCTI_TOKEN env vars)",
        )

    task = task_manager.create(
        "opencti_pull",
        {"entity_types": entity_types, "max_per_type": max_per_type},
    )
    task_manager.update(task.id, status=TaskStatus.RUNNING, progress="Starting...")

    def _run_sync():
        try:
            result = pull_from_opencti(
                client,
                graph_store,
                entity_types,
                max_per_type,
                run_store=run_store,
                settings=settings,
                progress_cb=lambda msg: task_manager.update(task.id, progress=msg),
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=f"Done: {result.entities_pulled} entities, {result.relations_pulled} relations, {result.reports_queued} reports queued",
                detail={
                    "entities_pulled": result.entities_pulled,
                    "relations_pulled": result.relations_pulled,
                    "reports_queued": result.reports_queued,
                    "errors": result.errors[:20],
                },
                finished_at=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            task_manager.update(
                task.id,
                status=TaskStatus.FAILED,
                error=str(exc),
                finished_at=datetime.utcnow().isoformat(),
            )
        finally:
            client.close()

    async def _run():
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.post("/api/elasticsearch/pull")
async def elasticsearch_pull(
    indices: Optional[List[str]] = Query(
        default=None,
        description="Optional list of index names. Defaults to ELASTIC_CONNECTOR_INDICES.",
    ),
    max_per_index: int = Query(default=500, ge=1, le=20000),
    lookback_minutes: int = Query(
        default=settings.elastic_connector_lookback_minutes, ge=0
    ),
):
    """Pull source documents from Elasticsearch and queue LLM extraction runs."""
    selected_indices: List[str] = []
    for raw in indices or settings.elastic_connector_indices_list:
        for idx in raw.split(","):
            if idx.strip():
                selected_indices.append(idx.strip())
    if not selected_indices:
        raise HTTPException(
            status_code=400,
            detail="No Elasticsearch connector indices configured (set ELASTIC_CONNECTOR_INDICES)",
        )

    client = get_elastic_connector_client(allow_disabled=True)
    if not client:
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch connector not configured (set ELASTICSEARCH_URL or ELASTIC_CONNECTOR_HOSTS)",
        )

    task = task_manager.create(
        "elasticsearch_pull",
        {
            "indices": selected_indices,
            "max_per_index": max_per_index,
            "lookback_minutes": lookback_minutes,
        },
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting Elasticsearch pull..."
    )

    def _run_sync():
        try:
            result = pull_from_elasticsearch(
                client,
                run_store,
                settings,
                selected_indices,
                max_per_index=max_per_index,
                lookback_minutes=lookback_minutes,
                min_text_chars=settings.elastic_connector_min_text_chars,
                progress_cb=lambda msg: task_manager.update(task.id, progress=msg),
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    f"Done: {result.runs_queued} queued, "
                    f"{result.skipped_existing} skipped existing, "
                    f"{result.skipped_empty} skipped empty"
                ),
                detail={
                    "indexes_scanned": result.indexes_scanned,
                    "documents_seen": result.documents_seen,
                    "runs_queued": result.runs_queued,
                    "skipped_existing": result.skipped_existing,
                    "skipped_empty": result.skipped_empty,
                    "errors": result.errors[:50],
                },
                finished_at=datetime.utcnow().isoformat(),
            )
        except Exception as exc:
            task_manager.update(
                task.id,
                status=TaskStatus.FAILED,
                error=str(exc),
                finished_at=datetime.utcnow().isoformat(),
            )
        finally:
            client.close()

    async def _run():
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.post("/api/feedly/pull")
async def feedly_pull(
    index: str = Query(default="feedly_news", description="Feedly ES index name"),
    max_articles: int = Query(
        default=0, ge=0, le=100000, description="Max articles (0=unlimited)"
    ),
    lookback_minutes: int = Query(
        default=settings.elastic_connector_lookback_minutes,
        ge=0,
        description="Only fetch articles newer than N minutes (0=all time)",
    ),
    queue_for_llm: bool = Query(
        default=False, description="Also queue text for LLM extraction"
    ),
):
    """Pull structured CTI data from a Feedly Elasticsearch index."""
    if not settings.elastic_connector_hosts_list:
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch connector not configured (set ELASTIC_CONNECTOR_HOSTS)",
        )

    task = task_manager.create(
        "feedly_pull",
        {
            "index": index,
            "max_articles": max_articles,
            "lookback_minutes": lookback_minutes,
            "queue_for_llm": queue_for_llm,
        },
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting Feedly pull..."
    )

    since = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        if lookback_minutes > 0
        else datetime(2000, 1, 1, tzinfo=timezone.utc)
    )

    def _run_sync():
        try:
            result = sync_feedly_index(
                settings=settings,
                graph_store=graph_store,
                run_store=run_store if queue_for_llm else None,
                index_name=index,
                since=since,
                max_articles=max_articles,
                queue_for_llm=queue_for_llm,
                progress_cb=lambda msg: task_manager.update(task.id, progress=msg),
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    f"Done: {result.articles_processed} articles, "
                    f"{result.entities_created} entities, "
                    f"{result.relations_created} relations, "
                    f"{result.iocs_created} IOCs"
                ),
                detail={
                    "articles_processed": result.articles_processed,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                    "iocs_created": result.iocs_created,
                    "articles_queued_for_llm": result.articles_queued_for_llm,
                    "errors": result.errors[:50],
                },
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.post("/api/rss/pull")
async def rss_pull(
    feeds: Optional[List[str]] = Query(
        default=None,
        description="Optional list of RSS/Atom feed URLs. Defaults to RSS_WORKER_FEEDS.",
    ),
    lookback_hours: int = Query(
        default=settings.rss_worker_lookback_hours,
        ge=0,
        le=8760,
        description="Only queue entries newer than N hours (0=all available in feed).",
    ),
    max_items_per_feed: int = Query(
        default=settings.rss_worker_max_items_per_feed, ge=1, le=5000
    ),
):
    """Pull public RSS/Atom feeds and queue unseen entries for LLM extraction."""
    selected_feeds: List[str] = []
    for raw in feeds or settings.rss_worker_feeds_list:
        for value in raw.split(","):
            value = value.strip()
            if value:
                selected_feeds.append(value)
    if not selected_feeds:
        raise HTTPException(
            status_code=400, detail="No RSS feeds configured (set RSS_WORKER_FEEDS)"
        )

    task = task_manager.create(
        "rss_pull",
        {
            "feeds": selected_feeds,
            "lookback_hours": lookback_hours,
            "max_items_per_feed": max_items_per_feed,
        },
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting RSS pull..."
    )

    def _run_sync():
        try:
            result = pull_from_rss_feeds(
                run_store,
                settings,
                selected_feeds,
                lookback_hours=lookback_hours,
                max_items_per_feed=max_items_per_feed,
                min_text_chars=settings.rss_worker_min_text_chars,
                timeout_seconds=settings.rss_worker_timeout_seconds,
                progress_cb=lambda msg: task_manager.update(task.id, progress=msg),
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    f"Done: {result.runs_queued} queued, "
                    f"{result.skipped_existing} existing, "
                    f"{result.skipped_old} old, "
                    f"{result.skipped_empty} empty"
                ),
                detail={
                    "feeds_scanned": result.feeds_scanned,
                    "items_seen": result.items_seen,
                    "runs_queued": result.runs_queued,
                    "skipped_existing": result.skipped_existing,
                    "skipped_old": result.skipped_old,
                    "skipped_empty": result.skipped_empty,
                    "errors": result.errors[:50],
                },
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.post("/api/gvm/pull")
async def gvm_pull(
    lookback_minutes: int = Query(
        default=settings.gvm_worker_lookback_minutes,
        ge=0,
        description="Only process GVM results newer than N minutes (0=all available).",
    ),
    max_results: int = Query(
        default=settings.gvm_max_results,
        ge=1,
        le=50000,
        description="Maximum number of GVM results to process.",
    ),
):
    """Pull vulnerability scan results from GVM/OpenVAS."""
    task = task_manager.create(
        "gvm_pull",
        {"lookback_minutes": lookback_minutes, "max_results": max_results},
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting GVM pull..."
    )

    since = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        if lookback_minutes > 0
        else datetime(2000, 1, 1, tzinfo=timezone.utc)
    )

    def _run_sync():
        try:
            result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
                max_results=max_results,
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    f"Done: {result.results_processed} results, "
                    f"{result.hosts_seen} hosts, "
                    f"{result.entities_created} entities, "
                    f"{result.relations_created} relations"
                ),
                detail={
                    "results_processed": result.results_processed,
                    "hosts_seen": result.hosts_seen,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                    "skipped_low_qod": result.skipped_low_qod,
                    "errors": result.errors[:50],
                },
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.post("/api/watcher/pull")
async def watcher_pull(
    lookback_minutes: int = Query(
        default=settings.watcher_worker_lookback_minutes,
        ge=0,
        description="Only process Watcher records newer than N minutes (0=all available).",
    ),
):
    """Pull structured threat-intelligence records from Watcher."""
    if not settings.watcher_base_url:
        raise HTTPException(
            status_code=503, detail="Watcher not configured (set WATCHER_BASE_URL)"
        )

    task = task_manager.create("watcher_pull", {"lookback_minutes": lookback_minutes})
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting Watcher pull..."
    )

    since = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        if lookback_minutes > 0
        else datetime(2000, 1, 1, tzinfo=timezone.utc)
    )

    def _run_sync():
        try:
            result = sync_watcher(
                settings=settings, graph_store=graph_store, since=since
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress=(
                    f"Done: {result.trendy_words_processed} trendy, "
                    f"{result.data_leaks_processed} leaks, "
                    f"{result.dns_twisted_processed} twisted, "
                    f"{result.sites_processed} sites"
                ),
                detail={
                    "trendy_words_processed": result.trendy_words_processed,
                    "data_leaks_processed": result.data_leaks_processed,
                    "dns_twisted_processed": result.dns_twisted_processed,
                    "sites_processed": result.sites_processed,
                    "entities_created": result.entities_created,
                    "relations_created": result.relations_created,
                    "skipped_low_score": result.skipped_low_score,
                    "skipped_low_occurrences": result.skipped_low_occurrences,
                    "errors": result.errors[:50],
                },
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


# ── Pull-all orchestrator ───────────────────────────────────────


@router.post("/api/sources/pull-all")
async def pull_all_sources(
    lookback_minutes: int = Query(
        default=settings.elastic_connector_lookback_minutes,
        ge=0,
        description="Lookback window for time-based sources (0=all time)",
    ),
    queue_for_llm: bool = Query(
        default=False, description="Queue Feedly article text for LLM extraction too"
    ),
    extensions: str = Query(default=".txt,.md,.pdf,.json,.html,.csv,.xml,.yaml,.yml"),
):
    """Pull from ALL configured sources concurrently."""
    task = task_manager.create(
        "pull_all_sources",
        {
            "lookback_minutes": lookback_minutes,
            "queue_for_llm": queue_for_llm,
            "extensions": extensions,
        },
    )
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Launching connectors..."
    )

    since = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        if lookback_minutes > 0
        else datetime(2000, 1, 1, tzinfo=timezone.utc)
    )

    sub_ids: Dict[str, str] = {}

    def _make_sub(kind: str, label: str) -> str:
        sub = task_manager.create(kind, {"parent": task.id})
        task_manager.update(sub.id, status=TaskStatus.RUNNING, progress=f"{label}...")
        sub_ids[kind] = sub.id
        return sub.id

    def _pull_feedly() -> str:
        sid = _make_sub("feedly_pull", "Feedly CTI")
        if not settings.elastic_connector_hosts_list:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (no ES hosts)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "Feedly: skipped (no ES hosts)"
        try:
            feedly_result = sync_feedly_index(
                settings=settings,
                graph_store=graph_store,
                run_store=run_store if queue_for_llm else None,
                index_name=(
                    settings.elastic_connector_indices_list[0]
                    if settings.elastic_connector_indices_list
                    else "feedly_news"
                ),
                since=since,
                max_articles=0,
                queue_for_llm=queue_for_llm,
                progress_cb=lambda msg: task_manager.update(
                    sid, progress=f"Feedly: {msg}"
                ),
            )
            summary = (
                f"Feedly: {feedly_result.articles_processed} articles, "
                f"{feedly_result.entities_created} entities, "
                f"{feedly_result.relations_created} rels, "
                f"{feedly_result.iocs_created} IOCs"
            )
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"Feedly: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"Feedly: FAILED ({exc})"

    def _pull_opencti() -> str:
        sid = _make_sub("opencti_pull", "OpenCTI")
        opencti_client = get_opencti_client()
        if not opencti_client:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (not configured)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "OpenCTI: skipped (not configured)"
        try:
            opencti_result = pull_from_opencti(
                opencti_client,
                graph_store,
                entity_types=list(OPENCTI_DEFAULT_ENTITY_TYPES),
                max_per_type=0,
                run_store=run_store,
                settings=settings,
                progress_cb=lambda msg: task_manager.update(
                    sid, progress=f"OpenCTI: {msg}"
                ),
            )
            summary = (
                f"OpenCTI: {opencti_result.entities_pulled} entities, "
                f"{opencti_result.relations_pulled} rels, "
                f"{opencti_result.reports_queued} reports queued"
            )
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"OpenCTI: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"OpenCTI: FAILED ({exc})"
        finally:
            if opencti_client:
                opencti_client.close()

    def _pull_rss() -> str:
        sid = _make_sub("rss_pull", "Public RSS feeds")
        if not settings.rss_worker_enabled:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (RSS worker disabled)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "RSS: skipped (RSS_WORKER_ENABLED=0)"
        feeds = settings.rss_worker_feeds_list
        if not feeds:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (no RSS feeds configured)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "RSS: skipped (no RSS_WORKER_FEEDS)"
        try:
            if lookback_minutes > 0:
                lbh = max(1, (lookback_minutes + 59) // 60)
            else:
                lbh = settings.rss_worker_lookback_hours
            rss_result = pull_from_rss_feeds(
                run_store,
                settings,
                feeds,
                lookback_hours=lbh,
                max_items_per_feed=settings.rss_worker_max_items_per_feed,
                min_text_chars=settings.rss_worker_min_text_chars,
                timeout_seconds=settings.rss_worker_timeout_seconds,
                progress_cb=lambda msg: task_manager.update(
                    sid, progress=f"RSS: {msg}"
                ),
            )
            summary = f"RSS: {rss_result.runs_queued} queued, {rss_result.skipped_existing} existing, {rss_result.skipped_old} old"
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"RSS: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"RSS: FAILED ({exc})"

    def _pull_gvm() -> str:
        sid = _make_sub("gvm_pull", "GVM vulnerability scan")
        if not settings.gvm_worker_enabled:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (GVM worker disabled)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "GVM: skipped (GVM_WORKER_ENABLED=0)"
        try:
            gvm_result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
                until=datetime.now(timezone.utc),
            )
            summary = (
                f"GVM: {gvm_result.results_processed} results, "
                f"{gvm_result.hosts_seen} hosts, "
                f"{gvm_result.entities_created} entities, "
                f"{gvm_result.relations_created} rels"
            )
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"GVM: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"GVM: FAILED ({exc})"

    def _pull_watcher() -> str:
        sid = _make_sub("watcher_pull", "Watcher threat intelligence")
        if not settings.watcher_worker_enabled:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (Watcher worker disabled)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "Watcher: skipped (WATCHER_WORKER_ENABLED=0)"
        if not settings.watcher_base_url:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (Watcher base URL not configured)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "Watcher: skipped (missing WATCHER_BASE_URL)"
        try:
            watcher_result = sync_watcher(
                settings=settings,
                graph_store=graph_store,
                since=since,
                until=datetime.now(timezone.utc),
            )
            summary = (
                f"Watcher: {watcher_result.trendy_words_processed} trendy, "
                f"{watcher_result.data_leaks_processed} leaks, "
                f"{watcher_result.dns_twisted_processed} twisted, "
                f"{watcher_result.sites_processed} sites"
            )
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"Watcher: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"Watcher: FAILED ({exc})"

    def _pull_filesystem() -> str:
        import pathlib

        sid = _make_sub("filesystem_scan", "Filesystem scan")
        dirs = settings.watched_folders_list
        valid_dirs = [d for d in dirs if pathlib.Path(d).is_dir()]
        if not valid_dirs:
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress="Skipped (no watched folders)",
                finished_at=datetime.utcnow().isoformat(),
            )
            return "Scan: skipped (no watched folders)"
        try:
            exts = set(e.strip().lower() for e in extensions.split(","))
            files: List[str] = []
            for d in valid_dirs:
                root = pathlib.Path(d)
                for p in root.rglob("*"):
                    if p.is_file() and p.suffix.lower() in exts:
                        files.append(str(p))
            files.sort()

            queued = 0
            stix_ok = 0
            aikg_ok = 0
            scan_errors: List[str] = []

            for i, filepath in enumerate(files):
                fname = os.path.basename(filepath)
                try:
                    if (
                        os.path.getsize(filepath)
                        > settings.max_document_size_mb * 1024 * 1024
                    ):
                        scan_errors.append(
                            f"{fname}: exceeds {settings.max_document_size_mb}MB limit"
                        )
                        continue
                    with open(filepath, "rb") as f:
                        raw = f.read()
                    if len(raw) < 10:
                        continue
                    if filepath.lower().endswith(".json") and is_stix_bundle(raw):
                        try:
                            bundle = parse_stix_file(raw, fname)
                            ingest_stix_bundle(
                                bundle, graph_store, source_uri=f"file://{filepath}"
                            )
                            stix_ok += 1
                        except Exception as exc:
                            scan_errors.append(f"{fname}: STIX: {exc}")
                        continue
                    if filepath.lower().endswith(".json"):
                        try:
                            triples = parse_aikg_file(raw, fname)
                            ingest_aikg_triples(
                                triples,
                                graph_store,
                                source_uri=f"file://{filepath}",
                                include_inferred=settings.aikg_import_include_inferred,
                                min_inferred_confidence=settings.aikg_import_min_inferred_confidence,
                                allow_via_predicates=settings.aikg_import_allow_via_predicates,
                            )
                            aikg_ok += 1
                            continue
                        except ValueError:
                            pass
                    text = extract_text(raw, fname)
                    if len(text.strip()) < 50:
                        continue
                    run_id = str(uuid4())
                    run = ExtractionRun(
                        run_id=run_id,
                        started_at=datetime.utcnow(),
                        model=settings.ollama_model,
                        prompt_version=settings.prompt_version,
                        params={
                            "chunk_size": settings.chunk_size,
                            "chunk_overlap": settings.chunk_overlap,
                        },
                        status="pending",
                        error=None,
                    )
                    run_store.create_run(
                        run,
                        f"file://{filepath}",
                        text,
                        {"filename": fname, "path": filepath, "size": len(raw)},
                    )
                    queued += 1
                except Exception as exc:
                    scan_errors.append(f"{fname}: {exc}")
                if (i + 1) % 25 == 0:
                    task_manager.update(
                        sid,
                        progress=f"Scan: {i+1}/{len(files)} processed, {queued} queued",
                    )

            summary = f"Scan: {queued} queued, {stix_ok} STIX, {aikg_ok} AIKG, {len(scan_errors)} errors"
            task_manager.update(
                sid,
                status=TaskStatus.COMPLETED,
                progress=summary,
                finished_at=datetime.utcnow().isoformat(),
            )
            return summary
        except Exception as exc:
            task_manager.update(
                sid,
                status=TaskStatus.FAILED,
                error=str(exc),
                progress=f"Scan: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"Scan: FAILED ({exc})"

    def _run_all():
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="connector") as pool:
            futures: Dict[str, Future] = {
                "feedly": pool.submit(_pull_feedly),
                "opencti": pool.submit(_pull_opencti),
                "rss": pool.submit(_pull_rss),
                "gvm": pool.submit(_pull_gvm),
                "watcher": pool.submit(_pull_watcher),
                "filesystem": pool.submit(_pull_filesystem),
            }
            total_connectors = len(futures)
            summaries: List[str] = []
            errors: List[str] = []
            for name, fut in futures.items():
                try:
                    result = fut.result()
                    summaries.append(result)
                except Exception as exc:
                    summaries.append(f"{name}: FAILED ({exc})")
                    errors.append(f"{name}: {exc}")
                done = sum(1 for f in futures.values() if f.done())
                task_manager.update(
                    task.id, progress=f"{done}/{total_connectors} connectors done"
                )

            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress="Done: " + " | ".join(summaries),
                detail={
                    "summaries": summaries,
                    "errors": errors[:50],
                    "sub_tasks": sub_ids,
                },
                finished_at=datetime.utcnow().isoformat(),
            )

    async def _run():
        import asyncio

        try:
            await asyncio.to_thread(_run_all)
        except Exception as exc:
            task_manager.update(
                task.id,
                status=TaskStatus.FAILED,
                error=str(exc),
                finished_at=datetime.utcnow().isoformat(),
            )

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running", "sub_tasks": sub_ids}


# ── Backfill ─────────────────────────────────────────────────────


@router.post("/api/backfill")
async def start_backfill(
    source: str = Query(
        default="all",
        pattern="^(all|feedly|opencti)$",
        description="all, feedly, or opencti",
    ),
    reset: bool = Query(
        default=False, description="Wipe checkpoints and restart from beginning"
    ),
):
    """Kick off a full historical backfill as a background task."""
    from ...backfill import CheckpointStore, run_backfill

    es_client = getattr(graph_store, "client", None)
    if es_client is None:
        raise HTTPException(
            status_code=501, detail="Backfill requires Elasticsearch backend"
        )

    sources = [source] if source != "all" else ["all"]
    task = task_manager.create("backfill", {"sources": sources, "reset": reset})
    task_manager.update(
        task.id, status=TaskStatus.RUNNING, progress="Starting backfill..."
    )

    def _run_sync():
        try:
            checkpoints = CheckpointStore(es_client, settings.elastic_index_prefix)
            results = run_backfill(
                settings,
                graph_store,
                run_store,
                checkpoints,
                sources=sources,
                reset=reset,
                progress_cb=lambda msg: task_manager.update(task.id, progress=msg),
            )
            task_manager.update(
                task.id,
                status=TaskStatus.COMPLETED,
                progress="Backfill complete",
                detail=results,
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


@router.get("/api/backfill/status")
def backfill_status():
    """Return current checkpoint state for all backfill sources."""
    from ...backfill import CheckpointStore, get_backfill_status

    es_client = getattr(graph_store, "client", None)
    if es_client is None:
        raise HTTPException(
            status_code=501, detail="Backfill requires Elasticsearch backend"
        )
    checkpoints = CheckpointStore(es_client, settings.elastic_index_prefix)
    return get_backfill_status(checkpoints)
