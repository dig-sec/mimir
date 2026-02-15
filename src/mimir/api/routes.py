from __future__ import annotations

import os
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
import asyncio

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from ..config import get_settings
from ..connectors import sync_feedly_index
from ..connectors.aikg import ingest_aikg_triples, parse_aikg_file
from ..connectors.gvm import sync_gvm
from ..connectors.rss import pull_from_rss_feeds
from ..connectors.watcher import sync_watcher
from ..elastic_source import ElasticsearchSourceClient, pull_from_elasticsearch
from ..export import export_csv_zip, export_graphml, export_json, export_markdown
from ..graph_limits import limit_subgraph
from ..lake import parse_source_uri
from ..opencti.client import OpenCTIClient
from ..opencti.sync import OPENCTI_DEFAULT_ENTITY_TYPES, pull_from_opencti
from ..schemas import (
    ExplainEntityRelation,
    ExplainEntityResponse,
    ExplainResponse,
    ExtractionRun,
    IngestRequest,
    IngestResponse,
    PathResult,
    QueryRequest,
    RunStatusResponse,
    Subgraph,
)
from ..stix.exporter import export_stix_bundle
from ..stix.importer import ingest_stix_bundle, parse_stix_file
from ..storage.factory import create_graph_store, create_metrics_store, create_run_store
from .ask_retrieval import gather_full_context
from .tasks import TaskStatus, task_manager
from .ui import render_root_ui
from .visualize import render_html

settings = get_settings()

graph_store = create_graph_store(settings)
run_store = create_run_store(settings)
metrics_store = create_metrics_store(settings)

router = APIRouter()


_TIMELINE_INTERVALS = {"day", "week", "month", "quarter", "year"}


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _parse_window_bounds(
    since: Optional[str],
    until: Optional[str],
) -> tuple[Optional[datetime], Optional[datetime]]:
    if not since or not until:
        return None, None
    since_dt = _parse_iso_datetime(since if "T" in since else since + "T00:00:00Z")
    until_dt = _parse_iso_datetime(until if "T" in until else until + "T23:59:59Z")
    if not since_dt or not until_dt:
        raise HTTPException(status_code=400, detail="Invalid since/until date format")
    return since_dt, until_dt


def _bucket_start(dt: datetime, interval: str) -> datetime:
    dt = _to_utc(dt)
    if interval == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if interval == "week":
        base = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        return base - timedelta(days=base.weekday())
    if interval == "month":
        return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if interval == "quarter":
        first_month = ((dt.month - 1) // 3) * 3 + 1
        return dt.replace(
            month=first_month, day=1, hour=0, minute=0, second=0, microsecond=0
        )
    return dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)


def _resolve_entity(seed_id: Optional[str], seed_name: Optional[str]):
    if seed_id:
        entity = graph_store.get_entity(seed_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        return entity
    if seed_name:
        matches = graph_store.search_entities(seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        return matches[0]
    raise HTTPException(status_code=400, detail="seed_id or seed_name required")


def _get_opencti_client() -> Optional[OpenCTIClient]:
    """Get an OpenCTI client if configured."""
    if not settings.opencti_url or not settings.opencti_token:
        return None
    return OpenCTIClient(settings.opencti_url, settings.opencti_token)


def _get_elastic_connector_client(
    *,
    allow_disabled: bool = False,
) -> Optional[ElasticsearchSourceClient]:
    """Get an Elasticsearch source client if connector hosts are configured."""
    if not allow_disabled and not settings.elastic_connector_enabled:
        return None
    if not settings.elastic_connector_hosts_list:
        return None
    return ElasticsearchSourceClient(
        hosts=settings.elastic_connector_hosts_list,
        username=settings.elastic_connector_user,
        password=settings.elastic_connector_password,
        verify_certs=settings.elastic_connector_verify_certs,
        timeout=settings.elastic_connector_timeout_seconds,
    )


def _worker_specs() -> List[Dict[str, Any]]:
    all_indices = settings.elastic_connector_indices_list or []
    excluded = set(settings.elastic_worker_exclude_indices_list)
    elastic_indices = [idx for idx in all_indices if idx not in excluded]
    malware_indices = settings.malware_worker_indices_list

    feedly_enabled = (
        settings.elastic_connector_enabled
        and bool(settings.elastic_connector_hosts_list)
        and settings.feedly_worker_interval_minutes > 0
    )
    opencti_enabled = (
        bool(settings.opencti_url)
        and bool(settings.opencti_token)
        and settings.opencti_worker_interval_minutes > 0
    )
    elastic_enabled = (
        settings.elastic_connector_enabled
        and bool(settings.elastic_connector_hosts_list)
        and settings.elastic_worker_interval_minutes > 0
        and bool(elastic_indices)
    )
    malware_enabled = (
        settings.malware_worker_enabled
        and settings.elastic_connector_enabled
        and bool(settings.elastic_connector_hosts_list)
        and settings.malware_worker_interval_minutes > 0
        and bool(malware_indices)
    )
    rss_enabled = (
        settings.rss_worker_enabled
        and settings.rss_worker_interval_minutes > 0
        and bool(settings.rss_worker_feeds_list)
    )
    gvm_conn_type = settings.gvm_connection_type.strip().lower()
    gvm_conn_ready = (
        (gvm_conn_type == "unix" and bool(settings.gvm_socket_path))
        or (
            gvm_conn_type == "tls"
            and bool(settings.gvm_host)
            and settings.gvm_port > 0
        )
    )
    gvm_enabled = (
        settings.gvm_worker_enabled
        and settings.gvm_worker_interval_minutes > 0
        and gvm_conn_ready
    )
    watcher_modules_enabled = any(
        (
            settings.watcher_pull_trendy_words,
            settings.watcher_pull_data_leaks,
            settings.watcher_pull_dns_twisted,
            settings.watcher_pull_site_monitoring,
        )
    )
    watcher_enabled = (
        settings.watcher_worker_enabled
        and settings.watcher_worker_interval_minutes > 0
        and bool(settings.watcher_base_url)
        and watcher_modules_enabled
    )

    return [
        {
            "id": "llm-worker",
            "label": "LLM Extraction",
            "enabled": True,
            "interval_seconds": max(settings.llm_worker_poll_seconds, 1),
            "disabled_reason": "",
        },
        {
            "id": "feedly-worker",
            "label": "Feedly Sync",
            "enabled": feedly_enabled,
            "interval_seconds": max(settings.feedly_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if feedly_enabled
                else "requires connector hosts, connector enabled, and interval > 0"
            ),
        },
        {
            "id": "opencti-worker",
            "label": "OpenCTI Sync",
            "enabled": opencti_enabled,
            "interval_seconds": max(settings.opencti_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if opencti_enabled
                else "requires OPENCTI_URL, OPENCTI_TOKEN, and interval > 0"
            ),
        },
        {
            "id": "elastic-worker",
            "label": "Elasticsearch Source",
            "enabled": elastic_enabled,
            "interval_seconds": max(settings.elastic_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if elastic_enabled
                else (
                    "all configured indices are excluded"
                    if (
                        settings.elastic_connector_enabled
                        and bool(settings.elastic_connector_hosts_list)
                        and settings.elastic_worker_interval_minutes > 0
                        and not elastic_indices
                        and bool(all_indices)
                    )
                    else "requires connector hosts, connector enabled, interval > 0, and non-excluded indices"
                )
            ),
        },
        {
            "id": "malware-worker",
            "label": "Malware Sync",
            "enabled": malware_enabled,
            "interval_seconds": max(settings.malware_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if malware_enabled
                else "requires MALWARE_WORKER_ENABLED=1, connector hosts, connector enabled, interval > 0, and indices"
            ),
        },
        {
            "id": "rss-worker",
            "label": "Public RSS Feeds",
            "enabled": rss_enabled,
            "interval_seconds": max(settings.rss_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if rss_enabled
                else "requires RSS_WORKER_ENABLED=1, RSS_WORKER_INTERVAL_MINUTES>0, and RSS_WORKER_FEEDS"
            ),
        },
        {
            "id": "gvm-worker",
            "label": "GVM Vulnerability Sync",
            "enabled": gvm_enabled,
            "interval_seconds": max(settings.gvm_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if gvm_enabled
                else (
                    "requires GVM_WORKER_ENABLED=1, GVM_WORKER_INTERVAL_MINUTES>0, "
                    "and valid GVM connection settings"
                )
            ),
        },
        {
            "id": "watcher-worker",
            "label": "Watcher Threat Sync",
            "enabled": watcher_enabled,
            "interval_seconds": max(settings.watcher_worker_interval_minutes, 0) * 60,
            "disabled_reason": (
                ""
                if watcher_enabled
                else (
                    "requires WATCHER_WORKER_ENABLED=1, WATCHER_WORKER_INTERVAL_MINUTES>0, "
                    "WATCHER_BASE_URL, and at least one WATCHER_PULL_* module enabled"
                )
            ),
        },
    ]


def _iter_worker_heartbeat_files(worker_id: str) -> List[Path]:
    base = Path(settings.worker_heartbeat_dir).expanduser()
    files: Dict[str, Path] = {}
    for pattern in (f"{worker_id}.json", f"{worker_id}--*.json"):
        for path in base.glob(pattern):
            files[str(path)] = path
    return list(files.values())


def _read_worker_heartbeats(worker_id: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for path in _iter_worker_heartbeat_files(worker_id):
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        payload_worker_id = str(data.get("worker_id") or "").strip()
        if payload_worker_id and payload_worker_id != worker_id:
            continue

        updated_at = str(data.get("updated_at") or "").strip() or None
        updated_dt = _parse_iso_datetime(updated_at) if updated_at else None
        if updated_dt is None:
            try:
                updated_dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
                updated_at = updated_dt.isoformat()
            except Exception:
                updated_dt = None

        records.append(
            {
                "state": str(data.get("state") or "unknown").strip().lower() or "unknown",
                "updated_at": updated_at,
                "updated_dt": _to_utc(updated_dt) if updated_dt is not None else None,
                "details": data.get("details") if isinstance(data.get("details"), dict) else {},
                "pid": data.get("pid"),
                "hostname": data.get("hostname"),
                "instance_id": data.get("instance_id"),
                "path": str(path),
            }
        )

    records.sort(
        key=lambda item: (
            item["updated_dt"] is not None,
            item["updated_dt"] or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return records


def _worker_health_for_state(state: str) -> str:
    normalized = (state or "").strip().lower()
    if normalized in {"running", "sleeping"}:
        return "ok"
    if normalized in {"starting", "unknown"}:
        return "pending"
    if normalized in {"error"}:
        return "err"
    if normalized in {"disabled", "stopped", "stale"}:
        return "warn"
    return "pending"


def _build_worker_statuses() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    workers: List[Dict[str, Any]] = []
    for spec in _worker_specs():
        worker_id = str(spec["id"])
        enabled = bool(spec["enabled"])
        interval_seconds = int(spec.get("interval_seconds") or 0)
        stale_after_seconds = (
            max(interval_seconds * 3, 90) if interval_seconds > 0 else 90
        )
        heartbeats = _read_worker_heartbeats(worker_id)

        state = "disabled" if not enabled else "unknown"
        updated_at = None
        age_seconds = None
        details: Dict[str, Any] = {}

        if heartbeats:
            freshest = heartbeats[0]
            updated_at = freshest.get("updated_at")
            parsed = freshest.get("updated_dt")
            if isinstance(parsed, datetime):
                age_seconds = max(int((now - _to_utc(parsed)).total_seconds()), 0)
            details = dict(freshest.get("details") or {})
            details["pid"] = freshest.get("pid")
            details["hostname"] = freshest.get("hostname")
            details["instance_id"] = freshest.get("instance_id")
            details["replicas"] = len(heartbeats)
            if enabled:
                state = str(freshest.get("state") or state).strip().lower() or state
            else:
                details["last_reported_state"] = (
                    str(freshest.get("state") or "").strip().lower() or "unknown"
                )

        if enabled and age_seconds is not None and age_seconds > stale_after_seconds:
            state = "stale"

        workers.append(
            {
                "id": worker_id,
                "label": spec.get("label", worker_id),
                "enabled": enabled,
                "state": state,
                "health": _worker_health_for_state(state),
                "updated_at": updated_at,
                "age_seconds": age_seconds,
                "stale_after_seconds": stale_after_seconds,
                "interval_seconds": interval_seconds,
                "disabled_reason": spec.get("disabled_reason", ""),
                "details": details,
            }
        )
    return workers


@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> str:
    root_path = str(request.scope.get("root_path") or "")
    return render_root_ui(
        root_path=root_path,
        api_base_url=settings.mimir_api_base_url,
        ollama_model=settings.ollama_model,
    )


@router.get("/api/search")
def search_entities(
    q: str = Query(..., min_length=1, max_length=settings.search_query_max_length),
    entity_type: Optional[str] = Query(default=None),
):
    """Search for entities by name."""
    normalized_type = (entity_type or "").strip() or None
    matches = graph_store.search_entities(q, entity_type=normalized_type)
    return [{"id": e.id, "name": e.name, "type": e.type} for e in matches[:50]]


def _extract_text(raw: bytes, filename: str) -> str:
    """Extract plain text from raw file bytes, with PDF support."""
    if filename.lower().endswith(".pdf"):
        import fitz  # pymupdf

        doc = fitz.open(stream=raw, filetype="pdf")
        pages = [page.get_text() for page in doc]
        doc.close()
        return "\n\n".join(pages)
    return raw.decode("utf-8", errors="replace")


def _is_stix_bundle(raw: bytes) -> bool:
    """Quick check if raw bytes look like a STIX 2.1 JSON bundle."""
    try:
        # Only peek at the first 200 bytes to avoid parsing huge files
        head = raw[:200].decode("utf-8", errors="replace")
        return '"type"' in head and '"bundle"' in head
    except Exception:
        return False


@router.post("/api/upload")
async def upload_documents(files: List[UploadFile] = File(...)):
    """Upload documents (text, PDF, STIX JSON, or AIKG triples JSON)."""
    results = []
    max_upload_bytes = settings.max_document_size_mb * 1024 * 1024
    for f in files:
        raw = await f.read(max_upload_bytes + 1)
        filename = f.filename or ""
        if len(raw) > max_upload_bytes:
            results.append(
                {
                    "filename": filename,
                    "status": "error",
                    "error": (
                        f"File exceeds {settings.max_document_size_mb}MB upload limit"
                    ),
                }
            )
            continue

        # ── STIX bundle fast-path: structured import, no LLM needed ──
        if filename.lower().endswith(".json") and _is_stix_bundle(raw):
            try:
                bundle = parse_stix_file(raw, filename)
                stix_result = ingest_stix_bundle(
                    bundle, graph_store, source_uri=f"stix://{filename}"
                )
                results.append(
                    {
                        "filename": filename,
                        "status": "completed",
                        "type": "stix",
                        "entities": stix_result.entities_created,
                        "relations": stix_result.relations_created,
                        "skipped": stix_result.objects_skipped,
                        "errors": stix_result.errors,
                    }
                )
            except ValueError as exc:
                results.append(
                    {
                        "filename": filename,
                        "status": "error",
                        "type": "stix",
                        "error": str(exc),
                    }
                )
            continue

        # ── AIKG triples fast-path: structured import, no LLM needed ──
        if filename.lower().endswith(".json"):
            try:
                triples = parse_aikg_file(raw, filename)
                aikg_result = ingest_aikg_triples(
                    triples,
                    graph_store,
                    source_uri=f"upload://{filename}",
                    include_inferred=settings.aikg_import_include_inferred,
                    min_inferred_confidence=settings.aikg_import_min_inferred_confidence,
                    allow_via_predicates=settings.aikg_import_allow_via_predicates,
                )
                results.append(
                    {
                        "filename": filename,
                        "status": "completed",
                        "type": "aikg",
                        "triples_seen": aikg_result.triples_seen,
                        "triples_imported": aikg_result.triples_imported,
                        "entities": aikg_result.entities_created,
                        "relations": aikg_result.relations_created,
                        "skipped_invalid": aikg_result.skipped_invalid,
                        "skipped_inferred": aikg_result.skipped_inferred,
                        "skipped_low_confidence": aikg_result.skipped_low_confidence,
                        "errors": aikg_result.errors[:20],
                    }
                )
                continue
            except ValueError:
                # Not AIKG JSON; fall through to regular text ingestion.
                pass

        # ── Regular document: enqueue for LLM extraction ──
        text = _extract_text(raw, filename)
        source_uri = f"upload://{filename}"

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
            run, source_uri, text, {"filename": filename, "size": len(raw)}
        )
        results.append({"run_id": run_id, "filename": filename, "status": "pending"})
    return results


@router.get("/api/runs")
def list_runs():
    """List recent extraction runs."""
    runs = run_store.list_recent_runs(limit=50)
    return [
        {
            "run_id": r.run_id,
            "status": r.status,
            "model": r.model,
            "started_at": r.started_at.isoformat(),
        }
        for r in runs
    ]


@router.get("/api/export/stix")
def export_stix(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
):
    """Export a subgraph as a STIX 2.1 JSON bundle."""
    if seed_id:
        seed = seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif seed_name:
        matches = graph_store.search_entities(seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(status_code=400, detail="seed_id or seed_name required")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=depth,
        min_confidence=min_confidence,
    )
    bundle = export_stix_bundle(subgraph)
    return bundle


def _resolve_subgraph(
    seed_id: Optional[str],
    seed_name: Optional[str],
    depth: int,
    min_confidence: float,
    scope: str,
):
    """Resolve a subgraph — either seeded or full DB."""
    if scope == "all":
        return graph_store.get_full_graph(min_confidence=min_confidence)
    if seed_id:
        seed = seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif seed_name:
        matches = graph_store.search_entities(seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(
            status_code=400, detail="seed_id / seed_name required, or set scope=all"
        )
    return graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=depth,
        min_confidence=min_confidence,
    )


@router.get("/api/export/csv")
def export_csv(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export entities & relations as CSV files in a ZIP archive."""
    subgraph = _resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    data = export_csv_zip(subgraph)
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=mimir-export.zip"},
    )


@router.get("/api/export/graphml")
def export_graphml_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as GraphML (Gephi / Cytoscape / yEd)."""
    subgraph = _resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    xml = export_graphml(subgraph)
    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Content-Disposition": "attachment; filename=mimir-export.graphml"
        },
    )


@router.get("/api/export/json")
def export_json_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as a plain JSON knowledge graph."""
    subgraph = _resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    return export_json(subgraph)


@router.get("/api/export/markdown")
def export_markdown_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as a human-readable Markdown report."""
    subgraph = _resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    md = export_markdown(subgraph)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=mimir-export.md"},
    )


# ── POST export: accepts the visible graph inline ───────────────────


@router.post("/api/export/stix")
def post_export_stix(payload: Subgraph):
    """Export a client-provided subgraph as STIX 2.1."""
    bundle = export_stix_bundle(payload)
    return bundle


@router.post("/api/export/csv")
def post_export_csv(payload: Subgraph):
    """Export a client-provided subgraph as CSV ZIP."""
    data = export_csv_zip(payload)
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=mimir-export.zip"},
    )


@router.post("/api/export/graphml")
def post_export_graphml(payload: Subgraph):
    """Export a client-provided subgraph as GraphML."""
    xml = export_graphml(payload)
    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Content-Disposition": "attachment; filename=mimir-export.graphml"
        },
    )


@router.post("/api/export/json")
def post_export_json(payload: Subgraph):
    """Export a client-provided subgraph as plain JSON."""
    return export_json(payload)


@router.post("/api/export/markdown")
def post_export_markdown(payload: Subgraph):
    """Export a client-provided subgraph as Markdown."""
    md = export_markdown(payload)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=mimir-export.md"},
    )


@router.delete("/api/runs")
def delete_all_runs():
    """Delete all runs and associated documents/chunks."""
    count = run_store.delete_all_runs()
    return {"deleted": count}


@router.post("/ingest", response_model=IngestResponse)
def ingest(payload: IngestRequest) -> IngestResponse:
    if len(payload.text) > settings.max_total_chars_per_run:
        raise HTTPException(
            status_code=413,
            detail=(
                f"text exceeds {settings.max_total_chars_per_run} character limit"
            ),
        )
    payload_bytes = len(payload.text.encode("utf-8"))
    if payload_bytes > settings.max_document_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"text exceeds {settings.max_document_size_mb}MB size limit",
        )

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
    run_store.create_run(run, payload.source_uri, payload.text, payload.metadata)
    return IngestResponse(run_id=run_id, status=run.status)


@router.get("/runs/{run_id}", response_model=RunStatusResponse)
def run_status(run_id: str) -> RunStatusResponse:
    run = run_store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunStatusResponse(run=run)


@router.post("/query", response_model=Subgraph)
def query(payload: QueryRequest, response: Response) -> Subgraph:
    if payload.seed_id:
        seed = payload.seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif payload.seed_name:
        matches = graph_store.search_entities(payload.seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(status_code=400, detail="seed_id or seed_name required")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=payload.depth,
        min_confidence=payload.min_confidence,
        source_uri=payload.source_uri,
        since=payload.since,
        until=payload.until,
    )
    capped_subgraph, truncated = limit_subgraph(
        subgraph,
        seed_id=seed,
        max_nodes=(
            payload.max_nodes
            if payload.max_nodes is not None
            else settings.query_max_nodes
        ),
        max_edges=(
            payload.max_edges
            if payload.max_edges is not None
            else settings.query_max_edges
        ),
    )
    if truncated:
        response.headers["X-Mimir-Graph-Truncated"] = "1"
        response.headers["X-Mimir-Original-Nodes"] = str(len(subgraph.nodes))
        response.headers["X-Mimir-Original-Edges"] = str(len(subgraph.edges))
        response.headers["X-Mimir-Limited-Nodes"] = str(len(capped_subgraph.nodes))
        response.headers["X-Mimir-Limited-Edges"] = str(len(capped_subgraph.edges))
    return capped_subgraph


# ── path-finding endpoints ─────────────────────────────────────────────


def _resolve_path_entity(
    entity_id: Optional[str], entity_name: Optional[str], label: str
) -> str:
    """Resolve an entity by ID or name search, returning its ID."""
    if entity_id:
        entity = graph_store.get_entity(entity_id)
        if not entity:
            raise HTTPException(
                status_code=404, detail=f"{label} entity not found"
            )
        return entity.id
    if entity_name:
        matches = graph_store.search_entities(entity_name)
        if not matches:
            raise HTTPException(
                status_code=404, detail=f"{label} entity not found"
            )
        return matches[0].id
    raise HTTPException(
        status_code=400, detail=f"{label}_id or {label}_name required"
    )


@router.get("/path/shortest", response_model=PathResult)
def shortest_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> PathResult:
    """Find the shortest path between two entities (BFS)."""
    src = _resolve_path_entity(source_id, source_name, "source")
    tgt = _resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_shortest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )


@router.get("/path/all", response_model=PathResult)
def all_paths(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=4, ge=1, le=8),
    max_paths: int = Query(default=20, ge=1, le=100),
) -> PathResult:
    """Find all simple paths between two entities (DFS, depth-limited)."""
    src = _resolve_path_entity(source_id, source_name, "source")
    tgt = _resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_all_paths(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
        max_paths=max_paths,
    )


@router.get("/path/longest", response_model=PathResult)
def longest_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> PathResult:
    """Find the longest simple path between two entities."""
    src = _resolve_path_entity(source_id, source_name, "source")
    tgt = _resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_longest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )


@router.get("/path/visualize", response_class=HTMLResponse)
def visualize_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    algorithm: str = Query(default="shortest"),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> HTMLResponse:
    """Visualize a path between two entities in the graph explorer."""
    src = _resolve_path_entity(source_id, source_name, "source")
    tgt = _resolve_path_entity(target_id, target_name, "target")

    if algorithm == "longest":
        result = graph_store.find_longest_path(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )
    elif algorithm == "all":
        result = graph_store.find_all_paths(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )
    else:
        result = graph_store.find_shortest_path(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )

    if not result.paths:
        raise HTTPException(status_code=404, detail="No path found between entities")

    # Merge all paths into a single Subgraph for rendering
    all_nodes: dict[str, any] = {}
    all_edges: dict[str, any] = {}
    path_node_ids: set[str] = set()
    path_edge_ids: set[str] = set()

    for path in result.paths:
        for node in path.nodes:
            all_nodes[node.id] = node
            path_node_ids.add(node.id)
        for edge in path.edges:
            all_edges[edge.id] = edge
            path_edge_ids.add(edge.id)

    from ..schemas import SubgraphEdge, SubgraphNode

    subgraph = Subgraph(
        nodes=list(all_nodes.values()),
        edges=list(all_edges.values()),
    )

    src_entity = graph_store.get_entity(src)
    tgt_entity = graph_store.get_entity(tgt)
    src_label = src_entity.name if src_entity else src
    tgt_label = tgt_entity.name if tgt_entity else tgt
    title = f"Path: {src_label} → {tgt_label} ({algorithm}, {len(result.paths)} path(s))"

    return render_html(subgraph, title=title)


@router.get("/explain", response_model=ExplainResponse | ExplainEntityResponse)
def explain(
    relation_id: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
):
    if relation_id:
        try:
            relation, provenance, runs = graph_store.explain_edge(relation_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Relation not found") from None
        return ExplainResponse(relation=relation, provenance=provenance, runs=runs)
    if entity_id:
        entity = graph_store.get_entity(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Entity not found")
        subgraph = graph_store.get_subgraph(entity_id, depth=1)
        relations = []
        for edge in subgraph.edges[:50]:
            relation, provenance, runs = graph_store.explain_edge(edge.id)
            relations.append(
                ExplainEntityRelation(
                    relation=relation, provenance=provenance, runs=runs
                )
            )
        return ExplainEntityResponse(entity=entity, relations=relations)
    raise HTTPException(status_code=400, detail="relation_id or entity_id required")


@router.get("/visualize", response_class=HTMLResponse)
def visualize(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=1, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
):
    if seed_id:
        seed = seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif seed_name:
        matches = graph_store.search_entities(seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(status_code=400, detail="seed_id or seed_name required")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=depth,
        min_confidence=min_confidence,
        source_uri=source_uri,
        since=since,
        until=until,
    )
    subgraph, _ = limit_subgraph(
        subgraph,
        seed_id=seed,
        max_nodes=settings.query_max_nodes,
        max_edges=settings.query_max_edges,
    )
    title = f"Mimir Graph: {seed_name or seed_id}"
    return render_html(subgraph, title=title)


@router.get("/api/timeline/entity")
def entity_timeline(
    entity_id: Optional[str] = Query(default=None),
    entity_name: Optional[str] = Query(default=None),
    depth: int = Query(default=1, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    interval: str = Query(default="month", pattern="^(day|week|month|quarter|year)$"),
):
    """Show how an entity's connected relations evolve over time."""
    interval = interval.lower()
    if interval not in _TIMELINE_INTERVALS:
        raise HTTPException(
            status_code=400, detail="interval must be day|week|month|quarter|year"
        )

    entity = _resolve_entity(entity_id, entity_name)
    since_utc = _to_utc(since) if since else None
    until_utc = _to_utc(until) if until else None
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="since must be <= until")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=entity.id,
        depth=depth,
        min_confidence=min_confidence,
        source_uri=source_uri,
        since=since,
        until=until,
    )

    buckets: Dict[datetime, Dict[str, object]] = {}
    relation_ids = [edge.id for edge in subgraph.edges]
    relation_timestamps: Dict[str, List[datetime]] = {}
    bulk_ts_loader = getattr(graph_store, "get_relation_provenance_timestamps", None)
    use_bulk_timestamps = callable(bulk_ts_loader)
    if use_bulk_timestamps and relation_ids:
        relation_timestamps = bulk_ts_loader(  # type: ignore[misc]
            relation_ids,
            source_uri=source_uri,
            since=since,
            until=until,
        )

    for edge in subgraph.edges:
        timestamps: List[datetime] = []
        if use_bulk_timestamps:
            timestamps = relation_timestamps.get(edge.id, [])
        else:
            try:
                _, provenance, _ = graph_store.explain_edge(edge.id)
            except KeyError:
                continue
            timestamps = [prov.timestamp for prov in provenance]

        for raw_ts in timestamps:
            ts = _to_utc(raw_ts)
            if since_utc and ts < since_utc:
                continue
            if until_utc and ts > until_utc:
                continue

            bucket_key = _bucket_start(ts, interval)
            if bucket_key not in buckets:
                buckets[bucket_key] = {
                    "relation_ids": set(),
                    "incoming_ids": set(),
                    "outgoing_ids": set(),
                    "evidence_count": 0,
                    "predicates": Counter(),
                }
            bucket = buckets[bucket_key]
            relation_ids = bucket["relation_ids"]
            incoming_ids = bucket["incoming_ids"]
            outgoing_ids = bucket["outgoing_ids"]
            predicates = bucket["predicates"]

            relation_ids.add(edge.id)
            if edge.subject_id == entity.id:
                outgoing_ids.add(edge.id)
            if edge.object_id == entity.id:
                incoming_ids.add(edge.id)
            bucket["evidence_count"] = int(bucket["evidence_count"]) + 1
            predicates[edge.predicate] += 1

    timeline = []
    for bucket_start in sorted(buckets):
        data = buckets[bucket_start]
        predicate_counts = data["predicates"]
        top_predicates = [
            {"predicate": pred, "count": count}
            for pred, count in predicate_counts.most_common(10)
        ]
        timeline.append(
            {
                "bucket_start": bucket_start.isoformat(),
                "relation_count": len(data["relation_ids"]),
                "incoming_relation_count": len(data["incoming_ids"]),
                "outgoing_relation_count": len(data["outgoing_ids"]),
                "evidence_count": int(data["evidence_count"]),
                "top_predicates": top_predicates,
            }
        )

    return {
        "entity": {"id": entity.id, "name": entity.name, "type": entity.type},
        "interval": interval,
        "depth": depth,
        "min_confidence": min_confidence,
        "source_uri": source_uri,
        "since": since_utc.isoformat() if since_utc else None,
        "until": until_utc.isoformat() if until_utc else None,
        "bucket_count": len(timeline),
        "buckets": timeline,
    }


@router.get("/api/timeline/threat-actors")
def threat_actor_timeline(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    interval: str = Query(default="month", pattern="^(day|week|month|quarter|year)$"),
    top_n: int = Query(default=10, ge=1, le=100),
):
    """Aggregate temporal activity for threat actors in a graph scope."""
    interval = interval.lower()
    if interval not in _TIMELINE_INTERVALS:
        raise HTTPException(
            status_code=400, detail="interval must be day|week|month|quarter|year"
        )

    since_utc = _to_utc(since) if since else None
    until_utc = _to_utc(until) if until else None
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="since must be <= until")

    seed_entity = None
    if seed_id or seed_name:
        seed_entity = _resolve_entity(seed_id, seed_name)
        subgraph = graph_store.get_subgraph(
            seed_entity_id=seed_entity.id,
            depth=depth,
            min_confidence=min_confidence,
            source_uri=source_uri,
            since=since,
            until=until,
        )
    else:
        subgraph = graph_store.get_full_graph(min_confidence=min_confidence)

    node_by_id = {node.id: node for node in subgraph.nodes}
    threat_actor_ids = {
        node.id for node in subgraph.nodes if node.type == "threat_actor"
    }

    actor_buckets: Dict[str, Dict[datetime, Dict[str, object]]] = {}
    actor_relation_ids: Dict[str, set[str]] = {}
    actor_evidence_totals: Dict[str, int] = {}
    relation_ids = [edge.id for edge in subgraph.edges]
    relation_timestamps: Dict[str, List[datetime]] = {}
    bulk_ts_loader = getattr(graph_store, "get_relation_provenance_timestamps", None)
    use_bulk_timestamps = callable(bulk_ts_loader)
    if use_bulk_timestamps and relation_ids:
        relation_timestamps = bulk_ts_loader(  # type: ignore[misc]
            relation_ids,
            source_uri=source_uri,
            since=since,
            until=until,
        )

    for edge in subgraph.edges:
        connected_actor_ids: List[str] = []
        if edge.subject_id in threat_actor_ids:
            connected_actor_ids.append(edge.subject_id)
        if edge.object_id in threat_actor_ids and edge.object_id != edge.subject_id:
            connected_actor_ids.append(edge.object_id)
        if not connected_actor_ids:
            continue

        if use_bulk_timestamps:
            timestamps = relation_timestamps.get(edge.id, [])
        else:
            try:
                _, provenance, _ = graph_store.explain_edge(edge.id)
            except KeyError:
                continue
            timestamps = [prov.timestamp for prov in provenance]

        filtered_timestamps: List[datetime] = []
        for raw_ts in timestamps:
            ts = _to_utc(raw_ts)
            if since_utc and ts < since_utc:
                continue
            if until_utc and ts > until_utc:
                continue
            filtered_timestamps.append(ts)

        if not filtered_timestamps:
            continue

        for actor_id in connected_actor_ids:
            actor_relation_ids.setdefault(actor_id, set()).add(edge.id)
            actor_evidence_totals[actor_id] = actor_evidence_totals.get(
                actor_id, 0
            ) + len(filtered_timestamps)
            by_bucket = actor_buckets.setdefault(actor_id, {})
            for ts in filtered_timestamps:
                bucket_key = _bucket_start(ts, interval)
                if bucket_key not in by_bucket:
                    by_bucket[bucket_key] = {
                        "relation_ids": set(),
                        "incoming_ids": set(),
                        "outgoing_ids": set(),
                        "evidence_count": 0,
                        "predicates": Counter(),
                    }
                bucket = by_bucket[bucket_key]
                relation_ids = bucket["relation_ids"]
                incoming_ids = bucket["incoming_ids"]
                outgoing_ids = bucket["outgoing_ids"]
                predicates = bucket["predicates"]

                relation_ids.add(edge.id)
                if edge.subject_id == actor_id:
                    outgoing_ids.add(edge.id)
                if edge.object_id == actor_id:
                    incoming_ids.add(edge.id)
                bucket["evidence_count"] = int(bucket["evidence_count"]) + 1
                predicates[edge.predicate] += 1

    active_actor_ids = [
        actor_id for actor_id in threat_actor_ids if actor_id in actor_relation_ids
    ]
    active_actor_ids.sort(
        key=lambda actor_id: (
            -len(actor_relation_ids.get(actor_id, set())),
            -actor_evidence_totals.get(actor_id, 0),
            (
                node_by_id.get(actor_id).name.lower()
                if actor_id in node_by_id
                else actor_id
            ),
        )
    )

    actors = []
    for actor_id in active_actor_ids[:top_n]:
        actor = node_by_id.get(actor_id)
        buckets = []
        for bucket_start in sorted(actor_buckets.get(actor_id, {})):
            data = actor_buckets[actor_id][bucket_start]
            predicate_counts = data["predicates"]
            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in predicate_counts.most_common(10)
            ]
            buckets.append(
                {
                    "bucket_start": bucket_start.isoformat(),
                    "relation_count": len(data["relation_ids"]),
                    "incoming_relation_count": len(data["incoming_ids"]),
                    "outgoing_relation_count": len(data["outgoing_ids"]),
                    "evidence_count": int(data["evidence_count"]),
                    "top_predicates": top_predicates,
                }
            )

        actors.append(
            {
                "entity": {
                    "id": actor_id,
                    "name": actor.name if actor else actor_id,
                    "type": actor.type if actor else "threat_actor",
                },
                "relation_count": len(actor_relation_ids.get(actor_id, set())),
                "evidence_count": actor_evidence_totals.get(actor_id, 0),
                "bucket_count": len(buckets),
                "buckets": buckets,
            }
        )

    return {
        "seed": (
            {"id": seed_entity.id, "name": seed_entity.name, "type": seed_entity.type}
            if seed_entity
            else None
        ),
        "interval": interval,
        "depth": depth,
        "min_confidence": min_confidence,
        "source_uri": source_uri,
        "since": since_utc.isoformat() if since_utc else None,
        "until": until_utc.isoformat() if until_utc else None,
        "top_n": top_n,
        "actor_count_total": len(threat_actor_ids),
        "actor_count_active": len(active_actor_ids),
        "actor_count_returned": len(actors),
        "actors": actors,
    }


@router.post("/api/opencti/pull")
async def opencti_pull(
    entity_types: List[str] = Query(
        default=list(OPENCTI_DEFAULT_ENTITY_TYPES)
    ),
    max_per_type: int = Query(
        default=0, ge=0, le=10000, description="0 = fetch all (no limit)"
    ),
):
    """Pull entities from OpenCTI as a background task."""
    client = _get_opencti_client()
    if not client:
        raise HTTPException(
            status_code=503,
            detail="OpenCTI not configured (set OPENCTI_URL and OPENCTI_TOKEN env vars)",
        )

    task = task_manager.create(
        "opencti_pull",
        {
            "entity_types": entity_types,
            "max_per_type": max_per_type,
        },
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

    client = _get_elastic_connector_client(allow_disabled=True)
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
                    "Done: "
                    f"{result.runs_queued} queued, "
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
        else datetime(2000, 1, 1, tzinfo=timezone.utc)  # epoch = all time
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
    max_items_per_feed: int = Query(default=settings.rss_worker_max_items_per_feed, ge=1, le=5000),
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
            status_code=400,
            detail="No RSS feeds configured (set RSS_WORKER_FEEDS)",
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
                    "Done: "
                    f"{result.runs_queued} queued, "
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
        {
            "lookback_minutes": lookback_minutes,
            "max_results": max_results,
        },
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
            status_code=503,
            detail="Watcher not configured (set WATCHER_BASE_URL)",
        )

    task = task_manager.create(
        "watcher_pull",
        {
            "lookback_minutes": lookback_minutes,
        },
    )
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
                settings=settings,
                graph_store=graph_store,
                since=since,
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
    """Pull from ALL configured sources concurrently.

    Runs each connector in its own thread:
     - Feedly structured CTI import
     - OpenCTI entity pull (if configured)
     - Public RSS threat feeds (if enabled/configured)
     - GVM/OpenVAS vulnerability findings (if enabled/configured)
     - Watcher threat-intelligence records (if enabled/configured)
     - Filesystem scan (if watched folders configured)

    Each connector gets its own sub-task for independent progress tracking.
    """
    from concurrent.futures import Future, ThreadPoolExecutor

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
        else datetime(2000, 1, 1, tzinfo=timezone.utc)  # epoch = all time
    )

    # Create sub-tasks for each connector
    sub_ids: Dict[str, str] = {}

    def _make_sub(kind: str, label: str) -> str:
        sub = task_manager.create(kind, {"parent": task.id})
        task_manager.update(sub.id, status=TaskStatus.RUNNING, progress=f"{label}...")
        sub_ids[kind] = sub.id
        return sub.id

    # ── Connector worker functions ────────────────────────

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
        opencti_client = _get_opencti_client()
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
            # Align ad-hoc pull-all lookback (minutes) to RSS lookback (hours).
            if lookback_minutes > 0:
                lookback_hours = max(1, (lookback_minutes + 59) // 60)
            else:
                lookback_hours = settings.rss_worker_lookback_hours
            rss_result = pull_from_rss_feeds(
                run_store,
                settings,
                feeds,
                lookback_hours=lookback_hours,
                max_items_per_feed=settings.rss_worker_max_items_per_feed,
                min_text_chars=settings.rss_worker_min_text_chars,
                timeout_seconds=settings.rss_worker_timeout_seconds,
                progress_cb=lambda msg: task_manager.update(sid, progress=f"RSS: {msg}"),
            )
            summary = (
                f"RSS: {rss_result.runs_queued} queued, "
                f"{rss_result.skipped_existing} existing, "
                f"{rss_result.skipped_old} old"
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

            from ..stix.importer import ingest_stix_bundle, parse_stix_file

            queued = 0
            stix_ok = 0
            aikg_ok = 0
            scan_errors: List[str] = []

            for i, filepath in enumerate(files):
                fname = os.path.basename(filepath)
                try:
                    if os.path.getsize(filepath) > settings.max_document_size_mb * 1024 * 1024:
                        scan_errors.append(
                            f"{fname}: exceeds {settings.max_document_size_mb}MB limit"
                        )
                        continue
                    with open(filepath, "rb") as f:
                        raw = f.read()
                    if len(raw) < 10:
                        continue
                    if filepath.lower().endswith(".json") and _is_stix_bundle(raw):
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
                    text = _extract_text(raw, fname)
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

            summary = (
                "Scan: "
                f"{queued} queued, {stix_ok} STIX, {aikg_ok} AIKG, "
                f"{len(scan_errors)} errors"
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
                progress=f"Scan: FAILED ({exc})",
                finished_at=datetime.utcnow().isoformat(),
            )
            return f"Scan: FAILED ({exc})"

    # ── Run all connectors concurrently ───────────────────

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

            # Update parent task as connectors finish
            summaries: List[str] = []
            errors: List[str] = []
            for name, fut in futures.items():
                try:
                    result = fut.result()  # blocks until this connector finishes
                    summaries.append(result)
                except Exception as exc:
                    summaries.append(f"{name}: FAILED ({exc})")
                    errors.append(f"{name}: {exc}")

                # Update parent progress with running status
                done = sum(1 for f in futures.values() if f.done())
                task_manager.update(
                    task.id,
                    progress=f"{done}/{total_connectors} connectors done",
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


@router.post("/api/scan")
async def scan_directory(
    extensions: str = Query(default=".txt,.md,.pdf,.json,.html,.csv,.xml,.yaml,.yml"),
):
    """Scan watched folders recursively and ingest all matching files as a background task."""
    import pathlib

    dirs = settings.watched_folders_list

    if not dirs:
        raise HTTPException(status_code=400, detail="No watched folders configured")

    # Verify at least one dir exists
    valid_dirs = [d for d in dirs if pathlib.Path(d).is_dir()]
    if not valid_dirs:
        raise HTTPException(
            status_code=400,
            detail=f"No watched folders found: {settings.watched_folders}",
        )

    exts = set(e.strip().lower() for e in extensions.split(","))

    task = task_manager.create(
        "filesystem_scan",
        {
            "watched_folders": valid_dirs,
        },
    )
    task_manager.update(
        task.id,
        status=TaskStatus.RUNNING,
        progress="Discovering files...",
    )

    async def _run():
        import asyncio

        await asyncio.to_thread(_scan_files_sync, task.id, valid_dirs, exts)

    def _scan_files_sync(task_id: str, scan_dirs: List[str], extensions: set):
        import pathlib

        # Discover files in thread (can take a while for large dirs)
        task_manager.update(task_id, progress="Discovering files...")
        files: List[str] = []
        for d in scan_dirs:
            root = pathlib.Path(d)
            for p in root.rglob("*"):
                if p.is_file() and p.suffix.lower() in extensions:
                    files.append(str(p))
        files.sort()

        if not files:
            task_manager.update(
                task_id,
                status=TaskStatus.COMPLETED,
                progress="No matching files found",
                finished_at=datetime.utcnow().isoformat(),
            )
            return

        task_manager.update(
            task_id, progress=f"Found {len(files)} files, starting ingestion..."
        )

        from ..stix.importer import ingest_stix_bundle, parse_stix_file

        processed = 0
        stix_ok = 0
        aikg_ok = 0
        queued = 0
        errors = []

        for filepath in files:
            processed += 1
            fname = os.path.basename(filepath)
            try:
                if os.path.getsize(filepath) > settings.max_document_size_mb * 1024 * 1024:
                    errors.append(
                        f"{fname}: exceeds {settings.max_document_size_mb}MB limit"
                    )
                    continue
                with open(filepath, "rb") as f:
                    raw = f.read()

                # Skip empty files
                if len(raw) < 10:
                    continue

                # STIX bundle?
                if filepath.lower().endswith(".json") and _is_stix_bundle(raw):
                    try:
                        bundle = parse_stix_file(raw, fname)
                        ingest_stix_bundle(
                            bundle, graph_store, source_uri=f"file://{filepath}"
                        )
                        stix_ok += 1
                    except Exception as exc:
                        errors.append(f"{fname}: STIX error: {exc}")
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

                # Regular document -> LLM extraction queue
                text = _extract_text(raw, fname)
                if len(text.strip()) < 50:
                    continue

                source_uri = f"file://{filepath}"
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
                    source_uri,
                    text,
                    {"filename": fname, "path": filepath, "size": len(raw)},
                )
                queued += 1

            except Exception as exc:
                errors.append(f"{fname}: {exc}")

            if processed % 25 == 0 or processed == len(files):
                task_manager.update(
                    task_id,
                    progress=(
                        f"Scanned {processed}/{len(files)}: {queued} queued, "
                        f"{stix_ok} STIX, {aikg_ok} AIKG, {len(errors)} errors"
                    ),
                )

        task_manager.update(
            task_id,
            status=TaskStatus.COMPLETED,
            progress=(
                f"Done: {queued} queued for LLM, "
                f"{stix_ok} STIX imported, {aikg_ok} AIKG imported, "
                f"{len(errors)} errors"
            ),
            detail={
                "total_scanned": processed,
                "queued_for_llm": queued,
                "stix_imported": stix_ok,
                "aikg_imported": aikg_ok,
                "errors": errors[:50],
            },
            finished_at=datetime.utcnow().isoformat(),
        )

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


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
    """Run daily metrics rollups (threat actors + PIR + optional CTI) in background."""
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
                    "Threat-actor rollup done "
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
                        "PIR rollup done "
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
        import asyncio

        await asyncio.to_thread(_run_sync)

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}


def _build_cti_summary(
    cti_metrics: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Attach a ``summary`` sub-dict expected by the status-page JS."""
    if not isinstance(cti_metrics, dict):
        return cti_metrics

    top = cti_metrics.get("top_assessments") or []
    active_actors = sum(
        1 for a in top if a.get("entity_type") == "threat_actor"
    )
    active_malware = sum(
        1 for a in top if a.get("entity_type") == "malware"
    )

    level_dist = cti_metrics.get("level_distribution") or {}
    total_docs = sum(int(v) for v in level_dist.values())
    weighted = sum(int(k) * int(v) for k, v in level_dist.items())
    avg_threat_level = round(weighted / total_docs, 1) if total_docs > 0 else None

    cti_metrics["summary"] = {
        "total_assessments": cti_metrics.get("assessments_total") or 0,
        "active_threat_actors": active_actors,
        "active_malware": active_malware,
        "avg_threat_level": avg_threat_level,
    }
    return cti_metrics


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

    # PIR rollup status — lightweight check via the same metrics index
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

    # Determine staleness — distinguish "no data" from truly stale
    metrics_has_data = isinstance(metrics, dict) and (
        (metrics.get("active_actors") or 0) > 0
        or last_rollup_at is not None
    )
    cti_has_data = isinstance(cti_metrics, dict) and (
        (cti_metrics.get("docs_total") or cti_metrics.get("assessments_total") or 0) > 0
        or cti_last_rollup_at is not None
    )
    pir_has_data = pir_last_rollup_at is not None

    is_stale = (
        metrics_error is not None
        or (
            metrics_has_data
            and (
                not last_rollup_dt
                or (
                    rollup_age_seconds is not None
                    and rollup_age_seconds > stale_threshold_seconds
                )
            )
        )
    )
    cti_is_stale = (
        cti_metrics_error is not None
        or (
            cti_has_data
            and (
                not cti_last_rollup_dt
                or (
                    cti_rollup_age_seconds is not None
                    and cti_rollup_age_seconds > stale_threshold_seconds
                )
            )
        )
    )
    pir_is_stale = (
        pir_metrics_error is not None
        or (
            pir_has_data
            and (
                not pir_last_rollup_dt
                or (
                    pir_rollup_age_seconds is not None
                    and pir_rollup_age_seconds > stale_threshold_seconds
                )
            )
        )
    )

    # Entity type breakdown (ES aggregation) - with timeout
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
                    )
                ),
                timeout=3.0  # 3 second timeout for aggregation
            )
            for bucket in (agg_resp.get("aggregations", {}).get("types", {}).get("buckets", [])):
                entity_type_counts[bucket["key"]] = bucket["doc_count"]
        except asyncio.TimeoutError:
            pass  # Timeout - skip aggregation, return empty dict
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
        "cti_metrics": _build_cti_summary(cti_metrics),
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
        "workers": _build_worker_statuses(),
    }


@router.get("/api/data-quality")
def data_quality(
    days: int = Query(default=30, ge=1, le=3650),
    source_uri: Optional[str] = Query(default=None),
):
    """Data quality summary for provenance/relation coverage in Elasticsearch."""
    quality_fn = getattr(graph_store, "get_data_quality_summary", None)
    if not callable(quality_fn):
        raise HTTPException(
            status_code=501,
            detail="Data quality summary is only available on Elasticsearch backend",
        )
    return quality_fn(days=days, source_uri=source_uri)


@router.get("/api/lake/overview")
def lake_overview():
    """Summarize source coverage across queued documents and provenance evidence."""
    run_client = getattr(run_store, "client", None)
    run_indices = getattr(run_store, "indices", None)
    if run_client is None or run_indices is None:
        raise HTTPException(
            status_code=501,
            detail="Lake overview is only available on Elasticsearch backend",
        )
    graph_client = getattr(graph_store, "client", None)
    graph_indices = getattr(graph_store, "indices", None)

    doc_agg_resp = run_client.search(
        index=run_indices.documents,
        size=0,
        aggs={
            "sources": {
                "terms": {
                    "field": "metadata.lake.source.keyword",
                    "size": 64,
                    "missing": "unknown",
                },
                "aggs": {
                    "collections": {
                        "terms": {
                            "field": "metadata.lake.collection.keyword",
                            "size": 256,
                            "missing": "",
                        }
                    }
                },
            }
        },
    )
    total_docs = int(
        run_client.count(index=run_indices.documents, query={"match_all": {}})["count"]
    )
    doc_source_rows = []
    doc_buckets = doc_agg_resp.get("aggregations", {}).get("sources", {}).get("buckets", [])
    for bucket in doc_buckets:
        collections = [
            {"collection": c.get("key", ""), "docs": int(c.get("doc_count", 0))}
            for c in bucket.get("collections", {}).get("buckets", [])
        ]
        doc_source_rows.append(
            {
                "source": str(bucket.get("key", "unknown")),
                "docs": int(bucket.get("doc_count", 0)),
                "collections": collections,
            }
        )
    doc_source_rows.sort(key=lambda row: row["docs"], reverse=True)
    docs_exact = sum(int(bucket.get("doc_count", 0)) for bucket in doc_buckets) == total_docs

    provenance_total = 0
    provenance_source_rows: List[Dict[str, Any]] = []
    provenance_exact = True
    provenance_by_source_collection: Dict[tuple[str, str], int] = {}

    provenance_index = getattr(graph_indices, "provenance", None)
    if graph_client is not None and provenance_index:
        prov_agg_resp = graph_client.search(
            index=provenance_index,
            size=0,
            aggs={
                "source_uris": {
                    "terms": {
                        "field": "source_uri",
                        "size": 2048,
                    }
                }
            },
        )
        provenance_total = int(
            graph_client.count(index=provenance_index, query={"match_all": {}})["count"]
        )
        prov_buckets = (
            prov_agg_resp.get("aggregations", {}).get("source_uris", {}).get("buckets", [])
        )

        for bucket in prov_buckets:
            source_uri = str(bucket.get("key", "") or "")
            parsed = parse_source_uri(source_uri)
            source_key = str(parsed.get("source", "unknown") or "unknown")
            collection_key = str(parsed.get("collection", "") or "")
            key = (source_key, collection_key)
            provenance_by_source_collection[key] = provenance_by_source_collection.get(
                key, 0
            ) + int(bucket.get("doc_count", 0))

        provenance_exact = (
            sum(int(bucket.get("doc_count", 0)) for bucket in prov_buckets) == provenance_total
        )

        prov_grouped: Dict[str, Dict[str, Any]] = {}
        for (source_key, collection_key), count in provenance_by_source_collection.items():
            row = prov_grouped.setdefault(
                source_key,
                {"source": source_key, "provenance_records": 0, "collections": []},
            )
            row["provenance_records"] += count
            row["collections"].append(
                {"collection": collection_key, "provenance_records": count}
            )
        provenance_source_rows = list(prov_grouped.values())
        for row in provenance_source_rows:
            row["collections"].sort(
                key=lambda item: int(item["provenance_records"]), reverse=True
            )
        provenance_source_rows.sort(
            key=lambda item: int(item["provenance_records"]), reverse=True
        )

    combined: Dict[str, Dict[str, Any]] = {}
    for row in doc_source_rows:
        source_key = str(row["source"])
        combined_row = combined.setdefault(
            source_key,
            {
                "source": source_key,
                "docs": 0,
                "provenance_records": 0,
                "collections": {},
            },
        )
        combined_row["docs"] += int(row["docs"])
        for collection in row["collections"]:
            collection_key = str(collection.get("collection", "") or "")
            item = combined_row["collections"].setdefault(
                collection_key,
                {
                    "collection": collection_key,
                    "docs": 0,
                    "provenance_records": 0,
                },
            )
            item["docs"] += int(collection.get("docs", 0))

    for (source_key, collection_key), count in provenance_by_source_collection.items():
        combined_row = combined.setdefault(
            source_key,
            {
                "source": source_key,
                "docs": 0,
                "provenance_records": 0,
                "collections": {},
            },
        )
        combined_row["provenance_records"] += int(count)
        item = combined_row["collections"].setdefault(
            collection_key,
            {
                "collection": collection_key,
                "docs": 0,
                "provenance_records": 0,
            },
        )
        item["provenance_records"] += int(count)

    combined_source_rows: List[Dict[str, Any]] = []
    for source_key, row in combined.items():
        collections = list(row["collections"].values())
        collections.sort(
            key=lambda item: (int(item["docs"]) + int(item["provenance_records"])),
            reverse=True,
        )
        combined_source_rows.append(
            {
                "source": source_key,
                "docs": int(row["docs"]),
                "provenance_records": int(row["provenance_records"]),
                "collections": collections,
            }
        )
    combined_source_rows.sort(
        key=lambda item: (int(item["docs"]) + int(item["provenance_records"])),
        reverse=True,
    )

    return {
        "backend": "elasticsearch",
        "exact": docs_exact and provenance_exact,
        "documents_exact": docs_exact,
        "provenance_exact": provenance_exact,
        "documents_total": total_docs,
        "provenance_total": provenance_total,
        "sources": doc_source_rows,
        "provenance_sources": provenance_source_rows,
        "combined_sources": combined_source_rows,
    }


@router.get("/api/pir/trending")
async def pir_trending(
    days: int = Query(default=7, ge=1, le=90),
    top_n: int = Query(default=10, ge=1, le=50),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """Priority Intelligence Requirements: trending entities for current vs previous window (with timeout)."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    kwargs: dict = {
        "top_n": top_n,
        "source_uri": source_uri,
        "days": days,
        "since": since_dt,
        "until": until_dt,
    }

    pir_metrics_fn = getattr(metrics_store, "get_pir_trending_summary", None)
    if callable(pir_metrics_fn):
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: pir_metrics_fn(**kwargs)
                ),
                timeout=5.0  # 5 second timeout for PIR data
            )
        except asyncio.TimeoutError:
            result = None  # Timeout - fall through to graph store
        except Exception:
            result = None
        
        # If metrics rollup has data, return it; otherwise fall through to graph store.
        if result:
            total_items = sum(
                len(q.get("items", [])) for q in (result or {}).get("questions", [])
            )
            if total_items > 0:
                return result

    # Fallback for backends that do not implement metrics-backed PIR rollups,
    # or when the metrics store has no rolled-up data yet.
    pir_graph_fn = getattr(graph_store, "get_pir_trending_summary", None)
    if callable(pir_graph_fn):
        try:
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: pir_graph_fn(**kwargs)
                ),
                timeout=5.0  # 5 second timeout for graph-based PIR
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail="PIR trending query timeout - dataset too large"
            )

    raise HTTPException(
        status_code=501,
        detail="PIR trending is only available on Elasticsearch backend",
    )


@router.get("/api/cti/overview")
def cti_overview(
    days: int = Query(default=30, ge=1, le=3650),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """CTI overview from daily precomputed CTI assessment metrics."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    overview_fn = getattr(metrics_store, "get_cti_overview", None)
    if not callable(overview_fn):
        raise HTTPException(
            status_code=501,
            detail="CTI overview is only available on Elasticsearch backend",
        )
    return overview_fn(
        days=days,
        source_uri=source_uri,
        since=since_dt,
        until=until_dt,
    )


@router.get("/api/cti/trends")
def cti_trends(
    days: int = Query(default=30, ge=1, le=3650),
    top_n: int = Query(default=10, ge=1, le=50),
    group_by: str = Query(default="activity", pattern="^(activity|domain|actor)$"),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """CTI trends grouped by activity, domain, or actor."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    trends_fn = getattr(metrics_store, "get_cti_trends", None)
    if not callable(trends_fn):
        raise HTTPException(
            status_code=501,
            detail="CTI trends are only available on Elasticsearch backend",
        )
    return trends_fn(
        days=days,
        top_n=top_n,
        group_by=group_by,
        source_uri=source_uri,
        since=since_dt,
        until=until_dt,
    )


@router.get("/api/pir/entity-context")
def pir_entity_context(
    entity_id: str = Query(...),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """Return lightweight context for a PIR entity: attrs, neighbors, sources."""
    entity = graph_store.get_entity(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Get depth-1 subgraph (neighbors)
    subgraph = graph_store.get_subgraph(entity_id, depth=1)

    # Build neighbor summaries grouped by predicate
    neighbors = []
    node_map = {n.id: n for n in subgraph.nodes}
    sources = []
    seen_uris = set()

    for edge in subgraph.edges[:80]:
        other_id = edge.object_id if edge.subject_id == entity_id else edge.subject_id
        other = node_map.get(other_id)
        if not other:
            continue

        # Extract source articles from report neighbors
        if other.type == "report":
            full_entity = graph_store.get_entity(other.id)
            attrs = full_entity.attrs if full_entity else {}
            url = (attrs or {}).get("source_url", "")
            published = (attrs or {}).get("published")
            if url and url not in seen_uris:
                seen_uris.add(url)
                sources.append(
                    {
                        "uri": url,
                        "title": other.name,
                        "timestamp": published,
                    }
                )
            continue  # don't add reports to neighbor list

        neighbors.append(
            {
                "id": other.id,
                "name": other.name,
                "type": other.type,
                "predicate": edge.predicate,
                "confidence": edge.confidence,
            }
        )

    # Sort neighbors by confidence desc
    neighbors.sort(key=lambda n: -n["confidence"])

    # Filter sources by date window when provided
    if since or until:
        filtered_sources = []
        for s in sources:
            ts = s.get("timestamp")
            if not ts:
                continue  # skip undated sources when a window is specified
            ts_str = str(ts)[:10]  # YYYY-MM-DD prefix
            if since and ts_str < since[:10]:
                continue
            if until and ts_str > until[:10]:
                continue
            filtered_sources.append(s)
        sources = filtered_sources

    # Sort sources newest first
    sources.sort(key=lambda s: s.get("timestamp") or "", reverse=True)

    return {
        "entity": {
            "id": entity.id,
            "name": entity.name,
            "type": entity.type,
            "attrs": entity.attrs or {},
        },
        "neighbors": neighbors[:30],
        "sources": sources[:15],
    }


@router.post("/api/recover-stale-runs")
def recover_stale_runs():
    """Reset runs stuck in 'running' back to 'pending'."""
    count = run_store.recover_stale_runs()
    return {"recovered": count}


@router.get("/api/watched-folders")
async def get_watched_folders():
    """Return configured watched folders and their file counts (with timeout)."""
    import pathlib

    def count_files_in_dir(d: str) -> int:
        """Count files in directory with hard limit to prevent hanging."""
        try:
            root = pathlib.Path(d)
            if not root.is_dir():
                return 0
            count = 0
            for _ in root.rglob("*"):
                if _.is_file():
                    count += 1
                    if count > 10000:  # Hard limit to prevent excessive scanning
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
            # Use executor with 2s timeout per directory
            try:
                count = await asyncio.wait_for(
                    loop.run_in_executor(executor, count_files_in_dir, d),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                count = None  # Timeout - return None
            
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


# ── Backfill ──────────────────────────────────────────────────


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
    from ..backfill import CheckpointStore, run_backfill

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
    """Return the current checkpoint state for all backfill sources."""
    from ..backfill import CheckpointStore, get_backfill_status

    es_client = getattr(graph_store, "client", None)
    if es_client is None:
        raise HTTPException(
            status_code=501, detail="Backfill requires Elasticsearch backend"
        )

    checkpoints = CheckpointStore(es_client, settings.elastic_index_prefix)
    return get_backfill_status(checkpoints)


# ── Ask (LLM-powered Q&A over the knowledge graph) ───────────


@router.post("/api/ask")
async def ask_question(request: Request):
    """Ask a natural-language question about the knowledge graph.

    Uses Ollama (phi4) to synthesize an answer from graph context.
    Streams the response token-by-token via SSE.
    """
    import json as _json

    import httpx

    from ..llm.prompts import render_prompt

    body = await request.json()
    question = (body.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    if len(question) > 4000:
        raise HTTPException(status_code=413, detail="question exceeds 4000 characters")

    # ── 1. Gather context from the knowledge graph ──────────────
    context, search_terms = gather_full_context(
        question, graph_store, run_store=run_store,
    )

    # ── 2. Render prompt with gathered context ──────────────────
    prompt = render_prompt(
        "ask_knowledge_graph.jinja2",
        question=question,
        entities=context["entities"],
        relations=context["relations"],
        provenance=context["provenance"],
        chunks=context.get("chunks", []),
        stats=context["stats"],
    )

    # ── 3. Stream response from Ollama ──────────────────────────
    async def _stream_response():
        # Send context summary first so the UI can show sources
        sources_event = {
            "type": "sources",
            "entities_found": len(context["entities"]),
            "relations_found": len(context["relations"]),
            "provenance_found": len(context["provenance"]),
            "chunks_found": len(context.get("chunks", [])),
            "entities": context["entities"][:10],
            "search_terms": search_terms[:10],
        }
        yield f"data: {_json.dumps(sources_event)}\n\n"

        try:
            async with httpx.AsyncClient(
                base_url=settings.ollama_base_url,
                timeout=httpx.Timeout(settings.ollama_timeout_seconds, connect=10.0),
            ) as client:
                async with client.stream(
                    "POST",
                    "/api/generate",
                    json={
                        "model": settings.ollama_model,
                        "prompt": prompt,
                        "stream": True,
                    },
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = _json.loads(line)
                            token = chunk.get("response", "")
                            if token:
                                yield f"data: {_json.dumps({'type': 'token', 'content': token})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {_json.dumps({'type': 'done'})}\n\n"
                        except _json.JSONDecodeError:
                            continue
        except httpx.ConnectError:
            yield f"data: {_json.dumps({'type': 'error', 'message': 'Cannot connect to Ollama. Is it running?'})}\n\n"
        except httpx.TimeoutException:
            yield f"data: {_json.dumps({'type': 'error', 'message': 'Ollama request timed out.'})}\n\n"
        except Exception as exc:
            import logging as _logging
            _logging.getLogger(__name__).exception("Ask endpoint error")
            yield f"data: {_json.dumps({'type': 'error', 'message': 'An internal error occurred while generating the answer.'})}\n\n"

    return StreamingResponse(
        _stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
