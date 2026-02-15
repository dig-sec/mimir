"""Shared helpers used across multiple route sub-modules.

Provides settings/store singletons, datetime parsing, entity resolution,
connector client factories, worker-status helpers, and file-type utilities.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from ...config import get_settings
from ...storage.factory import (
    create_graph_store,
    create_metrics_store,
    create_run_store,
)

# ── Singletons ──────────────────────────────────────────────────

settings = get_settings()
graph_store = create_graph_store(settings)
run_store = create_run_store(settings)
metrics_store = create_metrics_store(settings)

_TIMELINE_INTERVALS = {"day", "week", "month", "quarter", "year"}


# ── Datetime helpers ────────────────────────────────────────────


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
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


def parse_window_bounds(
    since: Optional[str],
    until: Optional[str],
) -> tuple[Optional[datetime], Optional[datetime]]:
    if not since or not until:
        return None, None
    since_dt = parse_iso_datetime(since if "T" in since else since + "T00:00:00Z")
    until_dt = parse_iso_datetime(until if "T" in until else until + "T23:59:59Z")
    if not since_dt or not until_dt:
        raise HTTPException(status_code=400, detail="Invalid since/until date format")
    return since_dt, until_dt


def bucket_start(dt: datetime, interval: str) -> datetime:
    dt = to_utc(dt)
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


# ── Entity resolution ──────────────────────────────────────────


def resolve_entity(seed_id: Optional[str], seed_name: Optional[str]):
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


def resolve_path_entity(
    entity_id: Optional[str], entity_name: Optional[str], label: str
) -> str:
    """Resolve an entity by ID or name search, returning its ID."""
    if entity_id:
        entity = graph_store.get_entity(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail=f"{label} entity not found")
        return entity.id
    if entity_name:
        matches = graph_store.search_entities(entity_name)
        if not matches:
            raise HTTPException(status_code=404, detail=f"{label} entity not found")
        return matches[0].id
    raise HTTPException(status_code=400, detail=f"{label}_id or {label}_name required")


def resolve_subgraph(
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


# ── Connector client factories ─────────────────────────────────


def get_opencti_client():
    """Get an OpenCTI client if configured."""
    from ...opencti.client import OpenCTIClient

    if not settings.opencti_url or not settings.opencti_token:
        return None
    return OpenCTIClient(settings.opencti_url, settings.opencti_token)


def get_elastic_connector_client(*, allow_disabled: bool = False):
    """Get an Elasticsearch source client if connector hosts are configured."""
    from ...elastic_source import ElasticsearchSourceClient

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


# ── File-type helpers ──────────────────────────────────────────


def extract_text(raw: bytes, filename: str) -> str:
    """Extract plain text from raw file bytes, with PDF support."""
    if filename.lower().endswith(".pdf"):
        import fitz  # pymupdf

        doc = fitz.open(stream=raw, filetype="pdf")
        pages = [page.get_text() for page in doc]
        doc.close()
        return "\n\n".join(pages)
    return raw.decode("utf-8", errors="replace")


def is_stix_bundle(raw: bytes) -> bool:
    """Quick check if raw bytes look like a STIX 2.1 JSON bundle."""
    try:
        head = raw[:200].decode("utf-8", errors="replace")
        return '"type"' in head and '"bundle"' in head
    except Exception:
        return False


# ── Worker status helpers ──────────────────────────────────────


def worker_specs() -> List[Dict[str, Any]]:
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
    gvm_conn_ready = (gvm_conn_type == "unix" and bool(settings.gvm_socket_path)) or (
        gvm_conn_type == "tls" and bool(settings.gvm_host) and settings.gvm_port > 0
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


def build_worker_statuses() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    workers: List[Dict[str, Any]] = []
    for spec in worker_specs():
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
                age_seconds = max(int((now - to_utc(parsed)).total_seconds()), 0)
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
        updated_dt = parse_iso_datetime(updated_at) if updated_at else None
        if updated_dt is None:
            try:
                updated_dt = datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                )
                updated_at = updated_dt.isoformat()
            except Exception:
                updated_dt = None

        records.append(
            {
                "state": str(data.get("state") or "unknown").strip().lower()
                or "unknown",
                "updated_at": updated_at,
                "updated_dt": to_utc(updated_dt) if updated_dt is not None else None,
                "details": (
                    data.get("details") if isinstance(data.get("details"), dict) else {}
                ),
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


def build_cti_summary(
    cti_metrics: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Attach a ``summary`` sub-dict expected by the status-page JS."""
    if not isinstance(cti_metrics, dict):
        return cti_metrics

    top = cti_metrics.get("top_assessments") or []
    active_actors = sum(1 for a in top if a.get("entity_type") == "threat_actor")
    active_malware = sum(1 for a in top if a.get("entity_type") == "malware")

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
