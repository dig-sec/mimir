"""Sync from OpenCTI into Wellspring.

All functions are synchronous — designed to run in a background thread.
Entities are processed page-by-page (streaming) to keep memory constant.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4, uuid5

from ..dedupe import EntityResolver
from ..normalize import normalize_predicate
from ..schemas import ExtractionRun, Provenance, Relation
from ..storage.base import GraphStore
from .client import OpenCTIClient

logger = logging.getLogger(__name__)

_NS_PROVENANCE = UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")


def _det_prov_id(
    *,
    source_uri: str,
    relation_id: str,
    model: str,
    chunk_id: str,
    start_offset: int,
    end_offset: int,
    snippet: str,
) -> str:
    snippet_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()
    material = (
        f"{source_uri}|{relation_id}|{model}|{chunk_id}|"
        f"{start_offset}|{end_offset}|{snippet_hash}"
    )
    return str(uuid5(_NS_PROVENANCE, material))


# OpenCTI entity_type → Wellspring entity type
_TYPE_MAP: Dict[str, str] = {
    "Malware": "malware",
    "Threat-Actor": "threat_actor",
    "Threat-Actor-Group": "threat_actor",
    "Threat-Actor-Individual": "threat_actor",
    "Attack-Pattern": "attack_pattern",
    "Tool": "tool",
    "Vulnerability": "vulnerability",
    "Campaign": "campaign",
    "Intrusion-Set": "threat_actor",
    "Indicator": "indicator",
    "Infrastructure": "infrastructure",
    "Course-Of-Action": "mitigation",
    "Report": "report",
}


@dataclass
class SyncResult:
    """Summary of a sync operation."""

    entities_pulled: int = 0
    relations_pulled: int = 0
    reports_queued: int = 0
    errors: List[str] = field(default_factory=list)


def pull_from_opencti(
    opencti: OpenCTIClient,
    graph_store: GraphStore,
    entity_types: List[str],
    max_per_type: int = 0,
    run_store: Any = None,
    settings: Any = None,
    progress_cb: Any = None,
) -> SyncResult:
    """Pull entities from OpenCTI and import into Wellspring.

    Processes entities page-by-page via streaming iterators so memory
    stays constant regardless of how many entities OpenCTI has.
    """
    result = SyncResult()
    resolver = EntityResolver(graph_store)
    sync_run_id = f"opencti-sync-{uuid4()}"

    def _progress(msg: str):
        if progress_cb:
            progress_cb(msg)

    import contextlib

    bulk_ctx = (
        graph_store.bulk_mode()
        if hasattr(graph_store, "bulk_mode")
        else contextlib.nullcontext()
    )

    with bulk_ctx:
        for i, entity_type in enumerate(entity_types, 1):
            _progress(f"[{i}/{len(entity_types)}] Fetching {entity_type}...")
            try:
                if entity_type == "Report":
                    _sync_reports(
                        opencti,
                        graph_store,
                        resolver,
                        result,
                        run_store,
                        settings,
                        _progress,
                        i,
                        len(entity_types),
                        sync_run_id,
                        max_per_type,
                    )
                else:
                    _sync_entity_type(
                        opencti,
                        graph_store,
                        resolver,
                        result,
                        entity_type,
                        _progress,
                        i,
                        len(entity_types),
                        sync_run_id,
                        max_per_type,
                    )
            except Exception as exc:
                logger.warning("Failed to pull %s: %s", entity_type, exc)
                result.errors.append(f"{entity_type}: {exc}")
                continue

    logger.info(
        "Pulled %d entities, %d relations, queued %d reports for LLM (%d errors)",
        result.entities_pulled,
        result.relations_pulled,
        result.reports_queued,
        len(result.errors),
    )
    return result


def _sync_entity_type(
    opencti: OpenCTIClient,
    graph_store: GraphStore,
    resolver: EntityResolver,
    result: SyncResult,
    entity_type: str,
    _progress,
    step: int,
    total_steps: int,
    sync_run_id: str,
    max_per_type: int,
):
    """Stream entities of one type page-by-page."""
    count = 0
    ws_type = _TYPE_MAP.get(entity_type, entity_type.lower())

    for ent in opencti.iter_entities(
        entity_type,
        on_page=lambda n: _progress(
            f"[{step}/{total_steps}] {entity_type}: fetched {n} so far, {result.entities_pulled} imported"
        ),
    ):
        if max_per_type and count >= max_per_type:
            break
        count += 1
        entity = resolver.resolve(ent["name"], entity_type=ws_type)

        if ent.get("description"):
            entity.attrs["description"] = ent["description"]
        entity.attrs["opencti_id"] = ent["id"]
        entity.attrs["opencti_type"] = entity_type
        graph_store.upsert_entities([entity])
        result.entities_pulled += 1

        # Process relationships
        for rel in ent.get("relations", []):
            from_name = rel.get("from_name", "")
            to_name = rel.get("to_name", "")
            if not from_name or not to_name:
                continue

            from_ws_type = _TYPE_MAP.get(rel.get("from_type", ""), None)
            to_ws_type = _TYPE_MAP.get(rel.get("to_type", ""), None)

            subj = resolver.resolve(from_name, entity_type=from_ws_type)
            obj = resolver.resolve(to_name, entity_type=to_ws_type)

            predicate = normalize_predicate(rel.get("type", "related-to"))
            if not predicate:
                predicate = "related_to"

            confidence = (rel.get("confidence") or 50) / 100.0

            relation = Relation(
                id=str(uuid4()),
                subject_id=subj.id,
                predicate=predicate,
                object_id=obj.id,
                confidence=min(max(confidence, 0.0), 1.0),
                attrs={
                    "origin": "opencti",
                    "opencti_rel_id": rel.get("id", ""),
                },
            )
            stored_relation = graph_store.upsert_relations([relation])[0]
            source_uri = f"opencti://{entity_type}/{ent.get('id', 'unknown')}"
            chunk_id = str(rel.get("id") or stored_relation.id)
            snippet = f"OpenCTI: {from_name} {predicate} {to_name}"
            provenance = Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored_relation.id,
                    model="opencti",
                    chunk_id=chunk_id,
                    start_offset=0,
                    end_offset=0,
                    snippet=snippet,
                ),
                source_uri=source_uri,
                chunk_id=chunk_id,
                start_offset=0,
                end_offset=0,
                snippet=snippet,
                extraction_run_id=sync_run_id,
                model="opencti",
                prompt_version="opencti-sync",
                timestamp=_parse_opencti_datetime(rel.get("timestamp")),
            )
            graph_store.attach_provenance(stored_relation.id, provenance)
            result.relations_pulled += 1

        if count % 50 == 0:
            _progress(
                f"[{step}/{total_steps}] {entity_type}: {count} processed, "
                f"{result.entities_pulled} entities total"
            )

    logger.info("Synced %d %s from OpenCTI", count, entity_type)


def _sync_reports(
    opencti: OpenCTIClient,
    graph_store: GraphStore,
    resolver: EntityResolver,
    result: SyncResult,
    run_store: Any,
    settings: Any,
    _progress,
    step: int,
    total_steps: int,
    sync_run_id: str,
    max_per_type: int,
):
    """Stream reports page-by-page."""
    count = 0

    for rpt in opencti.iter_reports(
        on_page=lambda n: _progress(
            f"[{step}/{total_steps}] Reports: fetched {n} so far"
        ),
    ):
        if max_per_type and count >= max_per_type:
            break
        count += 1

        # Create the report entity
        report_entity = resolver.resolve(rpt["name"], entity_type="report")
        if rpt.get("description"):
            report_entity.attrs["description"] = rpt["description"]
        report_entity.attrs["opencti_id"] = rpt["id"]
        report_entity.attrs["opencti_type"] = "Report"
        if rpt.get("published"):
            report_entity.attrs["published"] = rpt["published"]
        graph_store.upsert_entities([report_entity])
        result.entities_pulled += 1

        # Contained objects → "mentions" edges
        for obj in rpt.get("objects", []):
            ws_type = _TYPE_MAP.get(obj["type"], obj["type"].lower())
            obj_entity = resolver.resolve(obj["name"], entity_type=ws_type)
            obj_entity.attrs["opencti_id"] = obj["id"]
            graph_store.upsert_entities([obj_entity])
            result.entities_pulled += 1

            rel = Relation(
                id=str(uuid4()),
                subject_id=report_entity.id,
                predicate="mentions",
                object_id=obj_entity.id,
                confidence=0.9,
                attrs={"origin": "opencti"},
            )
            stored_relation = graph_store.upsert_relations([rel])[0]
            source_uri = f"opencti://report/{rpt.get('id', 'unknown')}"
            chunk_id = str(obj.get("id") or stored_relation.id)
            snippet = (
                f"OpenCTI report mentions: {report_entity.name} -> {obj_entity.name}"
            )
            provenance = Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored_relation.id,
                    model="opencti",
                    chunk_id=chunk_id,
                    start_offset=0,
                    end_offset=0,
                    snippet=snippet,
                ),
                source_uri=source_uri,
                chunk_id=chunk_id,
                start_offset=0,
                end_offset=0,
                snippet=snippet,
                extraction_run_id=sync_run_id,
                model="opencti",
                prompt_version="opencti-sync",
                timestamp=_parse_opencti_datetime(rpt.get("published")),
            )
            graph_store.attach_provenance(stored_relation.id, provenance)
            result.relations_pulled += 1

        # Explicit relationships within the report
        for rel_data in rpt.get("relations", []):
            from_name = rel_data.get("from_name", "")
            to_name = rel_data.get("to_name", "")
            if not from_name or not to_name:
                continue
            from_ws = _TYPE_MAP.get(rel_data.get("from_type", ""), None)
            to_ws = _TYPE_MAP.get(rel_data.get("to_type", ""), None)
            subj = resolver.resolve(from_name, entity_type=from_ws)
            obj_ent = resolver.resolve(to_name, entity_type=to_ws)
            predicate = normalize_predicate(rel_data["type"])
            if not predicate:
                predicate = "related_to"
            confidence = (rel_data.get("confidence") or 50) / 100.0
            rel = Relation(
                id=str(uuid4()),
                subject_id=subj.id,
                predicate=predicate,
                object_id=obj_ent.id,
                confidence=min(max(confidence, 0.0), 1.0),
                attrs={"origin": "opencti", "opencti_rel_id": rel_data.get("id", "")},
            )
            stored_relation = graph_store.upsert_relations([rel])[0]
            source_uri = f"opencti://report/{rpt.get('id', 'unknown')}"
            chunk_id = str(rel_data.get("id") or stored_relation.id)
            snippet = f"OpenCTI report relation: {from_name} {predicate} {to_name}"
            provenance = Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored_relation.id,
                    model="opencti",
                    chunk_id=chunk_id,
                    start_offset=0,
                    end_offset=0,
                    snippet=snippet,
                ),
                source_uri=source_uri,
                chunk_id=chunk_id,
                start_offset=0,
                end_offset=0,
                snippet=snippet,
                extraction_run_id=sync_run_id,
                model="opencti",
                prompt_version="opencti-sync",
                timestamp=_parse_opencti_datetime(
                    rel_data.get("timestamp") or rpt.get("published")
                ),
            )
            graph_store.attach_provenance(stored_relation.id, provenance)
            result.relations_pulled += 1

        # Queue report text for LLM extraction
        report_text = rpt.get("text", "").strip()
        if report_text and run_store and settings and len(report_text) > 50:
            source_uri = f"opencti://report/{rpt.get('id', 'unknown')}"
            # Deterministic run ID prevents re-queuing unchanged reports
            # every worker cycle while still allowing updated text to requeue.
            dedupe_material = f"{source_uri}|{report_text}"
            run_id = "opencti-report-" + hashlib.sha1(
                dedupe_material.encode("utf-8")
            ).hexdigest()

            if not run_store.get_run(run_id):
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
                    report_text,
                    {
                        "opencti_report": rpt.get("name", ""),
                        "opencti_id": rpt.get("id", ""),
                    },
                )
                result.reports_queued += 1

        if count % 10 == 0:
            _progress(
                f"[{step}/{total_steps}] Reports: {count} processed, "
                f"{result.entities_pulled} entities total"
            )

    logger.info("Synced %d reports from OpenCTI", count)


def _parse_opencti_datetime(value: Optional[Any]) -> datetime:
    if isinstance(value, datetime):
        return value
    if not value:
        return datetime.utcnow()
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.utcnow()
