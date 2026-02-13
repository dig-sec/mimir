from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4, uuid5

from ..chunking import chunk_text
from ..config import Settings
from ..dedupe import EntityResolver
from ..llm import OllamaClient, extract_triples
from ..llm.prompts import render_prompt
from ..normalize import normalize_predicate
from ..schemas import Entity, Provenance, Relation
from ..storage.base import GraphStore
from ..storage.run_store import RunStore

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


logger = logging.getLogger(__name__)


def _snippet(text: str, limit: int = 400) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _to_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_epoch_timestamp(value: float) -> Optional[datetime]:
    epoch = float(value)
    if abs(epoch) >= 10_000_000_000:
        epoch /= 1000.0
    elif abs(epoch) < 1_000_000_000:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _parse_datetime_value(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return _to_utc_datetime(value)
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return _parse_epoch_timestamp(float(value))
    text = str(value).strip()
    if not text:
        return None
    if text.replace(".", "", 1).lstrip("+-").isdigit():
        try:
            numeric = float(text)
        except ValueError:
            numeric = None
        if numeric is not None:
            parsed_epoch = _parse_epoch_timestamp(numeric)
            if parsed_epoch:
                return parsed_epoch
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _to_utc_datetime(datetime.fromisoformat(text))
    except ValueError:
        return None


def _resolve_provenance_timestamp(metadata: Optional[dict[str, Any]]) -> datetime:
    if isinstance(metadata, dict):
        for key in (
            "timestamp_value",
            "published",
            "published_at",
            "created_at",
            "updated_at",
            "timestamp",
        ):
            parsed = _parse_datetime_value(metadata.get(key))
            if parsed:
                return parsed
    return datetime.now(timezone.utc)


def _infer_is_a_relations(relations: list[Relation]) -> list[Relation]:
    is_a = [r for r in relations if r.predicate == "is_a"]
    if len(is_a) < 2:
        return []
    outgoing: dict[str, list[Relation]] = {}
    for relation in is_a:
        outgoing.setdefault(relation.subject_id, []).append(relation)

    existing = {(r.subject_id, r.predicate, r.object_id) for r in relations}
    inferred: list[Relation] = []
    seen: set[tuple[str, str, str]] = set()
    for first in is_a:
        for second in outgoing.get(first.object_id, []):
            if first.subject_id == second.object_id:
                continue
            triple_key = (first.subject_id, "is_a", second.object_id)
            if triple_key in existing or triple_key in seen:
                continue
            confidence = min(first.confidence, second.confidence) * 0.9
            inferred.append(
                Relation(
                    id=str(uuid4()),
                    subject_id=first.subject_id,
                    predicate="is_a",
                    object_id=second.object_id,
                    confidence=confidence,
                    attrs={"origin": "inferred", "rule": "is_a_transitive"},
                )
            )
            seen.add(triple_key)
    return inferred


def _build_cooccurrence_relations(
    entities: list[Entity],
    max_entities: int,
) -> list[Relation]:
    if max_entities <= 1:
        return []
    unique = {entity.id: entity for entity in entities}
    if len(unique) < 2:
        return []
    ordered = sorted(unique.values(), key=lambda e: e.id)
    if len(ordered) > max_entities:
        ordered = ordered[:max_entities]
    relations: list[Relation] = []
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            subject = ordered[i]
            obj = ordered[j]
            relations.append(
                Relation(
                    id=str(uuid4()),
                    subject_id=subject.id,
                    predicate="co_occurs_with",
                    object_id=obj.id,
                    confidence=0.1,
                    attrs={
                        "origin": "cooccurrence",
                        "co_occurrence_count": 1,
                    },
                )
            )
    return relations


async def process_run(
    run_id: str,
    graph_store: GraphStore,
    run_store: RunStore,
    settings: Settings,
    client: Optional[OllamaClient] = None,
) -> None:
    doc = run_store.get_document(run_id)
    if not doc:
        raise RuntimeError(f"No document for run {run_id}")

    source_uri = doc["source_uri"]
    text = doc["text"]
    metadata = doc.get("metadata") if isinstance(doc, dict) else None
    provenance_timestamp = _resolve_provenance_timestamp(metadata)

    chunks = chunk_text(
        text,
        source_uri=source_uri,
        max_chars=settings.chunk_size,
        overlap=settings.chunk_overlap,
    )
    # Cap chunks per run to avoid a single huge document blocking the queue
    if settings.max_chunks_per_run and len(chunks) > settings.max_chunks_per_run:
        logger.info(
            "Run %s: capping %d chunks to %d",
            run_id,
            len(chunks),
            settings.max_chunks_per_run,
        )
        chunks = chunks[: settings.max_chunks_per_run]
    run_store.store_chunks(run_id, chunks)

    resolver = EntityResolver(graph_store)

    owned_client = False
    if client is None:
        client = OllamaClient(settings.ollama_base_url, settings.ollama_model)
        owned_client = True

    try:
        for chunk in chunks:
            prompt = render_prompt("extract_triples.jinja2", chunk_text=chunk.text)
            raw = await client.generate(prompt)
            triples = extract_triples(raw)
            chunk_entities: list[Entity] = []
            extracted_relations: list[Relation] = []
            snippet = _snippet(chunk.text)
            for triple in triples:
                predicate = normalize_predicate(triple.predicate)
                if not predicate:
                    continue
                subject = resolver.resolve(triple.subject, triple.subject_type)
                obj = resolver.resolve(triple.object, triple.object_type)
                chunk_entities.extend([subject, obj])
                relation = Relation(
                    id=str(uuid4()),
                    subject_id=subject.id,
                    predicate=predicate,
                    object_id=obj.id,
                    confidence=triple.confidence,
                    attrs={"origin": "extracted"},
                )
                extracted_relations.append(relation)
                stored_relations = graph_store.upsert_relations([relation])
                stored_relation = stored_relations[0]
                provenance = Provenance(
                    provenance_id=_det_prov_id(
                        source_uri=chunk.source_uri,
                        relation_id=stored_relation.id,
                        model=settings.ollama_model,
                        chunk_id=chunk.chunk_id,
                        start_offset=chunk.start_offset,
                        end_offset=chunk.end_offset,
                        snippet=snippet,
                    ),
                    source_uri=chunk.source_uri,
                    chunk_id=chunk.chunk_id,
                    start_offset=chunk.start_offset,
                    end_offset=chunk.end_offset,
                    snippet=snippet,
                    extraction_run_id=run_id,
                    model=settings.ollama_model,
                    prompt_version=settings.prompt_version,
                    timestamp=provenance_timestamp,
                )
                graph_store.attach_provenance(stored_relation.id, provenance)
            if settings.enable_inference and extracted_relations:
                inferred = _infer_is_a_relations(extracted_relations)
                if inferred:
                    stored_inferred = graph_store.upsert_relations(inferred)
                    for stored_relation in stored_inferred:
                        provenance = Provenance(
                            provenance_id=_det_prov_id(
                                source_uri=chunk.source_uri,
                                relation_id=stored_relation.id,
                                model=settings.ollama_model,
                                chunk_id=chunk.chunk_id,
                                start_offset=chunk.start_offset,
                                end_offset=chunk.end_offset,
                                snippet=snippet,
                            ),
                            source_uri=chunk.source_uri,
                            chunk_id=chunk.chunk_id,
                            start_offset=chunk.start_offset,
                            end_offset=chunk.end_offset,
                            snippet=snippet,
                            extraction_run_id=run_id,
                            model=settings.ollama_model,
                            prompt_version=settings.prompt_version,
                            timestamp=provenance_timestamp,
                        )
                        graph_store.attach_provenance(stored_relation.id, provenance)
            if settings.enable_cooccurrence and chunk_entities:
                co_relations = _build_cooccurrence_relations(
                    chunk_entities, settings.cooccurrence_max_entities
                )
                if co_relations:
                    stored = graph_store.upsert_relations(co_relations)
                    for stored_relation in stored:
                        provenance = Provenance(
                            provenance_id=_det_prov_id(
                                source_uri=chunk.source_uri,
                                relation_id=stored_relation.id,
                                model=settings.ollama_model,
                                chunk_id=chunk.chunk_id,
                                start_offset=chunk.start_offset,
                                end_offset=chunk.end_offset,
                                snippet=snippet,
                            ),
                            source_uri=chunk.source_uri,
                            chunk_id=chunk.chunk_id,
                            start_offset=chunk.start_offset,
                            end_offset=chunk.end_offset,
                            snippet=snippet,
                            extraction_run_id=run_id,
                            model=settings.ollama_model,
                            prompt_version=settings.prompt_version,
                            timestamp=provenance_timestamp,
                        )
                        graph_store.attach_provenance(stored_relation.id, provenance)
    finally:
        if owned_client:
            await client.aclose()


def run_sync(
    run_id: str,
    graph_store: GraphStore,
    run_store: RunStore,
    settings: Settings,
) -> None:
    asyncio.run(process_run(run_id, graph_store, run_store, settings))
