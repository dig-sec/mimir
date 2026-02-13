from __future__ import annotations

import asyncio
import logging
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, TypeVar
from uuid import UUID, uuid5

from elasticsearch import (
    ApiError,
    ConflictError,
    ConnectionError as ESConnectionError,
    ConnectionTimeout,
    Elasticsearch,
    NotFoundError,
)

from ..normalize import canonical_entity_key
from ..schemas import (
    Chunk,
    Entity,
    ExtractionRun,
    Provenance,
    Relation,
    Subgraph,
    SubgraphEdge,
    SubgraphNode,
)
from .base import GraphStore
from .metrics_store import MetricsStore
from .run_store import RunStore

logger = logging.getLogger(__name__)

# Namespace UUID for deterministic entity/relation IDs
_NS_ENTITY = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
_NS_RELATION = UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")

T = TypeVar("T")


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not value:
        return datetime.utcnow()
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _normalize_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat()
    return value.astimezone(timezone.utc).isoformat()


def _merge_attrs(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if (
            key in merged
            and isinstance(merged[key], (int, float))
            and isinstance(value, (int, float))
        ):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


def _entity_keys(
    name: str, entity_type: Optional[str], aliases: List[str]
) -> List[str]:
    keys = {canonical_entity_key(name, entity_type)}
    for alias in aliases:
        keys.add(canonical_entity_key(alias, entity_type))
    return sorted(k for k in keys if k)


def _deterministic_entity_id(canonical_key: str) -> str:
    """Generate a stable UUID from a canonical entity key.

    Same (name, type) always produces the same ID, so re-ingesting
    the same entity is an update rather than a duplicate insert.
    """
    return str(uuid5(_NS_ENTITY, canonical_key))


def _triple_key(subject_id: str, predicate: str, object_id: str) -> str:
    return f"{subject_id}|{predicate}|{object_id}"


def _deterministic_relation_id(triple_key: str) -> str:
    """Stable UUID from a triple key so relations are idempotent."""
    return str(uuid5(_NS_RELATION, triple_key))


def _create_client(
    hosts: List[str],
    username: Optional[str],
    password: Optional[str],
    verify_certs: bool,
) -> Elasticsearch:
    kwargs: Dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": verify_certs,
        "request_timeout": 60,  # Increased from 30 to 60 for bulk ops
    }
    if username:
        kwargs["basic_auth"] = (username, password or "")
    return Elasticsearch(**kwargs)


def _retry_with_backoff(
    func: Callable[..., T],
    *args,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    **kwargs,
) -> T:
    """Retry a function with exponential backoff for transient ES errors.
    
    Retries on:
    - ApiError with status 429 (too many requests) or 503 (service unavailable)
    - ConnectionError or timeout
    
    Raises immediately on:
    - NotFoundError
    - ConflictError
    - Other exceptions
    """
    delay = initial_delay
    last_exception: Optional[Exception] = None

    for attempt in range(max(max_attempts, 1)):
        try:
            return func(*args, **kwargs)
        except (NotFoundError, ConflictError):
            # Don't retry these
            raise
        except ApiError as exc:
            # Only retry on transient errors
            if exc.status_code not in (429, 503):
                raise
            last_exception = exc
            if attempt < max_attempts - 1:
                logger.debug(
                    "ES request failed with %d (attempt %d/%d), retrying in %.1fs",
                    exc.status_code,
                    attempt + 1,
                    max_attempts,
                    delay,
                )
                import time
                time.sleep(delay)
                delay *= 2  # Exponential backoff
        except (ESConnectionError, ConnectionTimeout, OSError) as exc:
            # Retry on connection/timeout errors only
            last_exception = exc
            if attempt < max_attempts - 1:
                logger.debug(
                    "ES request failed with %s (attempt %d/%d), retrying in %.1fs",
                    type(exc).__name__,
                    attempt + 1,
                    max_attempts,
                    delay,
                )
                import time
                time.sleep(delay)
                delay *= 2

    # All retries exhausted
    if last_exception:
        raise last_exception
    raise RuntimeError(f"Failed after {max_attempts} attempts")


class _ElasticIndices:
    def __init__(self, prefix: str) -> None:
        self.entities = f"{prefix}-entities"
        self.relations = f"{prefix}-relations"
        self.provenance = f"{prefix}-provenance"
        self.relation_provenance = f"{prefix}-relation-provenance"
        self.metrics = f"{prefix}-metrics"
        self.runs = f"{prefix}-runs"
        self.documents = f"{prefix}-documents"
        self.chunks = f"{prefix}-chunks"


class _ElasticBase:
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str],
        password: Optional[str],
        index_prefix: str,
        verify_certs: bool,
    ) -> None:
        if not hosts:
            raise ValueError("At least one Elasticsearch host is required")
        self.client = _create_client(hosts, username, password, verify_certs)
        self.indices = _ElasticIndices(index_prefix)

    def _ensure_index(self, name: str, properties: Dict[str, Any]) -> None:
        if self.client.indices.exists(index=name):
            return
        try:
            self.client.indices.create(
                index=name,
                mappings={"properties": properties},
            )
        except ApiError as exc:
            err = getattr(exc, "error", None)
            if (
                err == "resource_already_exists_exception"
                or "resource_already_exists_exception" in str(exc)
            ):
                return
            raise

    def _iter_search_hits(
        self,
        index: str,
        query: Dict[str, Any],
        sort: List[Dict[str, Any]],
        size: int = 500,
    ) -> Iterator[Dict[str, Any]]:
        normalized_sort: List[Dict[str, Any]] = []
        has_shard_doc = False
        for sort_item in sort:
            if not isinstance(sort_item, dict) or not sort_item:
                continue
            field, spec = next(iter(sort_item.items()))
            if field == "_id":
                field = "_shard_doc"
                spec = "asc"
            if field == "_shard_doc":
                has_shard_doc = True
            normalized_sort.append({field: spec})
        if not normalized_sort:
            normalized_sort = [{"_shard_doc": "asc"}]
            has_shard_doc = True
        if not has_shard_doc:
            normalized_sort.append({"_shard_doc": "asc"})

        search_after: Optional[List[Any]] = None
        while True:
            params: Dict[str, Any] = {
                "index": index,
                "query": query,
                "sort": normalized_sort,
                "size": size,
            }
            if search_after:
                params["search_after"] = search_after
            response = self.client.search(**params)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                yield hit
            if len(hits) < size:
                return
            search_after = hits[-1].get("sort")
            if not search_after:
                return


class ElasticGraphStore(_ElasticBase, GraphStore):
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "mimir",
        verify_certs: bool = True,
    ) -> None:
        super().__init__(hosts, username, password, index_prefix, verify_certs)
        self._refresh: Any = "wait_for"
        self._ensure_indices()

    def bulk_mode(self):
        """Context manager that disables per-write refresh for throughput.

        Writes inside the block use ``refresh=False`` so Elasticsearch
        batches shard refreshes naturally (~1 s interval).  On exit,
        a manual refresh is issued on all graph indices so subsequent
        reads see the new data.

        Usage::

            with graph_store.bulk_mode():
                graph_store.upsert_entities([...])
                graph_store.upsert_relations([...])
        """
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            prev = self._refresh
            self._refresh = False
            try:
                yield
            finally:
                self._refresh = prev
                # Refresh all graph indices so data is immediately searchable
                try:
                    self.client.indices.refresh(
                        index=f"{self.indices.entities},{self.indices.relations},"
                        f"{self.indices.provenance},{self.indices.relation_provenance}"
                    )
                except Exception:
                    pass

        return _ctx()

    def _ensure_indices(self) -> None:
        self._ensure_index(
            self.indices.entities,
            {
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "type": {"type": "keyword"},
                "aliases": {"type": "keyword"},
                "attrs": {
                    "type": "object",
                    "properties": {
                        "origin": {"type": "keyword"},
                        "source_url": {"type": "keyword"},
                        "feed_name": {"type": "keyword"},
                        "published": {"type": "keyword"},
                        "feedly_id": {"type": "keyword"},
                        "mitre_id": {"type": "keyword"},
                        "cvss_score": {"type": "float"},
                        "has_exploit": {"type": "boolean"},
                        "has_patch": {"type": "boolean"},
                        "identity_class": {"type": "keyword"},
                        "ioc_type": {"type": "keyword"},
                        "opencti_id": {"type": "keyword"},
                        "opencti_type": {"type": "keyword"},
                        "description": {"type": "text"},
                    },
                },
                "canonical_key": {"type": "keyword"},
                "keys": {"type": "keyword"},
            },
        )
        self._ensure_index(
            self.indices.relations,
            {
                "subject_id": {"type": "keyword"},
                "predicate": {"type": "keyword"},
                "object_id": {"type": "keyword"},
                "confidence": {"type": "float"},
                "attrs": {
                    "type": "object",
                    "properties": {
                        "origin": {"type": "keyword"},
                        "rule": {"type": "keyword"},
                        "salience": {"type": "float"},
                        "co_occurrence_count": {"type": "integer"},
                        "relationship": {"type": "keyword"},
                        "topic_source": {"type": "keyword"},
                        "ioc_type": {"type": "keyword"},
                        "opencti_rel_id": {"type": "keyword"},
                    },
                },
                "triple_key": {"type": "keyword"},
            },
        )
        self._ensure_index(
            self.indices.provenance,
            {
                "source_uri": {"type": "keyword"},
                "chunk_id": {"type": "keyword"},
                "start_offset": {"type": "integer"},
                "end_offset": {"type": "integer"},
                "snippet": {"type": "text"},
                "extraction_run_id": {"type": "keyword"},
                "model": {"type": "keyword"},
                "prompt_version": {"type": "keyword"},
                "timestamp": {"type": "date"},
            },
        )
        self._ensure_index(
            self.indices.relation_provenance,
            {
                "relation_id": {"type": "keyword"},
                "provenance_id": {"type": "keyword"},
                "source_uri": {"type": "keyword"},
                "extraction_run_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
            },
        )
        self._ensure_index(
            self.indices.runs,
            {
                "started_at": {"type": "date"},
                "document_length": {"type": "integer"},
                "model": {"type": "keyword"},
                "prompt_version": {"type": "keyword"},
                "params": {"type": "object"},
                "status": {"type": "keyword"},
                "error": {"type": "text"},
            },
        )

    def _to_entity(self, entity_id: str, source: Dict[str, Any]) -> Entity:
        return Entity(
            id=entity_id,
            name=source.get("name", ""),
            type=source.get("type"),
            aliases=source.get("aliases") or [],
            attrs=source.get("attrs") or {},
        )

    def _to_relation(self, relation_id: str, source: Dict[str, Any]) -> Relation:
        return Relation(
            id=relation_id,
            subject_id=source["subject_id"],
            predicate=source["predicate"],
            object_id=source["object_id"],
            confidence=float(source.get("confidence", 0.0)),
            attrs=source.get("attrs") or {},
        )

    def _to_provenance(self, provenance_id: str, source: Dict[str, Any]) -> Provenance:
        return Provenance(
            provenance_id=provenance_id,
            source_uri=source["source_uri"],
            chunk_id=source["chunk_id"],
            start_offset=int(source["start_offset"]),
            end_offset=int(source["end_offset"]),
            snippet=source["snippet"],
            extraction_run_id=source["extraction_run_id"],
            model=source["model"],
            prompt_version=source["prompt_version"],
            timestamp=_parse_datetime(source["timestamp"]),
        )

    def _to_run(self, run_id: str, source: Dict[str, Any]) -> ExtractionRun:
        return ExtractionRun(
            run_id=run_id,
            started_at=_parse_datetime(source["started_at"]),
            model=source["model"],
            prompt_version=source["prompt_version"],
            params=source.get("params") or {},
            status=source["status"],
            error=source.get("error"),
        )

    def upsert_entities(self, entities: List[Entity]) -> List[Entity]:
        stored: List[Entity] = []
        for entity in entities:
            canonical = canonical_entity_key(entity.name, entity.type)
            deterministic_id = _deterministic_entity_id(canonical)
            aliases = entity.aliases or []
            hits = (
                self.client.search(
                    index=self.indices.entities,
                    query={"term": {"canonical_key": canonical}},
                    size=10,
                )
                .get("hits", {})
                .get("hits", [])
            )

            entity_id = deterministic_id
            existing_sources: List[Dict[str, Any]] = []
            if hits:
                # Keep legacy IDs stable to avoid breaking existing relation pointers.
                chosen = next(
                    (hit for hit in hits if hit["_id"] == deterministic_id), hits[0]
                )
                entity_id = chosen["_id"]
                existing_sources = [hit["_source"] for hit in hits]

            merged_aliases_set = set(aliases)
            merged_attrs: Dict[str, Any] = {}
            for source in existing_sources:
                merged_aliases_set.update(source.get("aliases") or [])
                merged_attrs.update(source.get("attrs") or {})
            merged_attrs.update(entity.attrs)
            merged_aliases = sorted(merged_aliases_set)

            keys = _entity_keys(entity.name, entity.type, merged_aliases)
            doc = {
                "name": entity.name,
                "type": entity.type,
                "aliases": merged_aliases,
                "attrs": merged_attrs,
                "canonical_key": canonical,
                "keys": keys,
            }
            self.client.index(
                index=self.indices.entities,
                id=entity_id,
                document=doc,
                refresh=self._refresh,
            )
            stored.append(
                Entity(
                    id=entity_id,
                    name=entity.name,
                    type=entity.type,
                    aliases=merged_aliases,
                    attrs=merged_attrs,
                )
            )
        return stored

    def upsert_relations(self, relations: List[Relation]) -> List[Relation]:
        stored: List[Relation] = []
        for relation in relations:
            key = _triple_key(
                relation.subject_id, relation.predicate, relation.object_id
            )
            deterministic_id = _deterministic_relation_id(key)
            hits = (
                self.client.search(
                    index=self.indices.relations,
                    query={"term": {"triple_key": key}},
                    size=10,
                )
                .get("hits", {})
                .get("hits", [])
            )

            relation_id = deterministic_id
            existing_sources: List[Dict[str, Any]] = []
            if hits:
                # Keep legacy IDs stable to avoid breaking existing provenance pointers.
                chosen = next(
                    (hit for hit in hits if hit["_id"] == deterministic_id), hits[0]
                )
                relation_id = chosen["_id"]
                existing_sources = [hit["_source"] for hit in hits]

            confidence = relation.confidence
            merged_attrs: Dict[str, Any] = {}
            for source in existing_sources:
                confidence = max(confidence, float(source.get("confidence", 0.0)))
                merged_attrs = _merge_attrs(merged_attrs, source.get("attrs") or {})
            merged_attrs = _merge_attrs(merged_attrs, relation.attrs)

            doc = {
                "subject_id": relation.subject_id,
                "predicate": relation.predicate,
                "object_id": relation.object_id,
                "confidence": confidence,
                "attrs": merged_attrs,
                "triple_key": key,
            }
            self.client.index(
                index=self.indices.relations,
                id=relation_id,
                document=doc,
                refresh=self._refresh,
            )
            stored.append(
                Relation(
                    id=relation_id,
                    subject_id=relation.subject_id,
                    predicate=relation.predicate,
                    object_id=relation.object_id,
                    confidence=confidence,
                    attrs=merged_attrs,
                )
            )
        return stored

    def attach_provenance(self, relation_id: str, provenance: Provenance) -> None:
        provenance_doc = {
            "source_uri": provenance.source_uri,
            "chunk_id": provenance.chunk_id,
            "start_offset": provenance.start_offset,
            "end_offset": provenance.end_offset,
            "snippet": provenance.snippet,
            "extraction_run_id": provenance.extraction_run_id,
            "model": provenance.model,
            "prompt_version": provenance.prompt_version,
            "timestamp": provenance.timestamp.isoformat(),
        }
        try:
            self.client.create(
                index=self.indices.provenance,
                id=provenance.provenance_id,
                document=provenance_doc,
                refresh=self._refresh,
            )
        except ConflictError:
            pass

        relation_provenance_id = f"{relation_id}:{provenance.provenance_id}"
        mapping_doc = {
            "relation_id": relation_id,
            "provenance_id": provenance.provenance_id,
            "source_uri": provenance.source_uri,
            "extraction_run_id": provenance.extraction_run_id,
            "timestamp": provenance.timestamp.isoformat(),
        }
        try:
            self.client.create(
                index=self.indices.relation_provenance,
                id=relation_provenance_id,
                document=mapping_doc,
                refresh=self._refresh,
            )
        except ConflictError:
            pass

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        try:
            doc = self.client.get(index=self.indices.entities, id=entity_id)
        except NotFoundError:
            return None
        return self._to_entity(doc["_id"], doc["_source"])

    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        canonical_key: Optional[str] = None,
    ) -> List[Entity]:
        if canonical_key:
            filters: List[Dict[str, Any]] = [{"term": {"keys": canonical_key}}]
            if entity_type:
                filters.append({"term": {"type": entity_type}})
            response = self.client.search(
                index=self.indices.entities,
                query={"bool": {"filter": filters}},
                size=50,
            )
            hits = response.get("hits", {}).get("hits", [])
            return [self._to_entity(hit["_id"], hit["_source"]) for hit in hits]

        if not query:
            return []

        normalized_query = query.strip()
        if not normalized_query:
            return []
        wildcard_value = (
            normalized_query.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("?", "\\?")
            + "*"
        )
        bool_query: Dict[str, Any] = {
            "should": [
                {
                    "match_phrase_prefix": {
                        "name": {
                            "query": normalized_query,
                            "max_expansions": 20,
                        }
                    }
                },
                {
                    "wildcard": {
                        "name.keyword": {
                            "value": wildcard_value,
                            "case_insensitive": True,
                        }
                    }
                },
                {
                    "match": {
                        "name": {
                            "query": normalized_query,
                            "operator": "and",
                        }
                    }
                },
            ]
        }
        bool_query["minimum_should_match"] = 1
        if entity_type:
            bool_query["filter"] = [{"term": {"type": entity_type}}]
        response = self.client.search(
            index=self.indices.entities,
            query={"bool": bool_query},
            size=50,
        )
        hits = response.get("hits", {}).get("hits", [])
        return [self._to_entity(hit["_id"], hit["_source"]) for hit in hits]

    def _fetch_entities_by_ids(self, ids: Iterable[str]) -> List[Entity]:
        id_list = list(ids)
        if not id_list:
            return []
        documents = self.client.mget(index=self.indices.entities, ids=id_list).get(
            "docs", []
        )
        entities: List[Entity] = []
        for doc in documents:
            if not doc.get("found"):
                continue
            entities.append(self._to_entity(doc["_id"], doc["_source"]))
        return entities

    def get_relation_provenance_timestamps(
        self,
        relation_ids: Iterable[str],
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, List[datetime]]:
        relation_id_list = list(
            dict.fromkeys(
                str(relation_id) for relation_id in relation_ids if relation_id
            )
        )
        if not relation_id_list:
            return {}

        since_value = _normalize_datetime(since)
        until_value = _normalize_datetime(until)
        timestamps_by_relation: Dict[str, List[datetime]] = {}

        chunk_size = 500
        for i in range(0, len(relation_id_list), chunk_size):
            id_chunk = relation_id_list[i : i + chunk_size]
            filters: List[Dict[str, Any]] = [
                {"terms": {"relation_id.keyword": id_chunk}}
            ]
            if source_uri:
                filters.append({"term": {"source_uri.keyword": source_uri}})
            if since_value or until_value:
                range_filter: Dict[str, Any] = {}
                if since_value:
                    range_filter["gte"] = since_value
                if until_value:
                    range_filter["lte"] = until_value
                filters.append({"range": {"timestamp": range_filter}})

            for hit in self._iter_search_hits(
                self.indices.relation_provenance,
                query={"bool": {"filter": filters}},
                sort=[{"timestamp": "asc"}, {"_id": "asc"}],
                size=1000,
            ):
                source = hit.get("_source") or {}
                relation_id = str(source.get("relation_id", ""))
                if not relation_id:
                    continue
                timestamp_raw = source.get("timestamp")
                if not timestamp_raw:
                    continue
                timestamps_by_relation.setdefault(relation_id, []).append(
                    _parse_datetime(timestamp_raw)
                )

        return timestamps_by_relation

    def _fetch_relations(
        self,
        entity_ids: Iterable[str],
        min_confidence: float,
        source_uri: Optional[str],
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> List[Relation]:
        ids = list(entity_ids)
        if not ids:
            return []

        relation_query: Dict[str, Any] = {
            "bool": {
                "should": [
                    {"terms": {"subject_id": ids}},
                    {"terms": {"object_id": ids}},
                ],
                "minimum_should_match": 1,
                "filter": [{"range": {"confidence": {"gte": min_confidence}}}],
            }
        }
        hits = list(
            self._iter_search_hits(
                self.indices.relations,
                query=relation_query,
                sort=[{"_id": "asc"}],
            )
        )
        relations = [self._to_relation(hit["_id"], hit["_source"]) for hit in hits]
        if not source_uri and not since and not until:
            return relations

        relation_ids = [relation.id for relation in relations]
        allowed_timestamps = self.get_relation_provenance_timestamps(
            relation_ids,
            source_uri=source_uri,
            since=since,
            until=until,
        )
        allowed_ids = set(allowed_timestamps.keys())
        return [relation for relation in relations if relation.id in allowed_ids]

    def get_subgraph(
        self,
        seed_entity_id: str,
        depth: int = 1,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Subgraph:
        visited = {seed_entity_id}
        frontier = {seed_entity_id}
        edges: Dict[str, Relation] = {}

        for _ in range(max(depth, 0)):
            if not frontier:
                break
            new_frontier: set[str] = set()
            relations = self._fetch_relations(
                frontier,
                min_confidence,
                source_uri,
                since,
                until,
            )
            for relation in relations:
                edges[relation.id] = relation
                if relation.subject_id not in visited:
                    new_frontier.add(relation.subject_id)
                if relation.object_id not in visited:
                    new_frontier.add(relation.object_id)
            visited.update(new_frontier)
            frontier = new_frontier

        nodes = self._fetch_entities_by_ids(visited)
        return Subgraph(
            nodes=[
                SubgraphNode(id=node.id, name=node.name, type=node.type)
                for node in nodes
            ],
            edges=[
                SubgraphEdge(
                    id=edge.id,
                    subject_id=edge.subject_id,
                    predicate=edge.predicate,
                    object_id=edge.object_id,
                    confidence=edge.confidence,
                    attrs=edge.attrs,
                )
                for edge in edges.values()
            ],
        )

    def get_full_graph(self, min_confidence: float = 0.0) -> Subgraph:
        entity_hits = self._iter_search_hits(
            self.indices.entities,
            query={"match_all": {}},
            sort=[{"_id": "asc"}],
        )
        relation_hits = self._iter_search_hits(
            self.indices.relations,
            query={"range": {"confidence": {"gte": min_confidence}}},
            sort=[{"_id": "asc"}],
        )
        entities = [self._to_entity(hit["_id"], hit["_source"]) for hit in entity_hits]
        relations = [
            self._to_relation(hit["_id"], hit["_source"]) for hit in relation_hits
        ]
        return Subgraph(
            nodes=[SubgraphNode(id=e.id, name=e.name, type=e.type) for e in entities],
            edges=[
                SubgraphEdge(
                    id=r.id,
                    subject_id=r.subject_id,
                    predicate=r.predicate,
                    object_id=r.object_id,
                    confidence=r.confidence,
                    attrs=r.attrs,
                )
                for r in relations
            ],
        )

    def explain_edge(
        self,
        relation_id: str,
    ) -> Tuple[Relation, List[Provenance], List[ExtractionRun]]:
        try:
            relation_doc = self.client.get(index=self.indices.relations, id=relation_id)
        except NotFoundError as exc:
            raise KeyError(f"Relation not found: {relation_id}") from exc
        relation = self._to_relation(relation_doc["_id"], relation_doc["_source"])

        mapping_hits = list(
            self._iter_search_hits(
                self.indices.relation_provenance,
                query={"term": {"relation_id.keyword": relation_id}},
                sort=[{"timestamp": "desc"}, {"_id": "asc"}],
            )
        )
        provenance_ids = [hit["_source"]["provenance_id"] for hit in mapping_hits]
        provenance_docs = []
        for i in range(0, len(provenance_ids), 512):
            chunk = provenance_ids[i : i + 512]
            if not chunk:
                continue
            response = self.client.mget(index=self.indices.provenance, ids=chunk)
            provenance_docs.extend(
                doc for doc in response.get("docs", []) if doc.get("found")
            )
        provenance = [
            self._to_provenance(doc["_id"], doc["_source"]) for doc in provenance_docs
        ]
        provenance.sort(key=lambda p: p.timestamp, reverse=True)

        run_ids = sorted({p.extraction_run_id for p in provenance})
        run_docs = []
        for i in range(0, len(run_ids), 512):
            chunk = run_ids[i : i + 512]
            if not chunk:
                continue
            response = self.client.mget(index=self.indices.runs, ids=chunk)
            run_docs.extend(doc for doc in response.get("docs", []) if doc.get("found"))
        runs = [self._to_run(doc["_id"], doc["_source"]) for doc in run_docs]
        return relation, provenance, runs

    def count_entities(self) -> int:
        return int(
            self.client.count(index=self.indices.entities, query={"match_all": {}})[
                "count"
            ]
        )

    def count_relations(self) -> int:
        return int(
            self.client.count(index=self.indices.relations, query={"match_all": {}})[
                "count"
            ]
        )

    def _count_relation_evidence_window(
        self,
        *,
        since: datetime,
        until: datetime,
        source_uri: Optional[str] = None,
        max_buckets: int = 10000,
    ) -> Counter[str]:
        filters: List[Dict[str, Any]] = [
            {
                "range": {
                    "timestamp": {
                        "gte": since.isoformat(),
                        "lt": until.isoformat(),
                    }
                }
            }
        ]
        if source_uri:
            filters.append({"term": {"source_uri.keyword": source_uri}})

        counts: Counter[str] = Counter()
        # Use terms aggregation – top N relation_ids by doc count (single request)
        response = self.client.search(
            index=self.indices.relation_provenance,
            query={"bool": {"filter": filters}},
            size=0,
            aggs={
                "by_relation": {
                    "terms": {
                        "field": "relation_id.keyword",
                        "size": max_buckets,
                    }
                }
            },
        )
        for bucket in (
            response.get("aggregations", {}).get("by_relation", {}).get("buckets", [])
        ):
            relation_id = str(bucket["key"])
            if relation_id:
                counts[relation_id] = int(bucket["doc_count"])
        return counts

    def _count_relation_evidence_window_with_daily(
        self,
        *,
        since: datetime,
        until: datetime,
        source_uri: Optional[str] = None,
        max_buckets: int = 10000,
    ) -> Dict[str, Dict[str, Any]]:
        """Count provenance per relation_id with daily breakdowns.

        Returns {relation_id: {"total": int, "daily": {iso_date: count}}}

        Step 1: terms agg to find top relation_ids by doc_count.
        Step 2: filter to those IDs + date_histogram for daily breakdown.
        This avoids exceeding ES max_buckets.
        """
        filters: List[Dict[str, Any]] = [
            {
                "range": {
                    "timestamp": {
                        "gte": since.isoformat(),
                        "lt": until.isoformat(),
                    }
                }
            }
        ]
        if source_uri:
            filters.append({"term": {"source_uri.keyword": source_uri}})

        # Step 1: Get top relation_ids by count (no sub-agg)
        response = self.client.search(
            index=self.indices.relation_provenance,
            query={"bool": {"filter": filters}},
            size=0,
            aggs={
                "by_relation": {
                    "terms": {
                        "field": "relation_id.keyword",
                        "size": max_buckets,
                    }
                }
            },
        )
        top_relations: Dict[str, int] = {}
        for bucket in (
            response.get("aggregations", {}).get("by_relation", {}).get("buckets", [])
        ):
            rid = str(bucket["key"])
            if rid:
                top_relations[rid] = int(bucket["doc_count"])

        if not top_relations:
            return {}

        # Step 2: Get daily breakdown only for the top relation_ids
        # Process in chunks to avoid overly large terms filter
        result: Dict[str, Dict[str, Any]] = {}
        rel_ids = list(top_relations.keys())
        chunk_size = 500  # keep sub-agg bucket count manageable
        for i in range(0, len(rel_ids), chunk_size):
            chunk = rel_ids[i : i + chunk_size]
            daily_filters = list(filters) + [{"terms": {"relation_id.keyword": chunk}}]
            daily_response = self.client.search(
                index=self.indices.relation_provenance,
                query={"bool": {"filter": daily_filters}},
                size=0,
                aggs={
                    "by_relation": {
                        "terms": {
                            "field": "relation_id.keyword",
                            "size": len(chunk),
                        },
                        "aggs": {
                            "daily": {
                                "date_histogram": {
                                    "field": "timestamp",
                                    "calendar_interval": "day",
                                    "format": "yyyy-MM-dd",
                                }
                            }
                        },
                    }
                },
            )
            for bucket in (
                daily_response.get("aggregations", {})
                .get("by_relation", {})
                .get("buckets", [])
            ):
                relation_id = str(bucket["key"])
                if not relation_id:
                    continue
                daily: Dict[str, int] = {}
                for day_bucket in bucket.get("daily", {}).get("buckets", []):
                    day_key = day_bucket.get("key_as_string", "")
                    if day_key:
                        daily[day_key] = int(day_bucket["doc_count"])
                result[relation_id] = {
                    "total": int(bucket["doc_count"]),
                    "daily": daily,
                }

        # Ensure all relations from step 1 are in result (even if daily chunk missed them)
        for rid, total in top_relations.items():
            if rid not in result:
                result[rid] = {"total": total, "daily": {}}

        return result

    def get_pir_trending_summary(
        self,
        *,
        days: int = 7,
        top_n: int = 10,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        top_n = max(1, min(int(top_n), 50))
        now = datetime.now(timezone.utc)

        # Use explicit since/until when provided, else fall back to days-from-now
        if since and until:
            current_since = since
            current_until = until
            days = max(1, int((current_until - current_since).total_seconds() / 86400))
        else:
            days = max(1, int(days))
            current_until = now
            current_since = now - timedelta(days=days)
        previous_since = current_since - timedelta(days=days)

        # Use daily-breakdown counting for current window (needed for sparklines)
        current_daily = self._count_relation_evidence_window_with_daily(
            since=current_since,
            until=current_until,
            source_uri=source_uri,
        )
        current_counts: Counter[str] = Counter(
            {rid: info["total"] for rid, info in current_daily.items()}
        )
        previous_counts = self._count_relation_evidence_window(
            since=previous_since,
            until=current_since,
            source_uri=source_uri,
        )

        relation_ids = sorted(set(current_counts.keys()) | set(previous_counts.keys()))
        relation_map: Dict[str, Relation] = {}
        for i in range(0, len(relation_ids), 512):
            chunk = relation_ids[i : i + 512]
            if not chunk:
                continue
            response = self.client.mget(index=self.indices.relations, ids=chunk)
            for doc in response.get("docs", []):
                if not doc.get("found"):
                    continue
                relation_map[doc["_id"]] = self._to_relation(doc["_id"], doc["_source"])

        entity_ids: set[str] = set()
        for relation in relation_map.values():
            entity_ids.add(relation.subject_id)
            entity_ids.add(relation.object_id)
        entities_by_id = {
            entity.id: entity for entity in self._fetch_entities_by_ids(entity_ids)
        }

        # Build day-bucket keys for the current window
        day_bucket_keys: List[str] = []
        cursor = current_since.replace(hour=0, minute=0, second=0, microsecond=0)
        while cursor < current_until:
            day_bucket_keys.append(cursor.strftime("%Y-%m-%d"))
            cursor += timedelta(days=1)

        def _build_question(entity_type: str, question: str) -> Dict[str, Any]:
            by_entity: Dict[str, Dict[str, Any]] = {}
            for relation_id, relation in relation_map.items():
                current_evidence = int(current_counts.get(relation_id, 0))
                previous_evidence = int(previous_counts.get(relation_id, 0))
                if current_evidence <= 0 and previous_evidence <= 0:
                    continue

                candidate_ids: List[str] = []
                subject = entities_by_id.get(relation.subject_id)
                obj = entities_by_id.get(relation.object_id)
                if subject and subject.type == entity_type:
                    candidate_ids.append(subject.id)
                if obj and obj.type == entity_type and obj.id != relation.subject_id:
                    candidate_ids.append(obj.id)
                if not candidate_ids:
                    continue

                # Get daily breakdown for this relation
                rel_daily = current_daily.get(relation_id, {}).get("daily", {})

                for entity_id in candidate_ids:
                    stat = by_entity.setdefault(
                        entity_id,
                        {
                            "current_evidence": 0,
                            "previous_evidence": 0,
                            "current_relation_ids": set(),
                            "predicate_counts": Counter(),
                            "daily_counts": Counter(),
                        },
                    )
                    stat["current_evidence"] = (
                        int(stat["current_evidence"]) + current_evidence
                    )
                    stat["previous_evidence"] = (
                        int(stat["previous_evidence"]) + previous_evidence
                    )
                    if current_evidence > 0:
                        stat["current_relation_ids"].add(relation_id)
                        stat["predicate_counts"][relation.predicate] += current_evidence
                        for day_key, day_count in rel_daily.items():
                            stat["daily_counts"][day_key] += day_count

            items = []
            for entity_id, stat in by_entity.items():
                if int(stat["current_evidence"]) <= 0:
                    continue
                entity = entities_by_id.get(entity_id)
                if not entity:
                    continue
                current_evidence = int(stat["current_evidence"])
                previous_evidence = int(stat["previous_evidence"])
                delta = current_evidence - previous_evidence
                trend_score = delta / max(previous_evidence, 1)
                top_predicates = [
                    {"predicate": pred, "count": count}
                    for pred, count in stat["predicate_counts"].most_common(5)
                ]
                history = [
                    {
                        "bucket_start": key,
                        "evidence_count": int(stat["daily_counts"].get(key, 0)),
                    }
                    for key in day_bucket_keys
                ]
                items.append(
                    {
                        "entity_id": entity.id,
                        "name": entity.name,
                        "type": entity.type,
                        "current_evidence": current_evidence,
                        "previous_evidence": previous_evidence,
                        "delta_evidence": delta,
                        "trend_score": trend_score,
                        "relation_count_current": len(stat["current_relation_ids"]),
                        "top_predicates": top_predicates,
                        "history": history,
                    }
                )

            items.sort(
                key=lambda item: (
                    -int(item["delta_evidence"]),
                    -int(item["current_evidence"]),
                    str(item["name"]).lower(),
                )
            )
            items = items[:top_n]

            return {
                "id": f"{entity_type}_trending",
                "question": question,
                "entity_type": entity_type,
                "item_count": len(items),
                "items": items,
            }

        return {
            "generated_at": now.isoformat(),
            "source_uri": source_uri,
            "window": {
                "days": days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "compare_window": {
                "days": days,
                "since": previous_since.isoformat(),
                "until": current_since.isoformat(),
            },
            "questions": [
                _build_question("malware", "What malware families are trending?"),
                _build_question(
                    "vulnerability", "Which CVEs / vulnerabilities are trending?"
                ),
                _build_question("threat_actor", "Which threat actors are trending?"),
                _build_question(
                    "attack_pattern", "Which ATT&CK techniques are trending?"
                ),
                _build_question(
                    "infrastructure", "What infrastructure is being targeted?"
                ),
            ],
        }

    def get_data_quality_summary(
        self,
        days: int = 30,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        days = max(int(days), 1)
        now = datetime.utcnow()
        since = now - timedelta(days=days)

        scope_filters: List[Dict[str, Any]] = []
        if source_uri:
            scope_filters.append({"term": {"source_uri.keyword": source_uri}})

        window_filters = list(scope_filters)
        window_filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})
        window_query: Dict[str, Any] = {"bool": {"filter": window_filters}}

        all_time_query: Dict[str, Any]
        if scope_filters:
            all_time_query = {"bool": {"filter": scope_filters}}
        else:
            all_time_query = {"match_all": {}}

        window_aggs = self.client.search(
            index=self.indices.relation_provenance,
            query=window_query,
            size=0,
            aggs={
                "active_relations": {
                    "cardinality": {
                        "field": "relation_id.keyword",
                        "precision_threshold": 40000,
                    }
                },
                "sources": {"cardinality": {"field": "source_uri.keyword"}},
                "latest_event": {"max": {"field": "timestamp"}},
                "earliest_event": {"min": {"field": "timestamp"}},
            },
        ).get("aggregations", {})

        all_time_aggs = self.client.search(
            index=self.indices.relation_provenance,
            query=all_time_query,
            size=0,
            aggs={
                "relations_with_evidence": {
                    "cardinality": {
                        "field": "relation_id.keyword",
                        "precision_threshold": 40000,
                    }
                }
            },
        ).get("aggregations", {})

        evidence_docs_window = int(
            self.client.count(
                index=self.indices.relation_provenance,
                query=window_query,
            )["count"]
        )
        missing_timestamp_query: Dict[str, Any] = {
            "bool": {"must_not": [{"exists": {"field": "timestamp"}}]}
        }
        if scope_filters:
            missing_timestamp_query = {
                "bool": {
                    "filter": scope_filters,
                    "must_not": [{"exists": {"field": "timestamp"}}],
                }
            }
        missing_timestamp_docs = int(
            self.client.count(
                index=self.indices.relation_provenance,
                query=missing_timestamp_query,
            )["count"]
        )

        relations_total = int(
            self.client.count(index=self.indices.relations, query={"match_all": {}})[
                "count"
            ]
        )
        relations_with_evidence_all_time = int(
            all_time_aggs.get("relations_with_evidence", {}).get("value") or 0
        )
        active_relations_window = int(
            window_aggs.get("active_relations", {}).get("value") or 0
        )
        sources_in_window = int(window_aggs.get("sources", {}).get("value") or 0)

        orphan_relations = None
        evidence_coverage = None
        if not source_uri:
            orphan_relations = max(
                relations_total - relations_with_evidence_all_time, 0
            )
            if relations_total > 0:
                evidence_coverage = relations_with_evidence_all_time / relations_total

        return {
            "source_uri": source_uri,
            "window_days": days,
            "window_since": since.isoformat(),
            "generated_at": now.isoformat(),
            "entities_total": int(
                self.client.count(index=self.indices.entities, query={"match_all": {}})[
                    "count"
                ]
            ),
            "relations_total": relations_total,
            "relations_with_evidence_all_time": relations_with_evidence_all_time,
            "active_relations_window": active_relations_window,
            "evidence_docs_window": evidence_docs_window,
            "sources_in_window": sources_in_window,
            "latest_event_at": window_aggs.get("latest_event", {}).get(
                "value_as_string"
            ),
            "earliest_event_at": window_aggs.get("earliest_event", {}).get(
                "value_as_string"
            ),
            "missing_timestamp_docs": missing_timestamp_docs,
            "orphan_relations": orphan_relations,
            "evidence_coverage": evidence_coverage,
        }


class ElasticRunStore(_ElasticBase, RunStore):
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "mimir",
        verify_certs: bool = True,
    ) -> None:
        super().__init__(hosts, username, password, index_prefix, verify_certs)
        self._ensure_indices()

    def _ensure_indices(self) -> None:
        self._ensure_index(
            self.indices.runs,
            {
                "started_at": {"type": "date"},
                "document_length": {"type": "integer"},
                "model": {"type": "keyword"},
                "prompt_version": {"type": "keyword"},
                "params": {"type": "object"},
                "status": {"type": "keyword"},
                "error": {"type": "text"},
            },
        )
        self._ensure_index(
            self.indices.documents,
            {
                "source_uri": {"type": "keyword"},
                "text": {"type": "text"},
                "metadata": {"type": "object"},
            },
        )
        self._ensure_index(
            self.indices.chunks,
            {
                "run_id": {"type": "keyword"},
                "source_uri": {"type": "keyword"},
                "start_offset": {"type": "integer"},
                "end_offset": {"type": "integer"},
                "text": {"type": "text"},
            },
        )

    def _to_run(self, run_id: str, source: Dict[str, Any]) -> ExtractionRun:
        return ExtractionRun(
            run_id=run_id,
            started_at=_parse_datetime(source["started_at"]),
            model=source["model"],
            prompt_version=source["prompt_version"],
            params=source.get("params") or {},
            status=source["status"],
            error=source.get("error"),
        )

    def create_run(
        self,
        run: ExtractionRun,
        source_uri: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.client.index(
            index=self.indices.runs,
            id=run.run_id,
            document={
                "started_at": run.started_at.isoformat(),
                "document_length": len(text),
                "model": run.model,
                "prompt_version": run.prompt_version,
                "params": run.params,
                "status": run.status,
                "error": run.error,
            },
            refresh="wait_for",
        )
        self.client.index(
            index=self.indices.documents,
            id=run.run_id,
            document={
                "source_uri": source_uri,
                "text": text,
                "metadata": metadata or {},
            },
            refresh="wait_for",
        )

    def update_run_status(
        self, run_id: str, status: str, error: Optional[str] = None
    ) -> None:
        self.client.update(
            index=self.indices.runs,
            id=run_id,
            doc={"status": status, "error": error},
            refresh="wait_for",
        )

    def get_run(self, run_id: str) -> Optional[ExtractionRun]:
        try:
            doc = self.client.get(index=self.indices.runs, id=run_id)
        except NotFoundError:
            return None
        return self._to_run(doc["_id"], doc["_source"])

    def recover_stale_runs(self) -> int:
        response = self.client.update_by_query(
            index=self.indices.runs,
            query={"term": {"status": "running"}},
            script={
                "source": "ctx._source.status = params.status; ctx._source.error = null",
                "params": {"status": "pending"},
            },
            refresh=True,
            conflicts="proceed",
        )
        return int(response.get("updated", 0))

    def claim_next_run(self) -> Optional[ExtractionRun]:
        response = self.client.search(
            index=self.indices.runs,
            query={"term": {"status": "pending"}},
            sort=[
                {"document_length": {"order": "asc", "missing": "_last"}},
                {"started_at": "asc"},
            ],
            size=25,
            seq_no_primary_term=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        for hit in hits:
            run_id = hit["_id"]
            try:
                self.client.update(
                    index=self.indices.runs,
                    id=run_id,
                    if_seq_no=hit["_seq_no"],
                    if_primary_term=hit["_primary_term"],
                    doc={"status": "running", "error": None},
                    refresh="wait_for",
                )
                return self._to_run(run_id, hit["_source"])
            except ConflictError:
                continue
        return None

    def get_document(self, run_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.client.get(index=self.indices.documents, id=run_id)
        except NotFoundError:
            return None
        source = doc["_source"]
        return {
            "source_uri": source["source_uri"],
            "text": source["text"],
            "metadata": source.get("metadata") or {},
        }

    def store_chunks(self, run_id: str, chunks: List[Chunk]) -> None:
        for chunk in chunks:
            try:
                self.client.create(
                    index=self.indices.chunks,
                    id=chunk.chunk_id,
                    document={
                        "run_id": run_id,
                        "source_uri": chunk.source_uri,
                        "start_offset": chunk.start_offset,
                        "end_offset": chunk.end_offset,
                        "text": chunk.text,
                    },
                    refresh="wait_for",
                )
            except ConflictError:
                continue

    def get_chunks(self, run_id: str) -> List[Chunk]:
        hits = list(
            self._iter_search_hits(
                self.indices.chunks,
                query={"term": {"run_id": run_id}},
                sort=[{"start_offset": "asc"}, {"_id": "asc"}],
            )
        )
        return [
            Chunk(
                chunk_id=hit["_id"],
                source_uri=hit["_source"]["source_uri"],
                start_offset=int(hit["_source"]["start_offset"]),
                end_offset=int(hit["_source"]["end_offset"]),
                text=hit["_source"]["text"],
            )
            for hit in hits
        ]

    def list_recent_runs(self, limit: int = 50) -> List[ExtractionRun]:
        response = self.client.search(
            index=self.indices.runs,
            query={"match_all": {}},
            sort=[{"started_at": "desc"}],
            size=limit,
        )
        hits = response.get("hits", {}).get("hits", [])
        return [self._to_run(hit["_id"], hit["_source"]) for hit in hits]

    def delete_all_runs(self) -> int:
        count = self.count_runs()
        self.client.delete_by_query(
            index=self.indices.chunks,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        self.client.delete_by_query(
            index=self.indices.documents,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        self.client.delete_by_query(
            index=self.indices.runs,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        return count

    def purge_document_text(self, run_id: str) -> bool:
        """Delete the full document text for a finished run."""
        try:
            self.client.delete(
                index=self.indices.documents,
                id=run_id,
                refresh="wait_for",
            )
            return True
        except NotFoundError:
            return False

    def purge_stale_pending_runs(self, max_age_days: int = 14) -> int:
        """Delete pending runs (and their documents) older than *max_age_days*."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        # Find the stale run IDs so we can also clean up their documents
        stale_query: Dict[str, Any] = {
            "bool": {
                "filter": [
                    {"term": {"status": "pending"}},
                    {"range": {"started_at": {"lt": cutoff}}},
                ]
            }
        }
        # Delete matching documents first
        stale_run_ids: List[str] = []
        for hit in self._iter_search_hits(
            self.indices.runs,
            query=stale_query,
            sort=[{"started_at": "asc"}],
        ):
            stale_run_ids.append(hit["_id"])

        if not stale_run_ids:
            return 0

        # Purge documents and chunks for those runs
        for rid in stale_run_ids:
            try:
                self.client.delete(index=self.indices.documents, id=rid)
            except NotFoundError:
                pass
        self.client.delete_by_query(
            index=self.indices.chunks,
            query={"terms": {"run_id": stale_run_ids}},
            refresh=True,
            conflicts="proceed",
        )

        # Delete the runs themselves
        response = self.client.delete_by_query(
            index=self.indices.runs,
            query=stale_query,
            refresh=True,
            conflicts="proceed",
        )
        return int(response.get("deleted", 0))

    def count_runs(
        self,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        filters: List[Dict[str, Any]] = []
        if status:
            filters.append({"term": {"status": status}})
        if since:
            filters.append({"range": {"started_at": {"gt": since.isoformat()}}})
        if filters:
            query: Dict[str, Any] = {"bool": {"filter": filters}}
        else:
            query = {"match_all": {}}
        response = self.client.count(index=self.indices.runs, query=query)
        return int(response["count"])


class ElasticMetricsStore(_ElasticBase, MetricsStore):
    METRIC_TYPE_DAILY_THREAT_ACTOR = "daily_threat_actor"
    METRIC_TYPE_DAILY_PIR_ENTITY = "daily_pir_entity"
    METRIC_TYPE_DAILY_CTI_ASSESSMENT = "daily_cti_assessment"
    GLOBAL_SCOPE = "__all__"
    PIR_ENTITY_TYPES = (
        "malware",
        "vulnerability",
        "threat_actor",
        "attack_pattern",
        "infrastructure",
    )
    PIR_QUESTIONS = {
        "malware": "What malware families are trending?",
        "vulnerability": "Which CVEs / vulnerabilities are trending?",
        "threat_actor": "Which threat actors are trending?",
        "attack_pattern": "Which ATT&CK techniques are trending?",
        "infrastructure": "What infrastructure is being targeted?",
    }
    CTI_LEVEL_THRESHOLDS = (0.2, 0.4, 0.6, 0.8)
    CTI_ATTRIBUTION_STATES = ("known", "suspected", "possible", "unknown")

    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "mimir",
        verify_certs: bool = True,
        cti_level_thresholds: Optional[List[float]] = None,
    ) -> None:
        super().__init__(hosts, username, password, index_prefix, verify_certs)
        self.cti_level_thresholds = self._normalize_level_thresholds(
            cti_level_thresholds
        )
        self._ensure_indices()

    def _ensure_indices(self) -> None:
        self._ensure_index(
            self.indices.metrics,
            {
                "metric_type": {"type": "keyword"},
                "source_scope": {"type": "keyword"},
                "bucket_start": {"type": "date"},
                "entity_id": {"type": "keyword"},
                "entity_name": {"type": "keyword"},
                "entity_type": {"type": "keyword"},
                "assessment_id": {"type": "keyword"},
                "assessment_name": {"type": "keyword"},
                "assessment_kind": {"type": "keyword"},
                "domain_key": {"type": "keyword"},
                "domain_name": {"type": "keyword"},
                "actor_id": {"type": "keyword"},
                "actor_name": {"type": "keyword"},
                "entity_ids": {"type": "keyword"},
                "relation_count": {"type": "integer"},
                "incoming_relation_count": {"type": "integer"},
                "outgoing_relation_count": {"type": "integer"},
                "evidence_count": {"type": "integer"},
                "threat_domain_score": {"type": "float"},
                "threat_actor_score": {"type": "float"},
                "threat_level_score": {"type": "float"},
                "threat_domain_level": {"type": "integer"},
                "threat_actor_level": {"type": "integer"},
                "threat_level": {"type": "integer"},
                "confidence_score": {"type": "float"},
                "source_reliability": {"type": "keyword"},
                "information_credibility": {"type": "keyword"},
                "attribution_state": {"type": "keyword"},
                "attribution_target_id": {"type": "keyword"},
                "attribution_text": {"type": "text"},
                "mitigation_priority_score": {"type": "float"},
                "top_mitigations": {"type": "object"},
                "decay_half_life_days": {"type": "integer"},
                "top_predicates": {"type": "object"},
                "lookback_days": {"type": "integer"},
                "min_confidence": {"type": "float"},
                "rollup_generated_at": {"type": "date"},
            },
        )

    @staticmethod
    def _bucket_day(ts: datetime) -> datetime:
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)

    def _source_scope(self, source_uri: Optional[str]) -> str:
        return source_uri or self.GLOBAL_SCOPE

    @staticmethod
    def _daily_window_bounds(
        *,
        days: int,
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> Tuple[int, datetime, datetime]:
        now = datetime.now(timezone.utc)
        if since and until:
            current_since = (
                since
                if since.tzinfo is not None
                else since.replace(tzinfo=timezone.utc)
            ).astimezone(timezone.utc)
            current_until = (
                until
                if until.tzinfo is not None
                else until.replace(tzinfo=timezone.utc)
            ).astimezone(timezone.utc)
            if current_since >= current_until:
                current_since = current_until - timedelta(days=1)
            duration_seconds = max(
                int((current_until - current_since).total_seconds()),
                1,
            )
            window_days = max(1, (duration_seconds + 86399) // 86400)
            return window_days, current_since, current_until

        window_days = max(1, int(days))
        current_until = now
        current_since = now - timedelta(days=window_days)
        return window_days, current_since, current_until

    @staticmethod
    def _iter_day_starts(start: datetime, end: datetime) -> List[datetime]:
        cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
        out: List[datetime] = []
        while cursor < end:
            out.append(cursor)
            cursor += timedelta(days=1)
        return out

    @staticmethod
    def _clamp_score(value: float) -> float:
        return max(0.0, min(float(value), 1.0))

    @classmethod
    def _normalize_level_thresholds(
        cls,
        values: Optional[List[float]],
    ) -> Tuple[float, float, float, float]:
        if not values:
            return cls.CTI_LEVEL_THRESHOLDS
        parsed = sorted(
            {
                float(value)
                for value in values
                if isinstance(value, (int, float)) and 0.0 <= float(value) <= 1.0
            }
        )
        if len(parsed) < 4:
            return cls.CTI_LEVEL_THRESHOLDS
        return (parsed[0], parsed[1], parsed[2], parsed[3])

    def _score_to_level(self, score: float) -> int:
        score = self._clamp_score(score)
        thresholds = self.cti_level_thresholds
        if score < thresholds[0]:
            return 1
        if score < thresholds[1]:
            return 2
        if score < thresholds[2]:
            return 3
        if score < thresholds[3]:
            return 4
        return 5

    @staticmethod
    def _infer_domain(
        entity_type: str,
        entity_attrs: Dict[str, Any],
    ) -> Tuple[str, str]:
        for key in ("sector", "industry", "target_sector", "target_industry"):
            value = entity_attrs.get(key)
            if isinstance(value, list):
                value = next(
                    (str(item).strip() for item in value if str(item).strip()),
                    "",
                )
            elif value is None:
                value = ""
            else:
                value = str(value).strip()
            if value:
                normalized = value.lower().replace(" ", "_")
                return f"sector:{normalized}", value
        fallback = entity_type or "unknown"
        return f"type:{fallback}", fallback.replace("_", " ").title()

    @staticmethod
    def _confidence_to_admiralty(confidence_score: float) -> Tuple[str, str]:
        confidence_score = max(0.0, min(float(confidence_score), 1.0))
        if confidence_score >= 0.85:
            return "B", "2"
        if confidence_score >= 0.70:
            return "C", "3"
        if confidence_score >= 0.50:
            return "D", "4"
        return "E", "5"

    @staticmethod
    def _heuristic_mitigations(
        entity_type: str,
        top_predicates: List[Dict[str, Any]],
        base_score: float,
    ) -> List[Dict[str, Any]]:
        names: List[str] = []
        predicates = {str(item.get("predicate") or "") for item in top_predicates}
        if "exploits_vulnerability" in predicates or entity_type == "vulnerability":
            names.extend(
                [
                    "Prioritize patching of exposed systems",
                    "Deploy compensating controls for unpatched assets",
                ]
            )
        if "uses_technique" in predicates or entity_type == "attack_pattern":
            names.extend(
                [
                    "Strengthen detection rules for observed techniques",
                    "Harden endpoint controls and execution policies",
                ]
            )
        if entity_type == "malware":
            names.extend(
                [
                    "Update malware signatures and EDR policies",
                    "Isolate infected hosts and rotate credentials",
                ]
            )
        if entity_type == "infrastructure":
            names.extend(
                [
                    "Block malicious infrastructure indicators",
                    "Enforce egress filtering and DNS monitoring",
                ]
            )
        if entity_type == "threat_actor":
            names.extend(
                [
                    "Increase monitoring on likely actor TTPs",
                    "Review exposed perimeter services",
                ]
            )
        if not names:
            names = [
                "Increase monitoring and triage related activity",
                "Apply preventive controls to exposed attack paths",
            ]
        unique_names: List[str] = []
        for name in names:
            if name not in unique_names:
                unique_names.append(name)
        out: List[Dict[str, Any]] = []
        for idx, name in enumerate(unique_names[:3]):
            score = max(0.0, min(base_score - (idx * 0.08), 1.0))
            out.append(
                {
                    "entity_id": f"heuristic:{entity_type}:{idx + 1}",
                    "name": name,
                    "score": round(score, 4),
                }
            )
        return out

    def rollup_daily_threat_actor_stats(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))

        now = datetime.utcnow()
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        actor_hits = list(
            self._iter_search_hits(
                self.indices.entities,
                query={"term": {"type": "threat_actor"}},
                sort=[{"_id": "asc"}],
            )
        )
        actor_names = {
            hit["_id"]: str(hit["_source"].get("name") or hit["_id"])
            for hit in actor_hits
        }
        actor_ids = set(actor_names.keys())
        if not actor_ids:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "actors_total": 0,
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        relation_meta: Dict[str, Dict[str, Any]] = {}
        actor_id_list = sorted(actor_ids)
        chunk_size = 500
        for i in range(0, len(actor_id_list), chunk_size):
            actor_chunk = actor_id_list[i : i + chunk_size]
            relation_query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"terms": {"subject_id": actor_chunk}},
                        {"terms": {"object_id": actor_chunk}},
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"range": {"confidence": {"gte": min_confidence}}}],
                }
            }
            for hit in self._iter_search_hits(
                self.indices.relations,
                query=relation_query,
                sort=[{"_id": "asc"}],
            ):
                relation_id = hit["_id"]
                source = hit["_source"]
                subject_id = source.get("subject_id")
                object_id = source.get("object_id")
                predicate = source.get("predicate", "related_to")
                roles: List[Tuple[str, str]] = []
                if subject_id in actor_ids:
                    roles.append((subject_id, "outgoing"))
                if object_id in actor_ids:
                    roles.append((object_id, "incoming"))
                if not roles:
                    continue
                relation_meta[relation_id] = {
                    "predicate": predicate,
                    "roles": roles,
                }

        if not relation_meta:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "actors_total": len(actor_ids),
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {"term": {"metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR}},
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        buckets: Dict[Tuple[str, datetime], Dict[str, Any]] = {}
        relation_ids = sorted(relation_meta.keys())
        relation_chunk_size = 500

        for i in range(0, len(relation_ids), relation_chunk_size):
            relation_chunk = relation_ids[i : i + relation_chunk_size]
            filters: List[Dict[str, Any]] = [
                {"terms": {"relation_id.keyword": relation_chunk}},
                {"range": {"timestamp": {"gte": since.isoformat()}}},
            ]
            if source_uri:
                filters.append({"term": {"source_uri.keyword": source_uri}})
            query = {"bool": {"filter": filters}}
            for hit in self._iter_search_hits(
                self.indices.relation_provenance,
                query=query,
                sort=[{"timestamp": "asc"}, {"_id": "asc"}],
                size=1000,
            ):
                source = hit["_source"]
                relation_id = str(source.get("relation_id"))
                if relation_id not in relation_meta:
                    continue
                relation = relation_meta[relation_id]
                ts = _parse_datetime(source.get("timestamp"))
                bucket_day = self._bucket_day(ts)
                for actor_id, direction in relation["roles"]:
                    key = (actor_id, bucket_day)
                    if key not in buckets:
                        buckets[key] = {
                            "relation_ids": set(),
                            "incoming_ids": set(),
                            "outgoing_ids": set(),
                            "evidence_count": 0,
                            "predicates": Counter(),
                        }
                    data = buckets[key]
                    data["relation_ids"].add(relation_id)
                    if direction == "incoming":
                        data["incoming_ids"].add(relation_id)
                    if direction == "outgoing":
                        data["outgoing_ids"].add(relation_id)
                    data["evidence_count"] += 1
                    data["predicates"][relation["predicate"]] += 1

        docs_written = 0
        generated_at = now.isoformat()
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None

        for (actor_id, bucket_day), data in buckets.items():
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day

            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in data["predicates"].most_common(10)
            ]
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_THREAT_ACTOR}:"
                f"{scope}:{bucket_day.date().isoformat()}:{actor_id}"
            )
            self.client.index(
                index=self.indices.metrics,
                id=doc_id,
                document={
                    "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                    "source_scope": scope,
                    "bucket_start": bucket_day.isoformat(),
                    "entity_id": actor_id,
                    "entity_name": actor_names.get(actor_id, actor_id),
                    "relation_count": len(data["relation_ids"]),
                    "incoming_relation_count": len(data["incoming_ids"]),
                    "outgoing_relation_count": len(data["outgoing_ids"]),
                    "evidence_count": int(data["evidence_count"]),
                    "top_predicates": top_predicates,
                    "lookback_days": lookback_days,
                    "min_confidence": min_confidence,
                    "rollup_generated_at": generated_at,
                },
                refresh=False,
            )
            docs_written += 1

        self.client.indices.refresh(index=self.indices.metrics)

        return {
            "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "actors_total": len(actor_ids),
            "relations_considered": len(relation_meta),
            "buckets_written": len(buckets),
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "generated_at": generated_at,
        }

    def rollup_daily_pir_stats(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))

        now = datetime.utcnow()
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        entity_hits = list(
            self._iter_search_hits(
                self.indices.entities,
                query={"terms": {"type": list(self.PIR_ENTITY_TYPES)}},
                sort=[{"_id": "asc"}],
            )
        )
        entity_meta = {
            hit["_id"]: {
                "name": str(hit["_source"].get("name") or hit["_id"]),
                "type": str(hit["_source"].get("type") or "unknown"),
            }
            for hit in entity_hits
        }
        entity_ids = set(entity_meta.keys())
        if not entity_ids:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "entities_total": 0,
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        relation_meta: Dict[str, Dict[str, Any]] = {}
        entity_id_list = sorted(entity_ids)
        chunk_size = 500
        for i in range(0, len(entity_id_list), chunk_size):
            entity_chunk = entity_id_list[i : i + chunk_size]
            relation_query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"terms": {"subject_id": entity_chunk}},
                        {"terms": {"object_id": entity_chunk}},
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"range": {"confidence": {"gte": min_confidence}}}],
                }
            }
            for hit in self._iter_search_hits(
                self.indices.relations,
                query=relation_query,
                sort=[{"_id": "asc"}],
            ):
                relation_id = hit["_id"]
                source = hit["_source"]
                subject_id = source.get("subject_id")
                object_id = source.get("object_id")
                predicate = source.get("predicate", "related_to")
                candidate_entity_ids: List[str] = []
                subject_meta = entity_meta.get(str(subject_id))
                object_meta = entity_meta.get(str(object_id))
                if subject_meta:
                    candidate_entity_ids.append(str(subject_id))
                if object_meta and str(object_id) != str(subject_id):
                    candidate_entity_ids.append(str(object_id))
                if not candidate_entity_ids:
                    continue
                relation_meta[relation_id] = {
                    "predicate": predicate,
                    "entity_ids": candidate_entity_ids,
                }

        if not relation_meta:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "entities_total": len(entity_ids),
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        buckets: Dict[Tuple[str, datetime], Dict[str, Any]] = {}
        relation_ids = sorted(relation_meta.keys())
        relation_chunk_size = 500

        for i in range(0, len(relation_ids), relation_chunk_size):
            relation_chunk = relation_ids[i : i + relation_chunk_size]
            filters: List[Dict[str, Any]] = [
                {"terms": {"relation_id.keyword": relation_chunk}},
                {"range": {"timestamp": {"gte": since.isoformat()}}},
            ]
            if source_uri:
                filters.append({"term": {"source_uri.keyword": source_uri}})
            query = {"bool": {"filter": filters}}
            for hit in self._iter_search_hits(
                self.indices.relation_provenance,
                query=query,
                sort=[{"timestamp": "asc"}, {"_id": "asc"}],
                size=1000,
            ):
                source = hit["_source"]
                relation_id = str(source.get("relation_id"))
                relation = relation_meta.get(relation_id)
                if not relation:
                    continue
                ts = _parse_datetime(source.get("timestamp"))
                bucket_day = self._bucket_day(ts)
                for entity_id in relation["entity_ids"]:
                    key = (entity_id, bucket_day)
                    if key not in buckets:
                        buckets[key] = {
                            "relation_ids": set(),
                            "evidence_count": 0,
                            "predicates": Counter(),
                        }
                    data = buckets[key]
                    data["relation_ids"].add(relation_id)
                    data["evidence_count"] += 1
                    data["predicates"][relation["predicate"]] += 1

        docs_written = 0
        generated_at = now.isoformat()
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None

        for (entity_id, bucket_day), data in buckets.items():
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day

            meta = entity_meta.get(entity_id, {"name": entity_id, "type": "unknown"})
            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in data["predicates"].most_common(10)
            ]
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_PIR_ENTITY}:"
                f"{scope}:{bucket_day.date().isoformat()}:{entity_id}"
            )
            self.client.index(
                index=self.indices.metrics,
                id=doc_id,
                document={
                    "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                    "source_scope": scope,
                    "bucket_start": bucket_day.isoformat(),
                    "entity_id": entity_id,
                    "entity_name": meta["name"],
                    "entity_type": meta["type"],
                    "relation_count": len(data["relation_ids"]),
                    "evidence_count": int(data["evidence_count"]),
                    "top_predicates": top_predicates,
                    "lookback_days": lookback_days,
                    "min_confidence": min_confidence,
                    "rollup_generated_at": generated_at,
                },
                refresh=False,
            )
            docs_written += 1

        self.client.indices.refresh(index=self.indices.metrics)

        return {
            "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "entities_total": len(entity_ids),
            "relations_considered": len(relation_meta),
            "buckets_written": len(buckets),
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "generated_at": generated_at,
        }

    def rollup_daily_cti_assessments(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
        decay_half_life_days: int = 14,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))
        decay_half_life_days = max(int(decay_half_life_days), 1)

        now = datetime.now(timezone.utc)
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {
                            "term": {
                                "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT
                            }
                        },
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": since.isoformat()}}},
            {"range": {"bucket_start": {"lt": now.isoformat()}}},
        ]
        pir_docs = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        high_risk_predicates = {
            "exploits_vulnerability",
            "uses_technique",
            "delivers_malware",
            "targets_sector",
            "compromises",
        }
        docs_written = 0
        buckets_written = 0
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None
        assessment_ids: set[str] = set()
        latest_pir_rollup_at: Optional[str] = None
        generated_at = now.isoformat()

        for hit in pir_docs:
            source = hit.get("_source") or {}
            entity_id = str(source.get("entity_id") or "")
            if not entity_id:
                continue

            entity_type = str(source.get("entity_type") or "unknown")
            entity_name = str(source.get("entity_name") or entity_id)
            bucket_start_raw = source.get("bucket_start")
            if not bucket_start_raw:
                continue
            bucket_ts = _parse_datetime(bucket_start_raw)
            if bucket_ts.tzinfo is None:
                bucket_ts = bucket_ts.replace(tzinfo=timezone.utc)
            else:
                bucket_ts = bucket_ts.astimezone(timezone.utc)
            bucket_day = self._bucket_day(bucket_ts)
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day
            buckets_written += 1

            relation_count = max(int(source.get("relation_count", 0)), 0)
            evidence_count = max(int(source.get("evidence_count", 0)), 0)
            top_predicates_raw = source.get("top_predicates") or []
            top_predicates = (
                top_predicates_raw if isinstance(top_predicates_raw, list) else []
            )
            age_days = max((now - bucket_ts).total_seconds() / 86400.0, 0.0)
            decay_weight = math.exp(
                (-math.log(2.0) * age_days) / float(decay_half_life_days)
            )

            activity_signal_raw = min(
                1.0, math.log1p(float(evidence_count)) / math.log1p(200.0)
            )
            domain_signal_raw = min(
                1.0, math.log1p(float(relation_count)) / math.log1p(80.0)
            )
            actor_signal_raw = (
                activity_signal_raw
                if entity_type == "threat_actor"
                else activity_signal_raw * 0.60
            )
            activity_signal = self._clamp_score(activity_signal_raw * decay_weight)
            threat_domain_score = self._clamp_score(domain_signal_raw * decay_weight)
            threat_actor_score = self._clamp_score(actor_signal_raw * decay_weight)
            threat_level_score = self._clamp_score(
                0.40 * activity_signal
                + 0.35 * threat_actor_score
                + 0.25 * threat_domain_score
            )
            confidence_score = self._clamp_score(
                max(min_confidence, 0.20)
                + (0.45 * activity_signal)
                + (0.20 * threat_domain_score)
            )
            source_reliability, information_credibility = self._confidence_to_admiralty(
                confidence_score
            )

            if entity_type == "threat_actor":
                if threat_level_score >= 0.65 and confidence_score >= 0.70:
                    attribution_state = "known"
                elif confidence_score >= 0.55:
                    attribution_state = "suspected"
                elif confidence_score >= 0.35:
                    attribution_state = "possible"
                else:
                    attribution_state = "unknown"
            else:
                if confidence_score >= 0.65:
                    attribution_state = "suspected"
                elif confidence_score >= 0.35:
                    attribution_state = "possible"
                else:
                    attribution_state = "unknown"
            attribution_target_id = (
                entity_id
                if entity_type == "threat_actor"
                and attribution_state in {"known", "suspected"}
                else None
            )
            attribution_text = {
                "known": "Observed activity confidently linked to actor",
                "suspected": "Likely linked to actor or campaign",
                "possible": "Weak or partial attribution indicators",
                "unknown": "Attribution not established (UTA)",
            }.get(attribution_state, "Attribution unknown")

            risk_modifier = 1.0
            if top_predicates:
                total_predicate_hits = sum(
                    max(int(item.get("count", 0)), 0) for item in top_predicates
                )
                risky_hits = sum(
                    max(int(item.get("count", 0)), 0)
                    for item in top_predicates
                    if str(item.get("predicate") or "") in high_risk_predicates
                )
                if total_predicate_hits > 0:
                    risk_modifier += (
                        min(risky_hits / float(total_predicate_hits), 1.0) * 0.25
                    )
            mitigation_priority_score = self._clamp_score(
                threat_level_score * risk_modifier
            )
            top_mitigations = self._heuristic_mitigations(
                entity_type=entity_type,
                top_predicates=top_predicates,
                base_score=mitigation_priority_score,
            )

            domain_key, domain_name = self._infer_domain(entity_type, {})
            assessment_id = f"activity:{entity_type}:{entity_id}"
            assessment_name = f"{entity_name} ({entity_type.replace('_', ' ')})"
            threat_domain_level = self._score_to_level(threat_domain_score)
            threat_actor_level = self._score_to_level(threat_actor_score)
            threat_level = self._score_to_level(threat_level_score)
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}:"
                f"{scope}:{bucket_day.date().isoformat()}:{assessment_id}"
            )
            self.client.index(
                index=self.indices.metrics,
                id=doc_id,
                document={
                    "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT,
                    "source_scope": scope,
                    "bucket_start": bucket_day.isoformat(),
                    "assessment_id": assessment_id,
                    "assessment_name": assessment_name,
                    "assessment_kind": "activity",
                    "domain_key": domain_key,
                    "domain_name": domain_name,
                    "actor_id": entity_id if entity_type == "threat_actor" else None,
                    "actor_name": (
                        entity_name if entity_type == "threat_actor" else None
                    ),
                    "entity_id": entity_id,
                    "entity_name": entity_name,
                    "entity_type": entity_type,
                    "entity_ids": [entity_id],
                    "relation_count": relation_count,
                    "evidence_count": evidence_count,
                    "threat_domain_score": threat_domain_score,
                    "threat_actor_score": threat_actor_score,
                    "threat_level_score": threat_level_score,
                    "threat_domain_level": threat_domain_level,
                    "threat_actor_level": threat_actor_level,
                    "threat_level": threat_level,
                    "confidence_score": confidence_score,
                    "source_reliability": source_reliability,
                    "information_credibility": information_credibility,
                    "attribution_state": attribution_state,
                    "attribution_target_id": attribution_target_id,
                    "attribution_text": attribution_text,
                    "mitigation_priority_score": mitigation_priority_score,
                    "top_mitigations": top_mitigations,
                    "top_predicates": top_predicates,
                    "lookback_days": lookback_days,
                    "min_confidence": min_confidence,
                    "decay_half_life_days": decay_half_life_days,
                    "rollup_generated_at": generated_at,
                },
                refresh=False,
            )
            docs_written += 1
            assessment_ids.add(assessment_id)

            pir_rollup_at = source.get("rollup_generated_at")
            if pir_rollup_at and (
                not latest_pir_rollup_at
                or str(pir_rollup_at) > str(latest_pir_rollup_at)
            ):
                latest_pir_rollup_at = str(pir_rollup_at)

        self.client.indices.refresh(index=self.indices.metrics)
        return {
            "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "decay_half_life_days": decay_half_life_days,
            "assessments_total": len(assessment_ids),
            "buckets_written": buckets_written,
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "pir_rollup_last_generated_at": latest_pir_rollup_at,
            "generated_at": generated_at,
        }

    def get_cti_overview(
        self,
        *,
        days: int = 30,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        scope = self._source_scope(source_uri)

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": current_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        hits = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        level_distribution: Counter[int] = Counter()
        attribution_distribution: Counter[str] = Counter()
        by_assessment: Dict[str, Dict[str, Any]] = {}
        rollup_generated_at: Optional[str] = None
        docs_total = 0

        for hit in hits:
            source = hit.get("_source") or {}
            docs_total += 1
            level = int(source.get("threat_level") or 1)
            level = max(1, min(level, 5))
            level_distribution[level] += 1

            state = str(source.get("attribution_state") or "unknown")
            if state not in self.CTI_ATTRIBUTION_STATES:
                state = "unknown"
            attribution_distribution[state] += 1

            assessment_id = str(source.get("assessment_id") or "")
            if not assessment_id:
                continue
            score = float(source.get("threat_level_score") or 0.0)
            evidence_count = int(source.get("evidence_count") or 0)
            relation_count = int(source.get("relation_count") or 0)
            item = by_assessment.setdefault(
                assessment_id,
                {
                    "assessment_id": assessment_id,
                    "assessment_name": str(
                        source.get("assessment_name") or assessment_id
                    ),
                    "assessment_kind": str(source.get("assessment_kind") or "activity"),
                    "entity_type": str(source.get("entity_type") or "unknown"),
                    "domain_name": str(source.get("domain_name") or "Unknown"),
                    "max_score": 0.0,
                    "score_sum": 0.0,
                    "evidence_total": 0,
                    "relation_total": 0,
                    "days": 0,
                },
            )
            item["max_score"] = max(float(item["max_score"]), score)
            item["score_sum"] = float(item["score_sum"]) + score
            item["evidence_total"] = int(item["evidence_total"]) + evidence_count
            item["relation_total"] = int(item["relation_total"]) + relation_count
            item["days"] = int(item["days"]) + 1

            latest_rollup = source.get("rollup_generated_at")
            if latest_rollup and (
                not rollup_generated_at or str(latest_rollup) > str(rollup_generated_at)
            ):
                rollup_generated_at = str(latest_rollup)

        top_assessments = []
        for item in by_assessment.values():
            days_with_data = max(int(item["days"]), 1)
            avg_score = self._clamp_score(
                float(item["score_sum"]) / float(days_with_data)
            )
            top_assessments.append(
                {
                    "assessment_id": item["assessment_id"],
                    "assessment_name": item["assessment_name"],
                    "assessment_kind": item["assessment_kind"],
                    "entity_type": item["entity_type"],
                    "domain_name": item["domain_name"],
                    "max_threat_level_score": round(float(item["max_score"]), 4),
                    "avg_threat_level_score": round(avg_score, 4),
                    "threat_level": self._score_to_level(avg_score),
                    "evidence_total": int(item["evidence_total"]),
                    "relation_total": int(item["relation_total"]),
                }
            )
        top_assessments.sort(
            key=lambda row: (
                -float(row["max_threat_level_score"]),
                -int(row["evidence_total"]),
                str(row["assessment_name"]).lower(),
            )
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "docs_total": docs_total,
            "assessments_total": len(by_assessment),
            "level_distribution": {
                str(level): int(level_distribution.get(level, 0))
                for level in range(1, 6)
            },
            "attribution_distribution": {
                state: int(attribution_distribution.get(state, 0))
                for state in self.CTI_ATTRIBUTION_STATES
            },
            "top_assessments": top_assessments[:10],
        }

    def get_cti_trends(
        self,
        *,
        days: int = 30,
        top_n: int = 10,
        group_by: str = "activity",
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        top_n = max(1, min(int(top_n), 50))
        group_by = str(group_by or "activity").strip().lower()
        if group_by not in {"activity", "domain", "actor"}:
            group_by = "activity"

        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        previous_since = current_since - timedelta(days=window_days)
        scope = self._source_scope(source_uri)
        current_bucket_keys = [
            bucket.isoformat()
            for bucket in self._iter_day_starts(current_since, current_until)
        ]

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": previous_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        hits = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        grouped: Dict[str, Dict[str, Any]] = {}
        rollup_generated_at: Optional[str] = None
        for hit in hits:
            source = hit.get("_source") or {}
            bucket_start_raw = source.get("bucket_start")
            if not bucket_start_raw:
                continue
            bucket_ts = _parse_datetime(bucket_start_raw)
            if bucket_ts.tzinfo is None:
                bucket_ts = bucket_ts.replace(tzinfo=timezone.utc)
            else:
                bucket_ts = bucket_ts.astimezone(timezone.utc)
            bucket_key = bucket_ts.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()

            if group_by == "domain":
                key = str(source.get("domain_key") or "")
                label = str(source.get("domain_name") or key)
            elif group_by == "actor":
                key = str(source.get("actor_id") or "")
                label = str(source.get("actor_name") or key)
            else:
                key = str(source.get("assessment_id") or "")
                label = str(source.get("assessment_name") or key)
            if not key:
                continue

            score = float(source.get("threat_level_score") or 0.0)
            evidence = int(source.get("evidence_count") or 0)
            state = str(source.get("attribution_state") or "unknown")
            if state not in self.CTI_ATTRIBUTION_STATES:
                state = "unknown"

            row = grouped.setdefault(
                key,
                {
                    "id": key,
                    "label": label,
                    "current_score_sum": 0.0,
                    "previous_score_sum": 0.0,
                    "current_evidence": 0,
                    "previous_evidence": 0,
                    "history_scores": Counter(),
                    "history_counts": Counter(),
                    "history_evidence": Counter(),
                    "state_counts": Counter(),
                },
            )

            if previous_since <= bucket_ts < current_since:
                row["previous_score_sum"] = float(row["previous_score_sum"]) + score
                row["previous_evidence"] = int(row["previous_evidence"]) + evidence
            if current_since <= bucket_ts < current_until:
                row["current_score_sum"] = float(row["current_score_sum"]) + score
                row["current_evidence"] = int(row["current_evidence"]) + evidence
                row["history_scores"][bucket_key] += score
                row["history_counts"][bucket_key] += 1
                row["history_evidence"][bucket_key] += evidence
                row["state_counts"][state] += 1

            latest_rollup = source.get("rollup_generated_at")
            if latest_rollup and (
                not rollup_generated_at or str(latest_rollup) > str(rollup_generated_at)
            ):
                rollup_generated_at = str(latest_rollup)

        items: List[Dict[str, Any]] = []
        for row in grouped.values():
            current_avg_score = self._clamp_score(
                float(row["current_score_sum"]) / float(max(window_days, 1))
            )
            previous_avg_score = self._clamp_score(
                float(row["previous_score_sum"]) / float(max(window_days, 1))
            )
            if current_avg_score <= 0.0 and int(row["current_evidence"]) <= 0:
                continue
            delta_score = current_avg_score - previous_avg_score
            trend_score = delta_score / max(previous_avg_score, 0.0001)
            history = []
            for key in current_bucket_keys:
                day_count = int(row["history_counts"].get(key, 0))
                day_score_sum = float(row["history_scores"].get(key, 0.0))
                day_avg_score = (
                    self._clamp_score(day_score_sum / float(day_count))
                    if day_count > 0
                    else 0.0
                )
                history.append(
                    {
                        "bucket_start": key,
                        "threat_level_score": round(day_avg_score, 4),
                        "evidence_count": int(row["history_evidence"].get(key, 0)),
                    }
                )
            state_counts = row.get("state_counts", Counter())
            dominant_state = "unknown"
            if state_counts:
                dominant_state = str(
                    max(
                        state_counts.items(),
                        key=lambda kv: (int(kv[1]), kv[0]),
                    )[0]
                )
            items.append(
                {
                    "id": row["id"],
                    "label": row["label"],
                    "group_by": group_by,
                    "current_threat_level_score": round(current_avg_score, 4),
                    "previous_threat_level_score": round(previous_avg_score, 4),
                    "delta_threat_level_score": round(delta_score, 4),
                    "trend_score": round(trend_score, 4),
                    "threat_level": self._score_to_level(current_avg_score),
                    "attribution_state": dominant_state,
                    "current_evidence": int(row["current_evidence"]),
                    "previous_evidence": int(row["previous_evidence"]),
                    "delta_evidence": int(row["current_evidence"])
                    - int(row["previous_evidence"]),
                    "history": history,
                }
            )

        items.sort(
            key=lambda item: (
                -float(item["delta_threat_level_score"]),
                -float(item["current_threat_level_score"]),
                -int(item["current_evidence"]),
                str(item["label"]).lower(),
            )
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "group_by": group_by,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "compare_window": {
                "days": window_days,
                "since": previous_since.isoformat(),
                "until": current_since.isoformat(),
            },
            "items": items[:top_n],
        }

    def get_pir_trending_summary(
        self,
        *,
        days: int = 7,
        top_n: int = 10,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        top_n = max(1, min(int(top_n), 50))
        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        previous_since = current_since - timedelta(days=window_days)
        scope = self._source_scope(source_uri)

        # Use composite aggregation to build per-entity stats in ES
        # instead of downloading all docs.
        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": previous_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        query = {"bool": {"filter": filters}}

        aggregated: Dict[str, Dict[str, Dict[str, Any]]] = {
            entity_type: {} for entity_type in self.PIR_ENTITY_TYPES
        }
        rollup_generated_at: Optional[str] = None

        # Paginate with composite agg: group by (entity_type, entity_id)
        after: Optional[Dict[str, Any]] = None
        while True:
            composite_body: Dict[str, Any] = {
                "sources": [
                    {"entity_type": {"terms": {"field": "entity_type"}}},
                    {"entity_id": {"terms": {"field": "entity_id"}}},
                ],
                "size": 2000,
            }
            if after:
                composite_body["after"] = after

            response = self.client.search(
                index=self.indices.metrics,
                query=query,
                size=0,
                aggs={
                    "by_entity": {
                        "composite": composite_body,
                        "aggs": {
                            "current_evidence": {
                                "filter": {
                                    "range": {
                                        "bucket_start": {
                                            "gte": current_since.isoformat(),
                                            "lt": current_until.isoformat(),
                                        }
                                    }
                                },
                                "aggs": {
                                    "total": {"sum": {"field": "evidence_count"}},
                                    "relations": {"sum": {"field": "relation_count"}},
                                    "daily": {
                                        "date_histogram": {
                                            "field": "bucket_start",
                                            "calendar_interval": "day",
                                        },
                                        "aggs": {
                                            "evidence": {
                                                "sum": {"field": "evidence_count"}
                                            }
                                        },
                                    },
                                },
                            },
                            "previous_evidence": {
                                "filter": {
                                    "range": {
                                        "bucket_start": {
                                            "gte": previous_since.isoformat(),
                                            "lt": current_since.isoformat(),
                                        }
                                    }
                                },
                                "aggs": {"total": {"sum": {"field": "evidence_count"}}},
                            },
                            "entity_name": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": ["entity_name"],
                                    "sort": [{"bucket_start": "desc"}],
                                }
                            },
                            "latest_rollup": {"max": {"field": "rollup_generated_at"}},
                        },
                    }
                },
            )

            comp_agg = response.get("aggregations", {}).get("by_entity", {})
            buckets = comp_agg.get("buckets", [])
            if not buckets:
                break

            for bucket in buckets:
                entity_type = str(bucket["key"]["entity_type"])
                entity_id = str(bucket["key"]["entity_id"])
                if entity_type not in aggregated or not entity_id:
                    continue

                current_agg = bucket.get("current_evidence", {})
                previous_agg = bucket.get("previous_evidence", {})

                current_ev = int(current_agg.get("total", {}).get("value", 0))
                previous_ev = int(previous_agg.get("total", {}).get("value", 0))
                relation_count = int(current_agg.get("relations", {}).get("value", 0))

                # Extract entity name from top_hits
                name_hits = (
                    bucket.get("entity_name", {}).get("hits", {}).get("hits", [])
                )
                entity_name = entity_id
                if name_hits:
                    entity_name = str(
                        name_hits[0].get("_source", {}).get("entity_name", entity_id)
                    )

                # Build daily history from date_histogram
                history_counts: Counter = Counter()
                for day_bucket in current_agg.get("daily", {}).get("buckets", []):
                    ts = _parse_datetime(day_bucket.get("key_as_string"))
                    bucket_key = ts.replace(
                        hour=0, minute=0, second=0, microsecond=0
                    ).isoformat()
                    history_counts[bucket_key] += int(
                        day_bucket.get("evidence", {}).get("value", 0)
                    )

                # Track latest rollup timestamp
                latest_rollup = bucket.get("latest_rollup", {}).get("value_as_string")
                if latest_rollup and (
                    not rollup_generated_at
                    or str(latest_rollup) > str(rollup_generated_at)
                ):
                    rollup_generated_at = str(latest_rollup)

                aggregated[entity_type][entity_id] = {
                    "entity_id": entity_id,
                    "name": entity_name,
                    "type": entity_type,
                    "current_evidence": current_ev,
                    "previous_evidence": previous_ev,
                    "relation_count_current": relation_count,
                    "history_counts": history_counts,
                }

            after = buckets[-1]["key"]
            if len(buckets) < 2000:
                break

        current_buckets = self._iter_day_starts(current_since, current_until)
        current_bucket_keys = [bucket.isoformat() for bucket in current_buckets]

        def _build_question(entity_type: str, question: str) -> Dict[str, Any]:
            items = []
            for entity in aggregated.get(entity_type, {}).values():
                current_evidence = int(entity["current_evidence"])
                if current_evidence <= 0:
                    continue
                previous_evidence = int(entity["previous_evidence"])
                delta = current_evidence - previous_evidence
                trend_score = delta / max(previous_evidence, 1)
                history = [
                    {
                        "bucket_start": key,
                        "evidence_count": int(entity["history_counts"].get(key, 0)),
                    }
                    for key in current_bucket_keys
                ]
                items.append(
                    {
                        "entity_id": entity["entity_id"],
                        "name": entity["name"],
                        "type": entity["type"],
                        "current_evidence": current_evidence,
                        "previous_evidence": previous_evidence,
                        "delta_evidence": delta,
                        "trend_score": trend_score,
                        "relation_count_current": int(entity["relation_count_current"]),
                        "top_predicates": [],
                        "history": history,
                    }
                )

            items.sort(
                key=lambda item: (
                    -int(item["delta_evidence"]),
                    -int(item["current_evidence"]),
                    str(item["name"]).lower(),
                )
            )
            items = items[:top_n]

            return {
                "id": f"{entity_type}_trending",
                "question": question,
                "entity_type": entity_type,
                "item_count": len(items),
                "items": items,
            }

        generated_at = datetime.now(timezone.utc).isoformat()
        return {
            "generated_at": generated_at,
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "compare_window": {
                "days": window_days,
                "since": previous_since.isoformat(),
                "until": current_since.isoformat(),
            },
            "questions": [
                _build_question(entity_type, question)
                for entity_type, question in self.PIR_QUESTIONS.items()
            ],
        }

    def get_rollup_overview(
        self,
        days: int = 30,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        days = max(int(days), 1)
        since = datetime.utcnow() - timedelta(days=days)
        scope = self._source_scope(source_uri)
        filters = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": since.isoformat()}}},
        ]
        response = self.client.search(
            index=self.indices.metrics,
            query={"bool": {"filter": filters}},
            size=1,
            sort=[
                {"bucket_start": "desc"},
                {"evidence_count": "desc"},
                {"entity_name": "asc"},
            ],
            aggs={
                "active_actors": {"cardinality": {"field": "entity_id"}},
                "evidence_total": {"sum": {"field": "evidence_count"}},
                "latest_bucket": {"max": {"field": "bucket_start"}},
                "latest_rollup": {"max": {"field": "rollup_generated_at"}},
            },
        )
        hits = response.get("hits", {}).get("hits", [])
        top_actor = None
        if hits:
            top = hits[0]["_source"]
            top_actor = {
                "entity_id": top.get("entity_id"),
                "entity_name": top.get("entity_name"),
                "bucket_start": top.get("bucket_start"),
                "evidence_count": int(top.get("evidence_count", 0)),
                "relation_count": int(top.get("relation_count", 0)),
            }
        aggs = response.get("aggregations", {})
        return {
            "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
            "source_scope": scope,
            "days": days,
            "active_actors": int(aggs.get("active_actors", {}).get("value") or 0),
            "evidence_total": float(aggs.get("evidence_total", {}).get("value") or 0.0),
            "latest_bucket": aggs.get("latest_bucket", {}).get("value_as_string"),
            "last_rollup_at": aggs.get("latest_rollup", {}).get("value_as_string"),
            "top_actor": top_actor,
        }
