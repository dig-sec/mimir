from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from elasticsearch import ConflictError, NotFoundError

from ...normalize import canonical_entity_key
from ...schemas import (
    Entity,
    ExtractionRun,
    Provenance,
    Relation,
    Subgraph,
    SubgraphEdge,
    SubgraphNode,
)
from ..base import GraphStore
from ._helpers import (
    _compact_text,
    _deterministic_entity_id,
    _deterministic_relation_id,
    _ElasticBase,
    _entity_keys,
    _merge_attrs,
    _normalize_datetime,
    _parse_datetime,
    _triple_key,
)


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
                "name_compact": {"type": "keyword"},
                "type": {"type": "keyword"},
                "aliases": {"type": "keyword"},
                "aliases_compact": {"type": "keyword"},
                "attrs": {
                    "type": "object",
                    "properties": {
                        "origin": {"type": "keyword"},
                        "source_url": {"type": "keyword"},
                        "feed_name": {"type": "keyword"},
                        "published": {"type": "keyword"},
                        "feedly_id": {"type": "keyword"},
                        "mitre_id": {"type": "keyword"},
                        "mitre_ids": {"type": "keyword"},
                        "cvss_score": {"type": "float"},
                        "has_exploit": {"type": "boolean"},
                        "has_patch": {"type": "boolean"},
                        "identity_class": {"type": "keyword"},
                        "ioc_type": {"type": "keyword"},
                        "indicator_type": {"type": "keyword"},
                        "opencti_id": {"type": "keyword"},
                        "opencti_type": {"type": "keyword"},
                        "description": {"type": "text"},
                        # ── Malware sample fields ──
                        "sha256": {"type": "keyword"},
                        "sha1": {"type": "keyword"},
                        "md5": {"type": "keyword"},
                        "ssdeep": {"type": "keyword"},
                        "imphash": {"type": "keyword"},
                        "crc32": {"type": "keyword"},
                        "file_name": {"type": "keyword"},
                        "file_type": {"type": "keyword"},
                        "file_size": {"type": "long"},
                        "source_index": {"type": "keyword"},
                        "compile_time": {"type": "keyword"},
                        "entry_point": {"type": "keyword"},
                        "pdb_path": {"type": "keyword"},
                        "company_name": {"type": "keyword"},
                        "original_filename": {"type": "keyword"},
                        "pe_arch": {"type": "keyword"},
                        "has_high_entropy": {"type": "boolean"},
                        "entropy_value": {"type": "float"},
                        # ── Capa / Yara rule fields ──
                        "rule_name": {"type": "keyword"},
                        "mbc_id": {"type": "keyword"},
                        "behavior": {"type": "keyword"},
                        "mbc_objective": {"type": "keyword"},
                        "detection_source": {"type": "keyword"},
                        "tactic": {"type": "keyword"},
                        "technique_name": {"type": "keyword"},
                        "subtechnique": {"type": "keyword"},
                        "display_name": {"type": "keyword"},
                        # ── STIX import fields ──
                        "stix_id": {"type": "keyword"},
                        "stix_external_ids": {"type": "keyword"},
                        "stix_source_uri": {"type": "keyword"},
                        "stix_spec_version": {"type": "keyword"},
                        "source_uri": {"type": "keyword"},
                        "raw_text": {"type": "keyword"},
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
                        "source": {"type": "keyword"},
                        "inference": {"type": "keyword"},
                        "source_article": {"type": "text"},
                        "tactic": {"type": "keyword"},
                        "detection_source": {"type": "keyword"},
                        "inferred": {"type": "boolean"},
                        "source_uri": {"type": "keyword"},
                        "stix_id": {"type": "keyword"},
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
            aliases_compact = sorted(
                {
                    compact
                    for compact in (_compact_text(alias) for alias in merged_aliases)
                    if compact
                }
            )
            doc = {
                "name": entity.name,
                "name_compact": _compact_text(entity.name),
                "type": entity.type,
                "aliases": merged_aliases,
                "aliases_compact": aliases_compact,
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
        compact_query = _compact_text(normalized_query)
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
                    "wildcard": {
                        "aliases": {
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
                {
                    "match": {
                        "name": {
                            "query": normalized_query,
                            "operator": "and",
                            "fuzziness": "AUTO",
                            "prefix_length": 1,
                        }
                    }
                },
            ]
        }
        if compact_query:
            compact_wildcard = compact_query + "*"
            bool_query["should"].extend(
                [
                    # Backward-compatible fallback for older entity docs that
                    # predate name_compact/aliases_compact fields.
                    {
                        "wildcard": {
                            "name.keyword": {
                                "value": compact_wildcard,
                                "case_insensitive": True,
                            }
                        }
                    },
                    {"term": {"name_compact": compact_query}},
                    {
                        "wildcard": {
                            "name_compact": {
                                "value": compact_wildcard,
                                "case_insensitive": True,
                            }
                        }
                    },
                    {
                        "wildcard": {
                            "aliases_compact": {
                                "value": compact_wildcard,
                                "case_insensitive": True,
                            }
                        }
                    },
                ]
            )
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
            filters: List[Dict[str, Any]] = [{"terms": {"relation_id": id_chunk}}]
            if source_uri:
                filters.append({"term": {"source_uri": source_uri}})
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
                query={"term": {"relation_id": relation_id}},
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
            filters.append({"term": {"source_uri": source_uri}})

        counts: Counter[str] = Counter()
        # Use terms aggregation – top N relation_ids by doc count (single request)
        response = self.client.search(
            index=self.indices.relation_provenance,
            query={"bool": {"filter": filters}},
            size=0,
            aggs={
                "by_relation": {
                    "terms": {
                        "field": "relation_id",
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
            filters.append({"term": {"source_uri": source_uri}})

        # Step 1: Get top relation_ids by count (no sub-agg)
        response = self.client.search(
            index=self.indices.relation_provenance,
            query={"bool": {"filter": filters}},
            size=0,
            aggs={
                "by_relation": {
                    "terms": {
                        "field": "relation_id",
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
            daily_filters = list(filters) + [{"terms": {"relation_id": chunk}}]
            daily_response = self.client.search(
                index=self.indices.relation_provenance,
                query={"bool": {"filter": daily_filters}},
                size=0,
                aggs={
                    "by_relation": {
                        "terms": {
                            "field": "relation_id",
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
            scope_filters.append({"term": {"source_uri": source_uri}})

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
                        "field": "relation_id",
                        "precision_threshold": 40000,
                    }
                },
                "sources": {"cardinality": {"field": "source_uri"}},
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
                        "field": "relation_id",
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
