from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from mimir.normalize import canonical_entity_key
from mimir.schemas import (
    Entity,
    ExtractionRun,
    Provenance,
    Relation,
    Subgraph,
    SubgraphEdge,
    SubgraphNode,
)
from mimir.storage.base import GraphStore


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


def _normalize_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


@dataclass
class InMemoryGraphStore(GraphStore):
    entities: Dict[str, Entity] = field(default_factory=dict)
    entities_by_key: Dict[str, str] = field(default_factory=dict)
    relations: Dict[str, Relation] = field(default_factory=dict)
    relations_by_triple: Dict[Tuple[str, str, str], str] = field(default_factory=dict)
    provenance_by_id: Dict[str, Provenance] = field(default_factory=dict)
    provenance_by_relation: Dict[str, List[str]] = field(default_factory=dict)

    def upsert_entities(self, entities: List[Entity]) -> List[Entity]:
        stored: List[Entity] = []
        for entity in entities:
            key = canonical_entity_key(entity.name, entity.type)
            existing_id = self.entities_by_key.get(key)
            if existing_id:
                existing = self.entities[existing_id]
                merged = Entity(
                    id=existing.id,
                    name=entity.name,
                    type=entity.type,
                    aliases=sorted({*existing.aliases, *entity.aliases}),
                    attrs={**existing.attrs, **entity.attrs},
                )
                self.entities[existing.id] = merged
                target = merged
            else:
                entity_id = entity.id or str(uuid4())
                target = Entity(
                    id=entity_id,
                    name=entity.name,
                    type=entity.type,
                    aliases=list(entity.aliases),
                    attrs=dict(entity.attrs),
                )
                self.entities[entity_id] = target

            keys = {canonical_entity_key(target.name, target.type)}
            for alias in target.aliases:
                keys.add(canonical_entity_key(alias, target.type))
            for each in keys:
                if each:
                    self.entities_by_key[each] = target.id
            stored.append(target)
        return stored

    def upsert_relations(self, relations: List[Relation]) -> List[Relation]:
        stored: List[Relation] = []
        for relation in relations:
            triple = (relation.subject_id, relation.predicate, relation.object_id)
            existing_id = self.relations_by_triple.get(triple)
            if existing_id:
                existing = self.relations[existing_id]
                merged = Relation(
                    id=existing.id,
                    subject_id=existing.subject_id,
                    predicate=existing.predicate,
                    object_id=existing.object_id,
                    confidence=max(existing.confidence, relation.confidence),
                    attrs=_merge_attrs(existing.attrs, relation.attrs),
                )
                self.relations[existing.id] = merged
                stored.append(merged)
            else:
                relation_id = relation.id or str(uuid4())
                item = Relation(
                    id=relation_id,
                    subject_id=relation.subject_id,
                    predicate=relation.predicate,
                    object_id=relation.object_id,
                    confidence=relation.confidence,
                    attrs=dict(relation.attrs),
                )
                self.relations[item.id] = item
                self.relations_by_triple[triple] = item.id
                stored.append(item)
        return stored

    def attach_provenance(self, relation_id: str, provenance: Provenance) -> None:
        self.provenance_by_id[provenance.provenance_id] = provenance
        self.provenance_by_relation.setdefault(relation_id, [])
        if provenance.provenance_id not in self.provenance_by_relation[relation_id]:
            self.provenance_by_relation[relation_id].append(provenance.provenance_id)

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self.entities.get(entity_id)

    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        canonical_key: Optional[str] = None,
    ) -> List[Entity]:
        if canonical_key and canonical_key in self.entities_by_key:
            ent = self.entities.get(self.entities_by_key[canonical_key])
            if not ent:
                return []
            if entity_type and ent.type != entity_type:
                return []
            return [ent]

        q = query.lower()
        results: List[Entity] = []
        for entity in self.entities.values():
            if entity_type and entity.type != entity_type:
                continue
            if q in entity.name.lower():
                results.append(entity)
        return results

    def get_subgraph(
        self,
        seed_entity_id: str,
        depth: int = 1,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Subgraph:
        since = _normalize_datetime(since)
        until = _normalize_datetime(until)
        visited = {seed_entity_id}
        frontier = {seed_entity_id}
        edges: Dict[str, Relation] = {}

        for _ in range(max(depth, 0)):
            if not frontier:
                break
            next_frontier: set[str] = set()
            for relation in self.relations.values():
                if relation.confidence < min_confidence:
                    continue
                if relation.subject_id in frontier or relation.object_id in frontier:
                    if source_uri:
                        provenance_ids = self.provenance_by_relation.get(
                            relation.id, []
                        )
                        if not any(
                            self.provenance_by_id[pid].source_uri == source_uri
                            and (
                                since is None
                                or _normalize_datetime(
                                    self.provenance_by_id[pid].timestamp
                                )
                                >= since
                            )
                            and (
                                until is None
                                or _normalize_datetime(
                                    self.provenance_by_id[pid].timestamp
                                )
                                <= until
                            )
                            for pid in provenance_ids
                            if pid in self.provenance_by_id
                        ):
                            continue
                    elif since or until:
                        provenance_ids = self.provenance_by_relation.get(
                            relation.id, []
                        )
                        if not any(
                            (
                                since is None
                                or _normalize_datetime(
                                    self.provenance_by_id[pid].timestamp
                                )
                                >= since
                            )
                            and (
                                until is None
                                or _normalize_datetime(
                                    self.provenance_by_id[pid].timestamp
                                )
                                <= until
                            )
                            for pid in provenance_ids
                            if pid in self.provenance_by_id
                        ):
                            continue
                    edges[relation.id] = relation
                    if relation.subject_id not in visited:
                        next_frontier.add(relation.subject_id)
                    if relation.object_id not in visited:
                        next_frontier.add(relation.object_id)
            visited.update(next_frontier)
            frontier = next_frontier

        nodes = [self.entities[eid] for eid in visited if eid in self.entities]
        return Subgraph(
            nodes=[SubgraphNode(id=n.id, name=n.name, type=n.type) for n in nodes],
            edges=[
                SubgraphEdge(
                    id=e.id,
                    subject_id=e.subject_id,
                    predicate=e.predicate,
                    object_id=e.object_id,
                    confidence=e.confidence,
                    attrs=e.attrs,
                )
                for e in edges.values()
            ],
        )

    def get_full_graph(self, min_confidence: float = 0.0) -> Subgraph:
        return Subgraph(
            nodes=[
                SubgraphNode(id=e.id, name=e.name, type=e.type)
                for e in self.entities.values()
            ],
            edges=[
                SubgraphEdge(
                    id=r.id,
                    subject_id=r.subject_id,
                    predicate=r.predicate,
                    object_id=r.object_id,
                    confidence=r.confidence,
                    attrs=r.attrs,
                )
                for r in self.relations.values()
                if r.confidence >= min_confidence
            ],
        )

    def explain_edge(
        self,
        relation_id: str,
    ) -> Tuple[Relation, List[Provenance], List[ExtractionRun]]:
        relation = self.relations.get(relation_id)
        if not relation:
            raise KeyError(f"Relation not found: {relation_id}")
        provenance = [
            self.provenance_by_id[pid]
            for pid in self.provenance_by_relation.get(relation_id, [])
            if pid in self.provenance_by_id
        ]
        return relation, provenance, []

    def count_entities(self) -> int:
        return len(self.entities)

    def count_relations(self) -> int:
        return len(self.relations)
