from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .normalize import canonical_entity_key, normalize_entity_name
from .schemas import Entity
from .storage.base import GraphStore


def _deterministic_entity_id(canonical_key: str) -> str:
    """Generate a stable UUID5 from a canonical entity key."""
    from uuid import UUID, uuid5

    _NS = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    return str(uuid5(_NS, canonical_key))


@dataclass
class EntityResolver:
    store: GraphStore

    def resolve(self, name: str, entity_type: Optional[str] = None) -> Entity:
        normalized_name = normalize_entity_name(name)
        key = canonical_entity_key(normalized_name, entity_type)
        matches = self.store.search_entities(
            query=normalized_name,
            entity_type=entity_type,
            canonical_key=key,
        )
        if matches:
            return matches[0]

        entity = Entity(
            id=_deterministic_entity_id(key),
            name=normalized_name,
            type=entity_type,
            aliases=[name] if name != normalized_name else [],
            attrs={},
        )
        self.store.upsert_entities([entity])
        return entity
