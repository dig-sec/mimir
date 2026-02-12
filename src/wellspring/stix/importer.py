"""STIX 2.1 → Wellspring knowledge-graph importer.

Parses a STIX bundle and converts SDOs + SROs into Wellspring entities
and relations, bypassing LLM extraction entirely for structured data.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List
from uuid import uuid4

from ..dedupe import EntityResolver
from ..normalize import normalize_predicate
from ..schemas import Entity, Relation
from ..storage.base import GraphStore

logger = logging.getLogger(__name__)

# ── STIX SDO type → Wellspring entity type mapping ──────────────────────────
_SDO_TYPE_MAP: Dict[str, str] = {
    "threat-actor": "threat_actor",
    "intrusion-set": "threat_actor",
    "malware": "malware",
    "tool": "tool",
    "attack-pattern": "attack_pattern",
    "campaign": "campaign",
    "vulnerability": "vulnerability",
    "course-of-action": "mitigation",
    "identity": "identity",
    "indicator": "indicator",
    "infrastructure": "infrastructure",
    "malware-analysis": "malware_analysis",
    "observed-data": "observed_data",
    "report": "report",
    "grouping": "grouping",
    "location": "location",
    "note": "note",
    "opinion": "opinion",
}

# ── STIX SRO relationship_type → Wellspring predicate ───────────────────────
_RELATIONSHIP_MAP: Dict[str, str] = {
    "uses": "uses",
    "targets": "targets",
    "indicates": "indicates",
    "mitigates": "mitigates",
    "attributed-to": "attributed_to",
    "variant-of": "variant_of",
    "derived-from": "derived_from",
    "related-to": "related_to",
    "impersonates": "impersonates",
    "located-at": "located_at",
    "based-on": "based_on",
    "communicates-with": "communicates_with",
    "consists-of": "consists_of",
    "controls": "controls",
    "delivers": "delivers",
    "downloads": "downloads",
    "drops": "drops",
    "exploits": "exploits",
    "has": "has",
    "hosts": "hosts",
    "owns": "owns",
    "authored-by": "authored_by",
    "beacons-to": "beacons_to",
    "exfiltrates-to": "exfiltrates_to",
    "originates-from": "originates_from",
    "compromises": "compromises",
    "remediates": "remediates",
    "investigates": "investigates",
    "characterizes": "characterizes",
}


def _extract_name(obj: Dict[str, Any]) -> str:
    """Best-effort name extraction from a STIX object."""
    return (
        obj.get("name")
        or obj.get("value")
        or obj.get("description", "")[:80]
        or obj.get("id", "unknown")
    )


def _extract_external_ids(obj: Dict[str, Any]) -> List[str]:
    """Pull external reference IDs (MITRE ATT&CK T-codes, CVEs, etc.)."""
    ids: List[str] = []
    for ref in obj.get("external_references", []):
        ext_id = ref.get("external_id")
        if ext_id:
            ids.append(ext_id)
    return ids


def _extract_aliases(obj: Dict[str, Any]) -> List[str]:
    """Pull alias fields from various SDO types."""
    aliases: List[str] = []
    for key in ("aliases", "x_mitre_aliases"):
        val = obj.get(key)
        if isinstance(val, list):
            aliases.extend(str(v) for v in val)
    return aliases


def _extract_kill_chain(obj: Dict[str, Any]) -> List[str]:
    """Pull kill-chain phase names (maps to ATT&CK tactics)."""
    phases = obj.get("kill_chain_phases", [])
    return [p.get("phase_name", "") for p in phases if isinstance(p, dict)]


@dataclass
class StixImportResult:
    """Summary returned after a STIX bundle import."""

    entities_created: int = 0
    relations_created: int = 0
    objects_skipped: int = 0
    errors: List[str] = field(default_factory=list)


def ingest_stix_bundle(
    bundle_data: Dict[str, Any],
    graph_store: GraphStore,
    source_uri: str = "stix://bundle",
) -> StixImportResult:
    """Ingest a STIX 2.1 bundle directly into the Wellspring graph store.

    Parameters
    ----------
    bundle_data:
        Parsed JSON dict of the STIX bundle (must have ``type`` = ``bundle``).
    graph_store:
        Wellspring graph store to write entities/relations into.
    source_uri:
        Provenance URI recorded for imported objects.

    Returns
    -------
    StixImportResult with counts of imported objects.
    """
    result = StixImportResult()

    if bundle_data.get("type") != "bundle":
        result.errors.append("Not a valid STIX 2.1 bundle (missing type=bundle)")
        return result

    objects = bundle_data.get("objects", [])
    if not objects:
        result.errors.append("Bundle contains no objects")
        return result

    resolver = EntityResolver(graph_store)

    # --- Phase 1: map STIX IDs → Wellspring entities ---
    stix_id_map: Dict[str, Entity] = {}  # stix_id → Entity

    for obj in objects:
        obj_type = obj.get("type", "")
        stix_id = obj.get("id", "")

        if obj_type in ("relationship", "sighting", "marking-definition"):
            continue  # handled in phase 2

        entity_type = _SDO_TYPE_MAP.get(obj_type)
        if not entity_type:
            result.objects_skipped += 1
            continue

        name = _extract_name(obj)
        if not name or len(name.strip()) < 2:
            result.objects_skipped += 1
            continue

        ext_ids = _extract_external_ids(obj)
        aliases = _extract_aliases(obj)

        # Build a rich display name: prefer "T1059 Command ..." format
        display_name = name
        if ext_ids and not name.startswith(ext_ids[0]):
            display_name = f"{ext_ids[0]} {name}"

        entity = resolver.resolve(display_name, entity_type=entity_type)

        # Merge aliases
        existing_aliases = set(entity.aliases)
        new_aliases = set(aliases + ext_ids) - existing_aliases - {entity.name}
        if new_aliases:
            entity.aliases = list(existing_aliases | new_aliases)
            graph_store.upsert_entities([entity])

        # Store STIX-specific attrs
        extra_attrs: Dict[str, Any] = {}
        if ext_ids:
            extra_attrs["stix_external_ids"] = ext_ids
        if obj.get("description"):
            extra_attrs["description"] = obj["description"][:500]
        stix_spec_version = obj.get("spec_version")
        if stix_spec_version:
            extra_attrs["stix_spec_version"] = stix_spec_version
        extra_attrs["stix_id"] = stix_id
        extra_attrs["stix_source_uri"] = source_uri

        if extra_attrs:
            entity.attrs.update(extra_attrs)
            graph_store.upsert_entities([entity])

        stix_id_map[stix_id] = entity
        result.entities_created += 1

        # --- Create kill-chain (tactic) relations ---
        for phase_name in _extract_kill_chain(obj):
            if not phase_name:
                continue
            tactic = resolver.resolve(phase_name, entity_type="tactic")
            rel = Relation(
                id=str(uuid4()),
                subject_id=entity.id,
                predicate="belongs_to_tactic",
                object_id=tactic.id,
                confidence=0.95,
                attrs={"origin": "stix_import", "source_uri": source_uri},
            )
            graph_store.upsert_relations([rel])
            result.relations_created += 1

    # --- Phase 2: convert SROs into relations ---
    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "relationship":
            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "related-to")

            source_entity = stix_id_map.get(source_ref)
            target_entity = stix_id_map.get(target_ref)

            if not source_entity or not target_entity:
                result.objects_skipped += 1
                continue

            predicate = _RELATIONSHIP_MAP.get(rel_type, normalize_predicate(rel_type))
            confidence = obj.get("confidence", 70) / 100.0  # STIX uses 0-100

            rel = Relation(
                id=str(uuid4()),
                subject_id=source_entity.id,
                predicate=predicate,
                object_id=target_entity.id,
                confidence=min(max(confidence, 0.0), 1.0),
                attrs={
                    "origin": "stix_import",
                    "stix_id": obj.get("id", ""),
                    "source_uri": source_uri,
                },
            )
            graph_store.upsert_relations([rel])
            result.relations_created += 1

        elif obj_type == "sighting":
            sighting_of = obj.get("sighting_of_ref", "")
            observed = obj.get("where_sighted_refs", [])

            source_entity = stix_id_map.get(sighting_of)
            if not source_entity:
                result.objects_skipped += 1
                continue

            for target_ref in observed:
                target_entity = stix_id_map.get(target_ref)
                if not target_entity:
                    continue
                rel = Relation(
                    id=str(uuid4()),
                    subject_id=source_entity.id,
                    predicate="sighted_at",
                    object_id=target_entity.id,
                    confidence=0.8,
                    attrs={
                        "origin": "stix_import",
                        "stix_id": obj.get("id", ""),
                        "source_uri": source_uri,
                        "count": obj.get("count", 1),
                    },
                )
                graph_store.upsert_relations([rel])
                result.relations_created += 1

    logger.info(
        "STIX import: %d entities, %d relations, %d skipped, %d errors",
        result.entities_created,
        result.relations_created,
        result.objects_skipped,
        len(result.errors),
    )
    return result


def parse_stix_file(raw: bytes, filename: str) -> Dict[str, Any]:
    """Parse raw bytes as a STIX 2.1 JSON bundle."""
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {filename}: {exc}") from exc

    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise ValueError(f"{filename} is not a STIX 2.1 bundle (missing type=bundle)")

    return data
