"""Wellspring knowledge-graph → STIX 2.1 bundle exporter.

Converts entities and relations from a subgraph query into valid STIX 2.1
JSON bundles that can be shared via TAXII, imported into MISP / OpenCTI, etc.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import NAMESPACE_URL, uuid5

from ..schemas import Subgraph, SubgraphEdge, SubgraphNode

# Wellspring entity type → STIX SDO type
_ENTITY_TYPE_TO_SDO: Dict[str, str] = {
    "threat_actor": "threat-actor",
    "malware": "malware",
    "tool": "tool",
    "attack_pattern": "attack-pattern",
    "campaign": "campaign",
    "vulnerability": "vulnerability",
    "mitigation": "course-of-action",
    "identity": "identity",
    "indicator": "indicator",
    "infrastructure": "infrastructure",
    "tactic": "attack-pattern",  # tactics map to attack-pattern in STIX
    "location": "location",
    "report": "report",
}

# Wellspring predicate → STIX relationship_type
_PREDICATE_TO_SRO: Dict[str, str] = {
    "uses": "uses",
    "uses_technique": "uses",
    "employs_tool": "uses",
    "targets": "targets",
    "targets_sector": "targets",
    "indicates": "indicates",
    "mitigates": "mitigates",
    "mitigated_by": "mitigates",  # reversed during export
    "attributed_to": "attributed-to",
    "is_attributed_to": "attributed-to",
    "variant_of": "variant-of",
    "derived_from": "derived-from",
    "related_to": "related-to",
    "associated_with": "related-to",
    "communicates_with": "communicates-with",
    "delivers": "delivers",
    "downloads": "downloads",
    "drops": "drops",
    "exploits": "exploits",
    "exploits_vulnerability": "exploits",
    "hosts": "hosts",
    "controls": "controls",
    "compromises": "compromises",
    "originates_from": "originates-from",
    "located_at": "located-at",
    "beacons_to": "beacons-to",
    "exfiltrates_to": "exfiltrates-to",
    "belongs_to_tactic": "related-to",
    "dropped_by": "delivers",  # reversed
    "has_capability": "related-to",
    "mapped_to_technique": "related-to",
    "developed_by": "attributed-to",
    "operated_by": "attributed-to",
    "detected_by": "related-to",
    "persists_via": "uses",
    "distributed_via": "delivers",
    "implements_capability": "related-to",
    "sighted_at": "related-to",
    "mentions": "related-to",
    "contains_ioc": "related-to",
}

# Predicates where the Wellspring relation direction is reversed vs STIX
_REVERSED_PREDICATES = frozenset({"mitigated_by", "dropped_by"})

# Deterministic STIX UUID namespace for Wellspring entities
_WELLSPRING_NS = uuid5(NAMESPACE_URL, "wellspring.graph")


def _deterministic_stix_id(sdo_type: str, wellspring_id: str) -> str:
    """Generate a deterministic STIX id from the Wellspring entity id."""
    uid = uuid5(_WELLSPRING_NS, f"{sdo_type}:{wellspring_id}")
    return f"{sdo_type}--{uid}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _node_to_sdo(node: SubgraphNode, created: str) -> Optional[Dict[str, Any]]:
    """Convert a Wellspring subgraph node into a STIX SDO dict."""
    sdo_type = _ENTITY_TYPE_TO_SDO.get(node.type or "", "identity")
    stix_id = _deterministic_stix_id(sdo_type, node.id)

    sdo: Dict[str, Any] = {
        "type": sdo_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": created,
        "modified": created,
        "name": node.name,
    }

    # STIX requires specific fields per SDO type
    if sdo_type == "threat-actor":
        sdo["threat_actor_types"] = ["unknown"]
    elif sdo_type == "malware":
        sdo["is_family"] = True
        sdo["malware_types"] = ["unknown"]
    elif sdo_type == "indicator":
        sdo["pattern"] = f"[file:name = '{node.name}']"
        sdo["pattern_type"] = "stix"
        sdo["valid_from"] = created
    elif sdo_type == "identity":
        sdo["identity_class"] = "unknown"

    return sdo


def _edge_to_sro(
    edge: SubgraphEdge,
    node_stix_ids: Dict[str, str],
    created: str,
) -> Optional[Dict[str, Any]]:
    """Convert a Wellspring subgraph edge into a STIX SRO dict."""
    relationship_type = _PREDICATE_TO_SRO.get(edge.predicate, "related-to")
    reversed_ = edge.predicate in _REVERSED_PREDICATES

    source_ws_id = edge.object_id if reversed_ else edge.subject_id
    target_ws_id = edge.subject_id if reversed_ else edge.object_id

    source_stix = node_stix_ids.get(source_ws_id)
    target_stix = node_stix_ids.get(target_ws_id)

    if not source_stix or not target_stix:
        return None

    sro_id = _deterministic_stix_id("relationship", edge.id)

    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": sro_id,
        "created": created,
        "modified": created,
        "relationship_type": relationship_type,
        "source_ref": source_stix,
        "target_ref": target_stix,
        "confidence": int(edge.confidence * 100),  # STIX uses 0-100
    }


def export_stix_bundle(subgraph: Subgraph) -> Dict[str, Any]:
    """Export a Wellspring subgraph as a STIX 2.1 bundle.

    Parameters
    ----------
    subgraph:
        Wellspring ``Subgraph`` (nodes + edges).

    Returns
    -------
    A dict representing a valid STIX 2.1 bundle, ready for ``json.dumps()``.
    """
    created = _now_iso()
    objects: List[Dict[str, Any]] = []
    node_stix_ids: Dict[str, str] = {}

    # Convert nodes → SDOs
    for node in subgraph.nodes:
        sdo = _node_to_sdo(node, created)
        if sdo:
            objects.append(sdo)
            node_stix_ids[node.id] = sdo["id"]

    # Convert edges → SROs
    for edge in subgraph.edges:
        sro = _edge_to_sro(edge, node_stix_ids, created)
        if sro:
            objects.append(sro)

    bundle_id = f"bundle--{uuid5(_WELLSPRING_NS, created)}"

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
