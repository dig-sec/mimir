"""AI Knowledge Graph (AIKG) JSON importer.

Imports Subject-Predicate-Object triples produced by tools like:
- https://github.com/robert-mcdermott/ai-knowledge-graph
- https://github.com/holisticinfosec/ai-knowledge-graph-files

Design goals:
- Safe by default: inferred edges are skipped unless explicitly enabled.
- Deterministic entity resolution through existing ``EntityResolver``.
- Predicate normalization to keep relation keys queryable.
- Provenance attached for every imported relation.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4, uuid5

from ..dedupe import EntityResolver
from ..normalize import normalize_predicate
from ..schemas import Provenance, Relation
from ..storage.base import GraphStore

logger = logging.getLogger(__name__)

_NS_PROVENANCE = UUID("f4f6c40f-b5c4-4ab5-9f21-4ca46d8e52eb")

_VALID_ENTITY_TYPES = frozenset(
    {
        "threat_actor",
        "malware",
        "tool",
        "vulnerability",
        "attack_pattern",
        "campaign",
        "identity",
        "infrastructure",
        "indicator",
        "location",
        "report",
        "mitigation",
        "topic",
        "malware_sample",
        "capa_rule",
        "capa_behavior",
        "yara_rule",
        "tactic",
        "sector",
        "service",
        "credential",
        "artifact",
        # Attack-surface / vulnerability-management types (GVM / Redamon-inspired)
        "domain",
        "subdomain",
        "ip_address",
        "port",
        "base_url",
        "endpoint",
        "parameter",
        "technology",
        "header",
        "certificate",
        "dns_record",
        "cve",
        "mitre_data",
        "capec",
        "exploit",
        # Watcher threat-intelligence types
        "trendy_word",
        "data_leak_alert",
        "data_leak_keyword",
        "twisted_domain",
        "monitored_domain",
        "monitored_site",
    }
)

_CV_RE = re.compile(r"^CVE-\d{4}-\d{4,8}$", re.IGNORECASE)
_TACTIC_RE = re.compile(r"^TA\d{4}$", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_IPV4_RE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$"
)
_URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_APT_RE = re.compile(r"\bapt[- ]?\d{1,3}\b", re.IGNORECASE)
_THREAT_ACTOR_TERMS = frozenset({"threat actor", "threat actors", "actor", "actors"})
_SECTOR_HINT_RE = re.compile(
    r"\b(sector|industry|critical infrastructure|logistics|transportation|defense)\b",
    re.IGNORECASE,
)
_SERVICE_HINT_RE = re.compile(
    r"\b(service|portal|vpn|webmail|imap|ews|rtsp|api)\b",
    re.IGNORECASE,
)
_CREDENTIAL_HINT_RE = re.compile(
    r"\b(credential|credentials|password|ntlm|hash|mfa)\b",
    re.IGNORECASE,
)
_ARTIFACT_HINT_RE = re.compile(
    r"\b(pdf lure|attachment|archive|shortcut|script|binary|dll|zip)\b",
    re.IGNORECASE,
)

_PREDICATE_CANONICAL: Dict[str, str] = {
    "targeted": "targets",
    "targeting": "targets",
    "uses": "uses",
    "used": "uses",
    "associated_with": "associated_with",
    "related_to": "related_to",
    "relates_to": "related_to",
}


@dataclass
class AikgImportResult:
    """Summary returned by AIKG triples import."""

    triples_seen: int = 0
    triples_imported: int = 0
    entities_created: int = 0
    relations_created: int = 0
    skipped_invalid: int = 0
    skipped_inferred: int = 0
    skipped_low_confidence: int = 0
    skipped_noisy_inferred: int = 0
    errors: List[str] = field(default_factory=list)


def _normalize_entity_type(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower().replace(" ", "_").replace("-", "_")
    return cleaned if cleaned in _VALID_ENTITY_TYPES else None


def _coerce_inferred(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _coerce_confidence(value: Any, *, inferred: bool) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    if isinstance(value, str):
        try:
            return max(0.0, min(float(value.strip()), 1.0))
        except ValueError:
            pass
    # AIKG JSON commonly omits confidence. Use a conservative default for inferred.
    return 0.45 if inferred else 0.80


def _infer_entity_type(label: str) -> str:
    value = label.strip()
    lower = value.lower()

    if _CV_RE.match(value):
        return "vulnerability"
    if _TACTIC_RE.match(value):
        return "tactic"
    if _TECHNIQUE_RE.match(value):
        return "attack_pattern"
    if _SHA256_RE.match(value):
        return "malware_sample"
    if _HASH_RE.match(value):
        return "indicator"
    if _EMAIL_RE.match(value):
        return "indicator"
    if _IPV4_RE.match(value):
        return "indicator"
    if _URL_RE.match(value):
        return "indicator"
    if _DOMAIN_RE.match(value):
        return "indicator"
    if _APT_RE.search(lower):
        return "threat_actor"
    if lower in _THREAT_ACTOR_TERMS:
        return "threat_actor"
    if _SECTOR_HINT_RE.search(lower):
        return "sector"
    if _SERVICE_HINT_RE.search(lower):
        return "service"
    if _CREDENTIAL_HINT_RE.search(lower):
        return "credential"
    if _ARTIFACT_HINT_RE.search(lower):
        return "artifact"
    if "ransomware" in lower or "trojan" in lower or "wiper" in lower:
        return "malware"
    return "topic"


def _det_provenance_id(
    *,
    source_uri: str,
    relation_id: str,
    chunk_id: str,
    snippet: str,
) -> str:
    material = f"{source_uri}|{relation_id}|{chunk_id}|{snippet}"
    return str(uuid5(_NS_PROVENANCE, material))


def _timestamp_from_row(item: Dict[str, Any]) -> datetime:
    raw = item.get("timestamp") or item.get("@timestamp") or item.get("date")
    if not raw:
        return datetime.now(timezone.utc)
    text = str(raw).strip()
    if not text:
        return datetime.now(timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_aikg_file(raw: bytes, filename: str) -> List[Dict[str, Any]]:
    """Parse raw bytes as AIKG triples JSON.

    Accepts:
    - JSON array of triple objects, or
    - JSON object with ``{"triples": [...]}``.
    """
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {filename}: {exc}") from exc

    if isinstance(data, dict):
        triples = data.get("triples")
    else:
        triples = data

    if not isinstance(triples, list):
        raise ValueError(
            f"{filename} is not AIKG triples JSON (expected array or object.triples)"
        )

    triple_rows: List[Dict[str, Any]] = []
    for item in triples:
        if not isinstance(item, dict):
            continue
        if {"subject", "predicate", "object"}.issubset(item.keys()):
            triple_rows.append(item)

    if not triple_rows:
        raise ValueError(
            f"{filename} has no triple rows with subject/predicate/object keys"
        )

    return triple_rows


def ingest_aikg_triples(
    triples: List[Dict[str, Any]],
    graph_store: GraphStore,
    *,
    source_uri: str,
    include_inferred: bool = False,
    min_inferred_confidence: float = 0.60,
    allow_via_predicates: bool = False,
    model: str = "aikg-import",
    prompt_version: str = "aikg-json-v1",
) -> AikgImportResult:
    """Import AIKG triples into the graph store."""
    result = AikgImportResult()
    resolver = EntityResolver(graph_store)

    # Clamp confidence threshold so malformed env values cannot break imports.
    min_inferred_confidence = max(0.0, min(float(min_inferred_confidence), 1.0))

    touched_entities: set[str] = set()
    touched_relations: set[str] = set()

    for idx, row in enumerate(triples, 1):
        result.triples_seen += 1
        try:
            subject = str(row.get("subject") or "").strip()
            predicate_raw = str(row.get("predicate") or "").strip()
            obj = str(row.get("object") or "").strip()
            if not subject or not predicate_raw or not obj:
                result.skipped_invalid += 1
                continue
            if subject == obj:
                result.skipped_invalid += 1
                continue

            inferred = _coerce_inferred(row.get("inferred"))
            if inferred and not include_inferred:
                result.skipped_inferred += 1
                continue

            confidence = _coerce_confidence(row.get("confidence"), inferred=inferred)
            if inferred and confidence < min_inferred_confidence:
                result.skipped_low_confidence += 1
                continue

            predicate = normalize_predicate(predicate_raw)
            if not predicate:
                result.skipped_invalid += 1
                continue
            predicate = _PREDICATE_CANONICAL.get(predicate, predicate)

            if inferred and "_via_" in predicate and not allow_via_predicates:
                result.skipped_noisy_inferred += 1
                continue

            subject_type = _normalize_entity_type(row.get("subject_type"))
            if not subject_type:
                subject_type = _infer_entity_type(subject)
            object_type = _normalize_entity_type(row.get("object_type"))
            if not object_type:
                object_type = _infer_entity_type(obj)

            subject_ent = resolver.resolve(subject, entity_type=subject_type)
            object_ent = resolver.resolve(obj, entity_type=object_type)
            for ent in (subject_ent, object_ent):
                ent.attrs.setdefault("origin", "aikg-import")
                ent.attrs.setdefault("source_uri", source_uri)

            graph_store.upsert_entities([subject_ent, object_ent])
            touched_entities.add(subject_ent.id)
            touched_entities.add(object_ent.id)

            attrs: Dict[str, Any] = {
                "origin": "aikg-import",
                "source": "aikg-json",
                "inferred": inferred,
                "source_uri": source_uri,
            }
            chunk = row.get("chunk")
            if isinstance(chunk, int):
                attrs["chunk"] = chunk

            rel = Relation(
                id=str(uuid4()),
                subject_id=subject_ent.id,
                predicate=predicate,
                object_id=object_ent.id,
                confidence=confidence,
                attrs=attrs,
            )
            stored = graph_store.upsert_relations([rel])[0]
            touched_relations.add(stored.id)

            snippet = f"{subject} {predicate_raw} {obj}"
            chunk_id = f"chunk-{chunk}" if isinstance(chunk, int) else f"triple-{idx}"
            prov = Provenance(
                provenance_id=_det_provenance_id(
                    source_uri=source_uri,
                    relation_id=stored.id,
                    chunk_id=chunk_id,
                    snippet=snippet,
                ),
                source_uri=source_uri,
                chunk_id=chunk_id,
                start_offset=0,
                end_offset=0,
                snippet=snippet,
                extraction_run_id=f"aikg-import-{idx}",
                model=model,
                prompt_version=prompt_version,
                timestamp=_timestamp_from_row(row),
            )
            graph_store.attach_provenance(stored.id, prov)
            result.triples_imported += 1
        except Exception as exc:
            logger.warning("AIKG import failed for row %d: %s", idx, exc)
            result.errors.append(f"row {idx}: {exc}")

    result.entities_created = len(touched_entities)
    result.relations_created = len(touched_relations)
    return result
