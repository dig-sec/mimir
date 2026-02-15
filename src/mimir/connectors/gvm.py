"""GVM (Greenbone Vulnerability Management) → Mimir connector.

Pulls scan results from GVM via the GMP (Greenbone Management Protocol)
and imports structured vulnerability / attack-surface data as graph
entities and relationships.

Mapped entity types (Redamon-inspired schema)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* **ip_address** — scanned host with ASN metadata
* **port** — open port on a host
* **service** — running service with version/banner info
* **vulnerability** — scanner finding with severity/evidence
* **cve** — known CVE from NVD (linked by GVM NVTs)
* **technology** — detected software (OS, server, library)
* **domain** / **subdomain** — reverse-DNS hostnames from results

Design goals
~~~~~~~~~~~~
* **Structured-first**: exploit GVM's pre-extracted vulnerability data
  so we get graph data instantly, without waiting for an LLM pass.
* **Incremental**: use modification_time filter so only results
  newer than the last sync window are pulled.
* **Memory-constant**: page through results using ``first`` / ``rows``.
* **Non-blocking**: all public functions are synchronous and designed to
  run inside ``asyncio.to_thread()``.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from uuid import uuid4

from ..config import Settings
from ..dedupe import EntityResolver
from ..schemas import Entity, Provenance, Relation
from ..storage.base import GraphStore
from ..utils.provenance import NS_PROVENANCE_GVM, det_prov_id

logger = logging.getLogger(__name__)

_NS_PROVENANCE = NS_PROVENANCE_GVM

# Regex patterns
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_PORT_RE = re.compile(r"^(\d+)/(tcp|udp|sctp)$", re.IGNORECASE)
_SEVERITY_THRESHOLDS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "log": 0.0,
}


# ── Results ──────────────────────────────────────────────────


@dataclass
class GvmSyncResult:
    """Tracks statistics for a GVM sync cycle."""

    results_processed: int = 0
    hosts_seen: int = 0
    entities_created: int = 0
    relations_created: int = 0
    skipped_low_qod: int = 0
    skipped_existing: int = 0
    errors: List[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────


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
    """Deterministic provenance ID keyed by evidence granularity."""
    return det_prov_id(
        namespace=_NS_PROVENANCE,
        source_uri=source_uri,
        relation_id=relation_id,
        model=model,
        chunk_id=chunk_id,
        start_offset=start_offset,
        end_offset=end_offset,
        snippet=snippet,
    )


def _severity_label(cvss: float) -> str:
    """Map CVSS score to a severity label."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "log"


def _xml_text(element: Optional[ET.Element], path: str) -> str:
    """Safely extract text from an XML element by path."""
    if element is None:
        return ""
    node = element.find(path)
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def _xml_float(element: Optional[ET.Element], path: str) -> float:
    """Safely extract a float from an XML element by path."""
    text = _xml_text(element, path)
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        return 0.0


def _xml_int(element: Optional[ET.Element], path: str) -> int:
    """Safely extract an int from an XML element by path."""
    text = _xml_text(element, path)
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


def _parse_iso_datetime(value: str) -> Optional[datetime]:
    """Best-effort parse of an ISO timestamp string."""
    if not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_cves(text: str) -> List[str]:
    """Extract all CVE identifiers from a string."""
    return sorted(set(_CVE_RE.findall(text.upper())))


def _parse_port_proto(port_str: str) -> Tuple[Optional[int], Optional[str]]:
    """Parse '443/tcp' into (443, 'tcp')."""
    match = _PORT_RE.match(port_str.strip())
    if match:
        return int(match.group(1)), match.group(2).lower()
    return None, None


# ── GMP client wrapper ──────────────────────────────────────


def _create_gmp_connection(settings: Settings):
    """Create an appropriate GMP connection based on the settings."""
    from gvm.connections import TLSConnection, UnixSocketConnection

    conn_type = settings.gvm_connection_type.lower().strip()
    if conn_type == "unix":
        return UnixSocketConnection(path=settings.gvm_socket_path)
    elif conn_type == "tls":
        kwargs: Dict[str, Any] = {
            "hostname": settings.gvm_host,
            "port": settings.gvm_port,
        }
        if settings.gvm_ca_cert:
            kwargs["cafile"] = settings.gvm_ca_cert
        return TLSConnection(**kwargs)
    else:
        raise ValueError(
            f"Unsupported GVM_CONNECTION_TYPE: {conn_type!r}. " "Use 'unix' or 'tls'."
        )


def _iter_gvm_results(
    settings: Settings,
    *,
    since: datetime,
    until: Optional[datetime] = None,
    page_size: int = 100,
    max_results: int = 500,
) -> Iterator[ET.Element]:
    """Page through GVM results using GMP protocol.

    Yields individual ``<result>`` XML elements.
    """
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform

    connection = _create_gmp_connection(settings)
    transform = EtreeCheckCommandTransform()

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(settings.gvm_username, settings.gvm_password)

        # Build a filter string that limits results by modification time
        filter_str = (
            f"modification_time>{since.strftime('%Y-%m-%dT%H:%M:%S')} "
            f"min_qod={settings.gvm_min_qod} "
            f"rows={min(page_size, max_results)} "
            f"sort-reverse=modification_time"
        )
        if until:
            filter_str += (
                f" and modification_time<{until.strftime('%Y-%m-%dT%H:%M:%S')}"
            )

        total_yielded = 0
        first = 1

        while total_yielded < max_results:
            current_filter = f"{filter_str} first={first}"
            response = gmp.get_results(filter_string=current_filter)

            results = response.findall("result")
            if not results:
                break

            for result_elem in results:
                if total_yielded >= max_results:
                    break
                yield result_elem
                total_yielded += 1

            if len(results) < page_size:
                break
            first += len(results)


# ── Entity extraction from GMP result XML ───────────────────


def _extract_host_entity(
    result_elem: ET.Element,
    resolver: EntityResolver,
) -> Optional[Entity]:
    """Extract an ip_address entity from a GVM result."""
    host = _xml_text(result_elem, "host")
    if not host:
        return None

    entity = resolver.resolve(host, entity_type="ip_address")
    entity.attrs["origin"] = "gvm"
    entity.attrs["version"] = "ipv4" if "." in host else "ipv6"

    # Extract hostname if available
    hostname_elem = result_elem.find("host/hostname")
    if hostname_elem is not None and hostname_elem.text:
        hostname = hostname_elem.text.strip()
        if hostname and hostname != host:
            entity.attrs["hostname"] = hostname
            if hostname not in entity.aliases:
                entity.aliases.append(hostname)

    # Extract asset/host details
    asset = result_elem.find("host/asset")
    if asset is not None:
        asset_id = asset.get("asset_id", "")
        if asset_id:
            entity.attrs["gvm_asset_id"] = asset_id

    return entity


def _extract_port_entity(
    result_elem: ET.Element,
    resolver: EntityResolver,
    host_name: str,
) -> Optional[Entity]:
    """Extract a port entity from a GVM result."""
    port_str = _xml_text(result_elem, "port")
    if not port_str:
        return None

    port_num, protocol = _parse_port_proto(port_str)
    if port_num is None:
        return None

    port_key = f"{host_name}:{port_num}/{protocol}"
    entity = resolver.resolve(port_key, entity_type="port")
    entity.attrs["origin"] = "gvm"
    entity.attrs["number"] = port_num
    entity.attrs["protocol"] = protocol or "tcp"
    entity.attrs["state"] = "open"
    entity.attrs["host"] = host_name

    return entity


def _extract_vulnerability_entity(
    result_elem: ET.Element,
    resolver: EntityResolver,
) -> Optional[Entity]:
    """Extract a vulnerability entity from a GVM result."""
    nvt = result_elem.find("nvt")
    if nvt is None:
        return None

    nvt_oid = nvt.get("oid", "")
    nvt_name = _xml_text(nvt, "name")

    if not nvt_name:
        return None

    entity = resolver.resolve(nvt_name, entity_type="vulnerability")
    entity.attrs["origin"] = "gvm"
    entity.attrs["source"] = "gvm"

    if nvt_oid:
        entity.attrs["nvt_oid"] = nvt_oid

    # Severity
    severity = _xml_float(result_elem, "severity")
    entity.attrs["cvss"] = severity
    entity.attrs["severity"] = _severity_label(severity)

    # QoD (Quality of Detection)
    qod_value = _xml_int(result_elem, "qod/value")
    if qod_value:
        entity.attrs["qod"] = qod_value
    qod_type = _xml_text(result_elem, "qod/type")
    if qod_type:
        entity.attrs["qod_type"] = qod_type

    # NVT metadata
    nvt_family = _xml_text(nvt, "family")
    if nvt_family:
        entity.attrs["category"] = nvt_family

    # Solution
    solution = result_elem.find("nvt/solution")
    if solution is not None:
        sol_type = solution.get("type", "")
        sol_text = (solution.text or "").strip()
        if sol_type:
            entity.attrs["solution_type"] = sol_type
        if sol_text:
            entity.attrs["solution"] = sol_text[:500]

    # Description from the result
    description = _xml_text(result_elem, "description")
    if description:
        entity.attrs["description"] = description[:1000]

    # Tags (contains CVSS, summary, etc.)
    tags = _xml_text(nvt, "tags")
    if tags:
        entity.attrs["nvt_tags"] = tags[:500]

    return entity


def _extract_service_entity(
    result_elem: ET.Element,
    resolver: EntityResolver,
    host_name: str,
    port_num: Optional[int],
    protocol: Optional[str],
) -> Optional[Entity]:
    """Attempt to extract a service entity from NVT detection results."""
    nvt = result_elem.find("nvt")
    if nvt is None:
        return None

    nvt_family = _xml_text(nvt, "family")
    description = _xml_text(result_elem, "description")

    # Service detection NVTs typically have family "Service detection"
    # or "Product detection"
    if nvt_family not in ("Service detection", "Product detection"):
        return None

    if not description or not host_name:
        return None

    # Attempt to parse the product/service name from the description
    nvt_name = _xml_text(nvt, "name")
    service_name = nvt_name or "unknown"

    service_key = f"{host_name}:{port_num or 0}/{service_name}"
    entity = resolver.resolve(service_key, entity_type="service")
    entity.attrs["origin"] = "gvm"
    entity.attrs["name"] = service_name
    entity.attrs["host"] = host_name

    if port_num is not None:
        entity.attrs["port"] = port_num
    if protocol:
        entity.attrs["protocol"] = protocol

    # Try to extract product/version from description
    version_match = re.search(
        r"(?:version|ver\.?)\s*[:=]?\s*([\d][.\d\w-]*)", description, re.IGNORECASE
    )
    if version_match:
        entity.attrs["version"] = version_match.group(1)

    product_match = re.search(
        r"(?:product|software|application)\s*[:=]?\s*(.+?)(?:\s*version|\s*$)",
        description,
        re.IGNORECASE,
    )
    if product_match:
        entity.attrs["product"] = product_match.group(1).strip()[:200]

    if description:
        entity.attrs["banner"] = description[:300]

    return entity


def _extract_technology_entity(
    result_elem: ET.Element,
    resolver: EntityResolver,
    host_name: str,
) -> Optional[Entity]:
    """Extract a technology entity from OS/product detection results."""
    nvt = result_elem.find("nvt")
    if nvt is None:
        return None

    nvt_family = _xml_text(nvt, "family")
    if nvt_family not in ("Product detection", "General"):
        return None

    description = _xml_text(result_elem, "description")
    nvt_name = _xml_text(nvt, "name")

    if not description and not nvt_name:
        return None

    tech_name = nvt_name or "unknown"

    entity = resolver.resolve(f"{tech_name}@{host_name}", entity_type="technology")
    entity.attrs["origin"] = "gvm"
    entity.attrs["name"] = tech_name
    entity.attrs["detected_by"] = "gvm"
    entity.attrs["host"] = host_name

    # Attempt version extraction
    version_match = re.search(
        r"(?:version|ver\.?)\s*[:=]?\s*([\d][.\d\w-]*)", description, re.IGNORECASE
    )
    if version_match:
        entity.attrs["version"] = version_match.group(1)

    # Confidence from QoD
    qod = _xml_int(result_elem, "qod/value")
    if qod:
        entity.attrs["confidence"] = qod

    return entity


def _extract_cve_entities(
    result_elem: ET.Element,
    resolver: EntityResolver,
) -> List[Entity]:
    """Extract CVE entities referenced by the NVT."""
    nvt = result_elem.find("nvt")
    if nvt is None:
        return []

    # CVEs from refs
    cve_ids: List[str] = []
    refs = nvt.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            ref_type = ref.get("type", "").lower()
            ref_id = ref.get("id", "").strip().upper()
            if ref_type == "cve" and ref_id.startswith("CVE-"):
                cve_ids.append(ref_id)

    # Also extract from tags
    tags = _xml_text(nvt, "tags")
    if tags:
        cve_ids.extend(_extract_cves(tags))

    # Also from description
    description = _xml_text(result_elem, "description")
    if description:
        cve_ids.extend(_extract_cves(description))

    seen: set[str] = set()
    entities: List[Entity] = []
    severity = _xml_float(result_elem, "severity")

    for cve_id in cve_ids:
        if cve_id in seen:
            continue
        seen.add(cve_id)

        entity = resolver.resolve(cve_id, entity_type="cve")
        entity.attrs["origin"] = "gvm"
        entity.attrs["id"] = cve_id
        entity.attrs["cvss"] = severity
        entity.attrs["severity"] = _severity_label(severity).upper()

        entities.append(entity)

    return entities


# ── Main sync function ──────────────────────────────────────


def _process_result(
    result_elem: ET.Element,
    graph_store: GraphStore,
    resolver: EntityResolver,
    source_uri: str,
    result: GvmSyncResult,
) -> None:
    """Process a single GVM result element into graph entities + relations."""
    entities: List[Entity] = []
    relations: List[Relation] = []

    now = datetime.now(timezone.utc)

    # Timestamp for provenance
    mod_time_str = _xml_text(result_elem, "modification_time")
    timestamp = _parse_iso_datetime(mod_time_str) or now

    result_id = result_elem.get("id", str(uuid4()))
    severity = _xml_float(result_elem, "severity")

    # ── Host entity ──
    host_entity = _extract_host_entity(result_elem, resolver)
    if host_entity is None:
        return
    entities.append(host_entity)
    host_name = host_entity.name

    # ── Port entity ──
    port_str = _xml_text(result_elem, "port")
    port_num, protocol = _parse_port_proto(port_str)
    port_entity = _extract_port_entity(result_elem, resolver, host_name)
    if port_entity is not None:
        entities.append(port_entity)

    # ── Vulnerability entity ──
    vuln_entity = _extract_vulnerability_entity(result_elem, resolver)
    if vuln_entity is not None:
        entities.append(vuln_entity)

    # ── Service entity (from detection NVTs) ──
    service_entity = _extract_service_entity(
        result_elem, resolver, host_name, port_num, protocol
    )
    if service_entity is not None:
        entities.append(service_entity)

    # ── Technology entity ──
    tech_entity = _extract_technology_entity(result_elem, resolver, host_name)
    if tech_entity is not None:
        entities.append(tech_entity)

    # ── CVE entities ──
    cve_entities = _extract_cve_entities(result_elem, resolver)
    entities.extend(cve_entities)

    # ── Persist entities ──
    if entities:
        graph_store.upsert_entities(entities)

    # ── Build relations ──
    # host → has_port → port
    if port_entity is not None:
        relations.append(
            Relation(
                id=str(uuid4()),
                subject_id=host_entity.id,
                predicate="has_port",
                object_id=port_entity.id,
                confidence=0.95,
                attrs={
                    "origin": "gvm",
                    "source_uri": source_uri,
                },
            )
        )

    # host (or port) → has_vulnerability → vulnerability
    if vuln_entity is not None:
        vuln_subject = port_entity if port_entity is not None else host_entity
        relations.append(
            Relation(
                id=str(uuid4()),
                subject_id=vuln_subject.id,
                predicate="has_vulnerability",
                object_id=vuln_entity.id,
                confidence=min(max(severity / 10.0, 0.3), 1.0),
                attrs={
                    "origin": "gvm",
                    "source_uri": source_uri,
                    "severity": _severity_label(severity),
                    "cvss": severity,
                },
            )
        )

    # host → runs_service → service
    if service_entity is not None:
        relations.append(
            Relation(
                id=str(uuid4()),
                subject_id=host_entity.id,
                predicate="runs_service",
                object_id=service_entity.id,
                confidence=0.85,
                attrs={
                    "origin": "gvm",
                    "source_uri": source_uri,
                },
            )
        )

    # service → on_port → port
    if service_entity is not None and port_entity is not None:
        relations.append(
            Relation(
                id=str(uuid4()),
                subject_id=service_entity.id,
                predicate="on_port",
                object_id=port_entity.id,
                confidence=0.90,
                attrs={
                    "origin": "gvm",
                    "source_uri": source_uri,
                },
            )
        )

    # host → uses_technology → technology
    if tech_entity is not None:
        relations.append(
            Relation(
                id=str(uuid4()),
                subject_id=host_entity.id,
                predicate="uses_technology",
                object_id=tech_entity.id,
                confidence=0.80,
                attrs={
                    "origin": "gvm",
                    "source_uri": source_uri,
                },
            )
        )

    # vulnerability → references_cve → CVE
    if vuln_entity is not None:
        for cve_ent in cve_entities:
            relations.append(
                Relation(
                    id=str(uuid4()),
                    subject_id=vuln_entity.id,
                    predicate="references_cve",
                    object_id=cve_ent.id,
                    confidence=0.95,
                    attrs={
                        "origin": "gvm",
                        "source_uri": source_uri,
                        "cve_id": cve_ent.attrs.get("id", ""),
                    },
                )
            )

    # ── Persist relations + provenance ──
    if relations:
        stored_relations = graph_store.upsert_relations(relations)
        for stored_rel in stored_relations:
            snippet = (
                f"GVM result {result_id}: "
                f"{_xml_text(result_elem, 'nvt/name') or 'scan finding'} "
                f"on {host_name}"
            )
            prov = Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored_rel.id,
                    model="gvm-connector",
                    chunk_id=f"gvm-result-{result_id}",
                    start_offset=0,
                    end_offset=0,
                    snippet=snippet,
                ),
                source_uri=source_uri,
                chunk_id=f"gvm-result-{result_id}",
                start_offset=0,
                end_offset=0,
                snippet=snippet,
                extraction_run_id=f"gvm-sync-{result_id}",
                model="gvm-connector",
                prompt_version="gvm-v1",
                timestamp=timestamp,
            )
            graph_store.attach_provenance(stored_rel.id, prov)

    result.entities_created += len(entities)
    result.relations_created += len(relations)


def sync_gvm(
    *,
    settings: Settings,
    graph_store: GraphStore,
    since: datetime,
    until: Optional[datetime] = None,
    max_results: Optional[int] = None,
) -> GvmSyncResult:
    """Pull results from GVM and import into the Mimir knowledge graph.

    Parameters
    ----------
    settings:
        Application settings (contains GVM connection details).
    graph_store:
        The graph store to upsert entities/relations into.
    since:
        Only process results modified after this time.
    until:
        Only process results modified before this time (optional).
    max_results:
        Cap on the number of GVM results to process (defaults to
        ``settings.gvm_max_results``).
    """
    result = GvmSyncResult()
    resolver = EntityResolver(graph_store)
    effective_max = max_results if max_results is not None else settings.gvm_max_results
    source_uri = f"gvm://{settings.gvm_host or 'localhost'}"
    hosts_seen: set[str] = set()

    logger.info(
        "GVM sync started: since=%s, until=%s, max_results=%d",
        since.isoformat(),
        (until or "now"),
        effective_max,
    )

    try:
        for result_elem in _iter_gvm_results(
            settings,
            since=since,
            until=until,
            max_results=effective_max,
        ):
            try:
                host = _xml_text(result_elem, "host")
                if host:
                    hosts_seen.add(host)

                # Skip low QoD results
                qod = _xml_int(result_elem, "qod/value")
                if qod and qod < settings.gvm_min_qod:
                    result.skipped_low_qod += 1
                    continue

                _process_result(
                    result_elem,
                    graph_store,
                    resolver,
                    source_uri,
                    result,
                )
                result.results_processed += 1

            except Exception as exc:
                result_id = result_elem.get("id", "?")
                errmsg = f"result {result_id}: {exc}"
                logger.warning("GVM result processing failed: %s", errmsg)
                result.errors.append(errmsg)

    except Exception as exc:
        errmsg = f"GVM connection/query failed: {exc}"
        logger.error(errmsg)
        result.errors.append(errmsg)

    result.hosts_seen = len(hosts_seen)

    logger.info(
        "GVM sync complete: %d results, %d hosts, %d entities, %d relations, "
        "%d skipped (low QoD), %d errors",
        result.results_processed,
        result.hosts_seen,
        result.entities_created,
        result.relations_created,
        result.skipped_low_qod,
        len(result.errors),
    )

    return result
