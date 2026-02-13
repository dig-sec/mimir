"""Feedly → Wellspring connector.

Reads articles from one or more Elasticsearch indices (e.g. ``feedly_news``)
and imports the Feedly-AI-extracted entities, topics, and IOCs as structured
graph data.  Optionally queues the article text for deeper LLM extraction.

Design goals
~~~~~~~~~~~~
* **Structured-first**: exploit Feedly's pre-extracted entities / IOCs so
  we get graph data instantly, without waiting for an LLM pass.
* **Incremental**: track the most-recent ``fetched_at`` timestamp per index
  so only new articles are pulled on each sync.
* **Memory-constant**: page through search_after to avoid loading large
  result sets in memory.
* **Non-blocking**: every public function is synchronous and designed to
  run inside ``asyncio.to_thread()``.
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from uuid import UUID, uuid4, uuid5

from elasticsearch import Elasticsearch

from ..config import Settings
from ..dedupe import EntityResolver
from ..schemas import ExtractionRun, Provenance, Relation
from ..storage.base import GraphStore
from ..storage.run_store import RunStore

logger = logging.getLogger(__name__)

# Namespace UUID for deterministic provenance IDs
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
    """Deterministic provenance ID keyed by evidence granularity."""
    snippet_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()
    material = (
        f"{source_uri}|{relation_id}|{model}|{chunk_id}|"
        f"{start_offset}|{end_offset}|{snippet_hash}"
    )
    return str(uuid5(_NS_PROVENANCE, material))


# ── Feedly entity-type → Wellspring entity-type (STIX 2.1 aligned) ──
_FEEDLY_TYPE_MAP: Dict[str, str] = {
    "threatActor": "threat_actor",  # STIX: threat-actor
    "malwareFamily": "malware",  # STIX: malware
    "mitreAttack": "attack_pattern",  # STIX: attack-pattern
    "vulnerability": "vulnerability",  # STIX: vulnerability
    "org": "identity",  # STIX: identity
    "person": "identity",  # STIX: identity
    "location": "location",  # STIX: location
    # consumerGood / technology: routed by _route_consumer_good()
    # publisher: skipped (noise — source is already in feed_name)
    # other: skipped
}

# IOC type → Wellspring entity type
_IOC_TYPE_MAP: Dict[str, str] = {
    "url": "indicator",
    "ip": "indicator",
    "domain": "indicator",
    "hash": "indicator",
    "email": "indicator",
    "cve": "vulnerability",
    "filename": "indicator",
}

# ── Platform keywords for consumerGood routing ───────────────
_PLATFORM_KEYWORDS = frozenset(
    {
        "windows",
        "linux",
        "android",
        "ios",
        "macos",
        "mac os",
        "ubuntu",
        "debian",
        "centos",
        "red hat",
        "rhel",
        "fedora",
        "freebsd",
        "chromeos",
        "chrome os",
        "unix",
        "solaris",
        "aix",
        "vmware esxi",
        "esxi",
    }
)

# Generic labels that are never CTI-relevant entities
_NOISE_LABELS = frozenset(
    {
        "inside",
        "outside",
        "top",
        "free",
        "best",
        "new",
        "first",
        "end",
        "start",
        "smart",
        "next",
        "open",
        "custom",
        "advanced",
        "simple",
        "modern",
        "global",
        "latest",
        "unknown",
        "december",
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
    }
)

# MITRE labels that are meta-noise, not actual technique/tactic
_MITRE_NOISE_LABELS = frozenset(
    {
        "tactics and techniques",
        "tactics",
        "techniques",
        "mitre att&ck",
        "mitre attack",
        "enterprise",
        "initial access",
        "execution",
        "persistence",
    }
)

_MITRE_ID_RE = re.compile(r"[TtSs]\d{4}(?:\.\d{3})?|TA\d{4}")

# ── STIX 2.1 SRO cross-link rules: (subject_type, object_type, predicate)
_CROSS_LINK_RULES: List[Tuple[str, str, str]] = [
    ("threat_actor", "malware", "uses"),
    ("threat_actor", "attack_pattern", "uses"),
    ("threat_actor", "tool", "uses"),
    ("threat_actor", "identity", "targets"),
    ("threat_actor", "infrastructure", "targets"),
    ("threat_actor", "vulnerability", "targets"),
    ("threat_actor", "location", "located_at"),
    ("malware", "attack_pattern", "uses"),
    ("malware", "vulnerability", "exploits"),
    ("malware", "infrastructure", "targets"),
    ("malware", "tool", "uses"),
    ("malware", "identity", "targets"),
    ("tool", "vulnerability", "exploits"),
    ("tool", "attack_pattern", "uses"),
]


def _route_consumer_good(label: str) -> Optional[str]:
    """Route Feedly consumerGood to infrastructure (platform) or tool."""
    lower = label.lower().strip()
    if lower in _NOISE_LABELS or len(lower) < 3:
        return None
    for kw in _PLATFORM_KEYWORDS:
        if kw in lower:
            return "infrastructure"
    return "tool"


def _is_noise_mitre(label: str) -> bool:
    """Return True if a MITRE ATT&CK label is meta-noise."""
    return label.lower().strip() in _MITRE_NOISE_LABELS


def _is_noise_entity(label: str) -> bool:
    """Return True if label is too generic to be a real CTI entity."""
    lower = label.lower().strip()
    return lower in _NOISE_LABELS or len(lower) < 2


def _extract_mitre_id(label: str) -> Optional[str]:
    """Extract MITRE ATT&CK ID (e.g. T1486, TA0005) from a label."""
    m = _MITRE_ID_RE.search(label)
    return m.group(0).upper() if m else None


def _salience_confidence(fe: Dict[str, Any]) -> float:
    """Compute confidence from Feedly salience and disambiguation."""
    base = 0.90 if fe.get("salienceLevel") == "about" else 0.65
    if fe.get("disambiguated"):
        base = min(base + 0.05, 1.0)
    return round(base, 2)


_STRIP_HTML_RE = re.compile(r"<[^>]+>")
_MULTI_WS_RE = re.compile(r"\s{2,}")


def _strip_html(text: str) -> str:
    text = html.unescape(text)
    text = _STRIP_HTML_RE.sub(" ", text)
    return _MULTI_WS_RE.sub(" ", text).strip()


def _epoch_ms_to_dt(epoch_ms: Any) -> Optional[datetime]:
    """Convert Feedly epoch-milliseconds to a UTC datetime."""
    if epoch_ms is None:
        return None
    try:
        ts = int(epoch_ms) / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def _iso_to_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# ── Results ──────────────────────────────────────────────────


@dataclass
class FeedlySyncResult:
    articles_processed: int = 0
    entities_created: int = 0
    relations_created: int = 0
    iocs_created: int = 0
    articles_queued_for_llm: int = 0
    errors: List[str] = field(default_factory=list)


# ── Core sync logic ─────────────────────────────────────────


def sync_feedly_index(
    settings: Settings,
    graph_store: GraphStore,
    run_store: Optional[RunStore] = None,
    *,
    index_name: str = "feedly_news",
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    max_articles: int = 0,
    queue_for_llm: bool = False,
    progress_cb: Optional[Any] = None,
) -> FeedlySyncResult:
    """Pull articles from a Feedly ES index and import structured CTI data.

    Parameters
    ----------
    settings : Settings
        Application settings (ES connection details come from connector_* fields).
    graph_store : GraphStore
        Where to upsert entities / relations.
    run_store : RunStore, optional
        If provided *and* ``queue_for_llm`` is True, article text is queued
        for LLM extraction.
    index_name : str
        Elasticsearch index to read from.
    since : datetime, optional
        Only fetch articles with ``fetched_at >= since``.  Defaults to
        ``elastic_connector_lookback_minutes`` from settings.
    max_articles : int
        Cap on articles to process (0 = unlimited).
    queue_for_llm : bool
        Whether to also queue the raw article text for LLM triple extraction.
    progress_cb : callable, optional
        ``progress_cb(message)`` for progress reporting.
    """
    result = FeedlySyncResult()
    resolver = EntityResolver(graph_store)
    sync_run_id = f"feedly-sync-{uuid4()}"

    # Build ES client for the source index (may be on a different cluster)
    client = _create_source_client(settings)

    if since is None:
        from datetime import timedelta

        since = datetime.now(timezone.utc) - timedelta(
            minutes=settings.elastic_connector_lookback_minutes
        )

    def _progress(msg: str):
        if progress_cb:
            progress_cb(msg)

    _progress(f"Scanning {index_name} since {since.isoformat()}...")

    # Use bulk_mode if available (ElasticGraphStore) to avoid per-write
    # refresh=wait_for — improves throughput ~30-60x for batch imports.
    import contextlib

    bulk_ctx = (
        graph_store.bulk_mode()
        if hasattr(graph_store, "bulk_mode")
        else contextlib.nullcontext()
    )

    try:
        with bulk_ctx:
            for i, doc in enumerate(
                _iter_feedly_docs(client, index_name, since, settings, until=until)
            ):
                if max_articles and i >= max_articles:
                    break

                try:
                    _process_article(
                        doc,
                        graph_store,
                        resolver,
                        run_store,
                        settings,
                        sync_run_id,
                        result,
                        queue_for_llm,
                    )
                except Exception as exc:
                    title = doc.get("entry", {}).get("title", "?")[:60]
                    result.errors.append(f"{title}: {exc}")
                    logger.warning("Failed to process article: %s", exc)

                if (i + 1) % 50 == 0:
                    _progress(
                        f"Processed {i+1} articles: "
                        f"{result.entities_created} entities, "
                        f"{result.relations_created} relations, "
                        f"{result.iocs_created} IOCs"
                    )
    finally:
        client.close()

    logger.info(
        "Feedly sync complete: %d articles, %d entities, %d relations, %d IOCs, %d queued, %d errors",
        result.articles_processed,
        result.entities_created,
        result.relations_created,
        result.iocs_created,
        result.articles_queued_for_llm,
        len(result.errors),
    )
    return result


def _create_source_client(settings: Settings) -> Elasticsearch:
    """Create an ES client pointing at the source Feedly index."""
    hosts = settings.elastic_connector_hosts_list
    kwargs: Dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": settings.elastic_connector_verify_certs,
        "request_timeout": settings.elastic_connector_timeout_seconds,
    }
    if settings.elastic_connector_user:
        kwargs["basic_auth"] = (
            settings.elastic_connector_user,
            settings.elastic_connector_password,
        )
    return Elasticsearch(**kwargs)


def _iter_feedly_docs(
    client: Elasticsearch,
    index_name: str,
    since: datetime,
    settings: Settings,
    *,
    until: Optional[datetime] = None,
) -> Iterator[Dict[str, Any]]:
    """Page through feedly docs using search_after for constant memory."""
    page_size = settings.elastic_connector_page_size

    time_filter: Dict[str, Any] = {"gte": since.isoformat()}
    if until is not None:
        time_filter["lt"] = until.isoformat()

    query: Dict[str, Any] = {
        "bool": {
            "must": [
                {"range": {"fetched_at": time_filter}},
            ]
        }
    }

    sort = [{"fetched_at": "asc"}, {"_shard_doc": "asc"}]
    search_after = None

    while True:
        body: Dict[str, Any] = {
            "query": query,
            "sort": sort,
            "size": page_size,
            "_source": [
                "entry.id",
                "entry.title",
                "entry.content.content",
                "entry.summary.content",
                "entry.fullContent",
                "entry.abstract.text",
                "entry.entities",
                "entry.commonTopics",
                "entry.indicatorsOfCompromise",
                "entry.published",
                "entry.canonicalUrl",
                "entry.alternate.href",
                "entry.origin.title",
                "entry.author",
                "entry.language",
                "entry.keywords",
                "entry.categories",
                "entry.leoSummary",
                "feed_name",
                "fetched_at",
                "entry_id",
            ],
        }
        if search_after:
            body["search_after"] = search_after

        resp = client.search(index=index_name, **body)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return

        for hit in hits:
            yield hit["_source"]

        search_after = hits[-1]["sort"]


def _create_cross_links(
    entities_by_type: Dict[str, list],
    entity_salience: Dict[str, str],
    graph_store: GraphStore,
    source_uri: str,
    sync_run_id: str,
    published_dt: datetime,
    title: str,
    result: FeedlySyncResult,
) -> None:
    """Create STIX 2.1 SRO cross-links between co-occurring entities.

    Uses the ``_CROSS_LINK_RULES`` table to generate entity-to-entity
    relationships (e.g. threat_actor ``uses`` malware) when both entities
    appear in the same article.  At least one entity must have salience
    "about" to avoid noisy mention×mention links.
    """
    for subj_type, obj_type, predicate in _CROSS_LINK_RULES:
        subjects = entities_by_type.get(subj_type, [])
        objects = entities_by_type.get(obj_type, [])

        for subj in subjects:
            for obj in objects:
                if subj.id == obj.id:
                    continue

                subj_sal = entity_salience.get(subj.id, "mention")
                obj_sal = entity_salience.get(obj.id, "mention")

                # Require at least one "about"-level entity
                if subj_sal != "about" and obj_sal != "about":
                    continue

                # Confidence reflects co-occurrence strength
                if subj_sal == "about" and obj_sal == "about":
                    confidence = 0.80
                else:
                    confidence = 0.65

                rel = Relation(
                    id=str(uuid4()),
                    subject_id=subj.id,
                    predicate=predicate,
                    object_id=obj.id,
                    confidence=confidence,
                    attrs={
                        "origin": "feedly",
                        "inference": "co-occurrence",
                        "source_article": title[:200],
                    },
                )
                stored = graph_store.upsert_relations([rel])[0]
                snippet = (
                    f"Co-occurrence: {subj.name} {predicate} "
                    f"{obj.name} in: {title[:80]}"
                )
                prov = Provenance(
                    provenance_id=_det_prov_id(
                        source_uri=source_uri,
                        relation_id=stored.id,
                        model="feedly-co-occurrence",
                        chunk_id=stored.id,
                        start_offset=0,
                        end_offset=0,
                        snippet=snippet,
                    ),
                    source_uri=source_uri,
                    chunk_id=stored.id,
                    start_offset=0,
                    end_offset=0,
                    snippet=snippet,
                    extraction_run_id=sync_run_id,
                    model="feedly-co-occurrence",
                    prompt_version="feedly-crosslink-v1",
                    timestamp=published_dt,
                )
                graph_store.attach_provenance(stored.id, prov)
                result.relations_created += 1


def _process_article(
    doc: Dict[str, Any],
    graph_store: GraphStore,
    resolver: EntityResolver,
    run_store: Optional[RunStore],
    settings: Settings,
    sync_run_id: str,
    result: FeedlySyncResult,
    queue_for_llm: bool,
) -> None:
    """Process a single Feedly article into STIX 2.1-aligned graph data.

    Creates:
    - A ``report`` entity for the article
    - Typed CTI entities (threat_actor, malware, attack_pattern, …)
    - Report → ``mentions`` → Entity relations
    - Entity ↔ Entity cross-links using STIX SRO predicates
    - IOC entities with ``contains_ioc`` relations
    """
    entry = doc.get("entry", {})
    result.articles_processed += 1

    title = entry.get("title", "").strip()
    feed_name = doc.get("feed_name", "")
    published_dt = _epoch_ms_to_dt(entry.get("published")) or datetime.now(timezone.utc)

    # Build source URI from canonical URL or entry ID
    canonical_url = entry.get("canonicalUrl", "")
    alt_links = entry.get("alternate", [])
    if not canonical_url and alt_links:
        if isinstance(alt_links, list) and alt_links:
            canonical_url = alt_links[0].get("href", "")
        elif isinstance(alt_links, dict):
            canonical_url = alt_links.get("href", "")
    source_uri = (
        f"feedly://{canonical_url}"
        if canonical_url
        else f"feedly://{entry.get('id', uuid4())}"
    )

    # ── Extract article text ─────────────────────────────────
    text_parts = []
    if title:
        text_parts.append(title)
    for field_name in ("content", "summary"):
        sub = entry.get(field_name)
        if isinstance(sub, dict):
            raw = sub.get("content", "")
        elif isinstance(sub, str):
            raw = sub
        else:
            continue
        if raw:
            text_parts.append(
                _strip_html(raw) if settings.elastic_connector_strip_html else raw
            )
    if entry.get("fullContent"):
        text_parts.append(
            _strip_html(entry["fullContent"])
            if settings.elastic_connector_strip_html
            else entry["fullContent"]
        )
    if entry.get("abstract", {}).get("text"):
        text_parts.append(entry["abstract"]["text"])
    full_text = "\n\n".join(text_parts)

    # ── Create the article entity ────────────────────────────
    article_entity = resolver.resolve(title or source_uri, entity_type="report")
    article_entity.attrs["source_url"] = canonical_url
    article_entity.attrs["feed_name"] = feed_name
    article_entity.attrs["published"] = published_dt.isoformat()
    article_entity.attrs["origin"] = "feedly"
    graph_store.upsert_entities([article_entity])
    result.entities_created += 1

    # ── Process Feedly AI entities (STIX 2.1 aligned) ──────────
    entities_by_type: Dict[str, list] = defaultdict(list)
    entity_salience: Dict[str, str] = {}

    for fe in entry.get("entities", []):
        label = fe.get("label", "").strip()
        if not label or _is_noise_entity(label):
            continue

        feedly_type = fe.get("type", "other")
        feedly_id = fe.get("id", "")

        # Detect CVEs by id prefix when type field is missing
        if feedly_type == "other" and feedly_id.startswith("vulnerability/"):
            feedly_type = "vulnerability"

        # Smart type routing
        if feedly_type in ("consumerGood", "technology"):
            ws_type = _route_consumer_good(label)
        elif feedly_type == "mitreAttack":
            ws_type = None if _is_noise_mitre(label) else "attack_pattern"
        else:
            ws_type = _FEEDLY_TYPE_MAP.get(feedly_type)

        if not ws_type:
            continue

        entity = resolver.resolve(label, entity_type=ws_type)
        entity.attrs["feedly_id"] = fe.get("id", "")
        entity.attrs["origin"] = "feedly"

        # Attach MITRE ATT&CK ID as attribute
        if feedly_type == "mitreAttack":
            mitre_id = _extract_mitre_id(label)
            if mitre_id:
                entity.attrs["mitre_id"] = mitre_id

        # Attach CVE vulnerability metadata
        vuln_info = fe.get("vulnerabilityInfo")
        if vuln_info and ws_type == "vulnerability":
            if vuln_info.get("cvssScore") is not None:
                entity.attrs["cvss_score"] = vuln_info["cvssScore"]
            if vuln_info.get("hasExploit") is not None:
                entity.attrs["has_exploit"] = vuln_info["hasExploit"]
            if vuln_info.get("hasPatch") is not None:
                entity.attrs["has_patch"] = vuln_info["hasPatch"]

        graph_store.upsert_entities([entity])
        result.entities_created += 1

        # Track for cross-linking
        salience = fe.get("salienceLevel", "mention")
        entities_by_type[ws_type].append(entity)
        entity_salience[entity.id] = salience

        # Report → mentions → Entity (salience-based confidence)
        confidence = _salience_confidence(fe)

        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate="mentions",
            object_id=entity.id,
            confidence=confidence,
            attrs={"origin": "feedly", "salience": salience},
        )
        stored = graph_store.upsert_relations([rel])[0]
        chunk_id = str(fe.get("id", stored.id))
        snippet = f"Feedly: {title[:100]} \u2192 {label}"
        prov = Provenance(
            provenance_id=_det_prov_id(
                source_uri=source_uri,
                relation_id=stored.id,
                model="feedly-ai",
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
            model="feedly-ai",
            prompt_version="feedly-entities-v2",
            timestamp=published_dt,
        )
        graph_store.attach_provenance(stored.id, prov)
        result.relations_created += 1

        # Process Feedly "causes" (inferred relationships)
        for cause in fe.get("causes", []):
            cause_label = cause.get("label", "").strip()
            if not cause_label or _is_noise_entity(cause_label):
                continue
            cause_entity = resolver.resolve(cause_label, entity_type=ws_type)
            cause_entity.attrs["origin"] = "feedly"
            graph_store.upsert_entities([cause_entity])
            result.entities_created += 1

            cause_rel = Relation(
                id=str(uuid4()),
                subject_id=entity.id,
                predicate="related_to",
                object_id=cause_entity.id,
                confidence=0.70,
                attrs={"origin": "feedly", "relationship": "causes"},
            )
            stored_cause = graph_store.upsert_relations([cause_rel])[0]
            cause_chunk_id = str(cause.get("id", stored_cause.id))
            cause_snippet = f"Feedly cause: {label} \u2192 {cause_label}"
            graph_store.attach_provenance(
                stored_cause.id,
                Provenance(
                    provenance_id=_det_prov_id(
                        source_uri=source_uri,
                        relation_id=stored_cause.id,
                        model="feedly-ai",
                        chunk_id=cause_chunk_id,
                        start_offset=0,
                        end_offset=0,
                        snippet=cause_snippet,
                    ),
                    source_uri=source_uri,
                    chunk_id=cause_chunk_id,
                    start_offset=0,
                    end_offset=0,
                    snippet=cause_snippet,
                    extraction_run_id=sync_run_id,
                    model="feedly-ai",
                    prompt_version="feedly-entities-v2",
                    timestamp=published_dt,
                ),
            )
            result.relations_created += 1

    # ── Parse structured topic metadata (vendor/product only) ──
    # Skip generic topics (Cyber Security, Malware, etc.) — they add
    # no traversal value.  Only promote VulnDB-style "vendor: X" and
    # "product: X" labels into proper Identity / Tool entities.
    for topic in entry.get("commonTopics", []):
        topic_label = topic.get("label", "").strip()
        if not topic_label:
            continue

        lower = topic_label.lower()
        entity = None

        if lower.startswith("vendor: "):
            vendor_name = topic_label[8:].strip()
            if vendor_name and len(vendor_name) > 1:
                entity = resolver.resolve(vendor_name, entity_type="identity")
                entity.attrs["identity_class"] = "organization"
        elif lower.startswith("product: "):
            product_name = topic_label[9:].strip()
            if product_name and len(product_name) > 1:
                entity = resolver.resolve(product_name, entity_type="tool")
        else:
            continue  # skip Cyber Security, Malware, All vulnerabilities, etc.

        if not entity:
            continue

        entity.attrs["origin"] = "feedly"
        graph_store.upsert_entities([entity])
        result.entities_created += 1

        entities_by_type[entity.type].append(entity)
        entity_salience[entity.id] = "about"

        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate="mentions",
            object_id=entity.id,
            confidence=0.85,
            attrs={"origin": "feedly", "topic_source": "vuln_metadata"},
        )
        stored_topic = graph_store.upsert_relations([rel])[0]
        topic_snippet = f"VulnDB metadata: {title[:80]} \u2192 {entity.name}"
        graph_store.attach_provenance(
            stored_topic.id,
            Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored_topic.id,
                    model="feedly-ai",
                    chunk_id=stored_topic.id,
                    start_offset=0,
                    end_offset=0,
                    snippet=topic_snippet,
                ),
                source_uri=source_uri,
                chunk_id=stored_topic.id,
                start_offset=0,
                end_offset=0,
                snippet=topic_snippet,
                extraction_run_id=sync_run_id,
                model="feedly-ai",
                prompt_version="feedly-vuln-metadata",
                timestamp=published_dt,
            ),
        )
        result.relations_created += 1

    # ── Entity-to-entity cross-links (STIX 2.1 SRO vocabulary) ──
    _create_cross_links(
        entities_by_type,
        entity_salience,
        graph_store,
        source_uri,
        sync_run_id,
        published_dt,
        title,
        result,
    )

    # ── Process IOC mentions ─────────────────────────────────
    ioc_data = entry.get("indicatorsOfCompromise", {})
    for ioc in ioc_data.get("mentions", []):
        ioc_text = ioc.get("canonical") or ioc.get("text", "")
        if not ioc_text:
            continue
        ioc_type = ioc.get("type", "indicator")
        ws_type = _IOC_TYPE_MAP.get(ioc_type, "indicator")

        ioc_entity = resolver.resolve(ioc_text, entity_type=ws_type)
        ioc_entity.attrs["ioc_type"] = ioc_type
        ioc_entity.attrs["origin"] = "feedly"
        if ioc.get("text"):
            ioc_entity.attrs["raw_text"] = ioc["text"]
        graph_store.upsert_entities([ioc_entity])
        result.entities_created += 1
        result.iocs_created += 1

        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate="contains_ioc",
            object_id=ioc_entity.id,
            confidence=0.95,
            attrs={"origin": "feedly", "ioc_type": ioc_type},
        )
        stored = graph_store.upsert_relations([rel])[0]
        ioc_chunk_id = str(stored.id)
        ioc_snippet = f"Feedly IOC: {ioc_type} {ioc_text[:80]}"
        graph_store.attach_provenance(
            stored.id,
            Provenance(
                provenance_id=_det_prov_id(
                    source_uri=source_uri,
                    relation_id=stored.id,
                    model="feedly-ai",
                    chunk_id=ioc_chunk_id,
                    start_offset=0,
                    end_offset=0,
                    snippet=ioc_snippet,
                ),
                source_uri=source_uri,
                chunk_id=ioc_chunk_id,
                start_offset=0,
                end_offset=0,
                snippet=ioc_snippet,
                extraction_run_id=sync_run_id,
                model="feedly-ai",
                prompt_version="feedly-ioc",
                timestamp=published_dt,
            ),
        )
        result.relations_created += 1

    # ── Keywords: skipped (created noise topic entities with 0.5 conf) ──

    # ── Optionally queue for LLM extraction ──────────────────
    if (
        queue_for_llm
        and run_store
        and len(full_text) > settings.elastic_connector_min_text_chars
    ):
        # Deterministic run ID so re-processing the same article in a
        # later lookback window does NOT create a duplicate queue entry.
        run_id = "feedly-" + hashlib.sha1(source_uri.encode("utf-8")).hexdigest()

        if run_store.get_run(run_id):
            # Already queued / processed — skip
            pass
        else:
            run = ExtractionRun(
                run_id=run_id,
                started_at=datetime.now(timezone.utc),
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
                full_text,
                {
                    "source": "feedly",
                    "feed_name": feed_name,
                    "title": title[:200],
                    "url": canonical_url,
                },
            )
            result.articles_queued_for_llm += 1
