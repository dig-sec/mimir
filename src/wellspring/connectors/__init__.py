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

import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional
from uuid import uuid4

from elasticsearch import Elasticsearch

from ..config import Settings
from ..dedupe import EntityResolver
from ..schemas import ExtractionRun, Provenance, Relation
from ..storage.base import GraphStore
from ..storage.run_store import RunStore

logger = logging.getLogger(__name__)

# ── Feedly entity-type → Wellspring entity-type ──────────────
_FEEDLY_TYPE_MAP: Dict[str, str] = {
    "threatActor": "threat_actor",
    "malwareFamily": "malware",
    "mitreAttack": "attack_pattern",
    "consumerGood": "tool",
    "technology": "tool",
    "org": "identity",
    "publisher": "identity",
    "location": "location",
    "vulnerability": "vulnerability",
    "person": "identity",
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

    try:
        for i, doc in enumerate(_iter_feedly_docs(client, index_name, since, settings)):
            if max_articles and i >= max_articles:
                break

            try:
                _process_article(
                    doc, graph_store, resolver, run_store, settings,
                    sync_run_id, result, queue_for_llm,
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
        result.articles_processed, result.entities_created,
        result.relations_created, result.iocs_created,
        result.articles_queued_for_llm, len(result.errors),
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
) -> Iterator[Dict[str, Any]]:
    """Page through feedly docs using search_after for constant memory."""
    page_size = settings.elastic_connector_page_size

    query: Dict[str, Any] = {
        "bool": {
            "must": [
                {"range": {"fetched_at": {"gte": since.isoformat()}}},
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
                "entry.id", "entry.title",
                "entry.content.content", "entry.summary.content",
                "entry.fullContent", "entry.abstract.text",
                "entry.entities", "entry.commonTopics",
                "entry.indicatorsOfCompromise",
                "entry.published", "entry.canonicalUrl",
                "entry.alternate.href", "entry.origin.title",
                "entry.author", "entry.language",
                "entry.keywords", "entry.categories",
                "entry.leoSummary",
                "feed_name", "fetched_at", "entry_id",
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
    """Process a single Feedly article into graph data."""
    entry = doc.get("entry", {})
    result.articles_processed += 1

    title = entry.get("title", "").strip()
    feed_name = doc.get("feed_name", "")
    published_dt = _epoch_ms_to_dt(entry.get("published")) or datetime.now(timezone.utc)
    fetched_at = _iso_to_dt(doc.get("fetched_at")) or datetime.now(timezone.utc)

    # Build source URI from canonical URL or entry ID
    canonical_url = entry.get("canonicalUrl", "")
    alt_links = entry.get("alternate", [])
    if not canonical_url and alt_links:
        if isinstance(alt_links, list) and alt_links:
            canonical_url = alt_links[0].get("href", "")
        elif isinstance(alt_links, dict):
            canonical_url = alt_links.get("href", "")
    source_uri = f"feedly://{canonical_url}" if canonical_url else f"feedly://{entry.get('id', uuid4())}"

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
            text_parts.append(_strip_html(raw) if settings.elastic_connector_strip_html else raw)
    if entry.get("fullContent"):
        text_parts.append(
            _strip_html(entry["fullContent"]) if settings.elastic_connector_strip_html else entry["fullContent"]
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

    # ── Process Feedly AI entities ───────────────────────────
    for fe in entry.get("entities", []):
        label = fe.get("label", "").strip()
        if not label:
            continue
        feedly_type = fe.get("type", "other")
        ws_type = _FEEDLY_TYPE_MAP.get(feedly_type)
        if not ws_type:
            continue  # skip unmapped types (disease, gene, etc.)

        entity = resolver.resolve(label, entity_type=ws_type)
        entity.attrs["feedly_id"] = fe.get("id", "")
        entity.attrs["origin"] = "feedly"
        graph_store.upsert_entities([entity])
        result.entities_created += 1

        # Relation: article → mentions → entity
        salience = fe.get("salienceLevel", "mention")
        predicate = "mentions" if salience == "mention" else "describes"
        confidence = 0.9 if salience == "about" else 0.6

        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate=predicate,
            object_id=entity.id,
            confidence=confidence,
            attrs={"origin": "feedly", "salience": salience},
        )
        stored = graph_store.upsert_relations([rel])[0]
        prov = Provenance(
            provenance_id=str(uuid4()),
            source_uri=source_uri,
            chunk_id=fe.get("id", stored.id),
            start_offset=0, end_offset=0,
            snippet=f"Feedly: {title[:100]} → {label}",
            extraction_run_id=sync_run_id,
            model="feedly-ai",
            prompt_version="feedly-entities",
            timestamp=published_dt,
        )
        graph_store.attach_provenance(stored.id, prov)
        result.relations_created += 1

        # Process entity causes (Feedly's inferred relationships)
        for cause in fe.get("causes", []):
            cause_label = cause.get("label", "").strip()
            if not cause_label:
                continue
            cause_entity = resolver.resolve(cause_label, entity_type=ws_type)
            cause_entity.attrs["origin"] = "feedly"
            graph_store.upsert_entities([cause_entity])
            result.entities_created += 1

            cause_rel = Relation(
                id=str(uuid4()),
                subject_id=entity.id,
                predicate="associated_with",
                object_id=cause_entity.id,
                confidence=0.7,
                attrs={"origin": "feedly", "relationship": "causes"},
            )
            stored_cause = graph_store.upsert_relations([cause_rel])[0]
            graph_store.attach_provenance(stored_cause.id, Provenance(
                provenance_id=str(uuid4()),
                source_uri=source_uri,
                chunk_id=cause.get("id", stored_cause.id),
                start_offset=0, end_offset=0,
                snippet=f"Feedly entity cause: {label} ← {cause_label}",
                extraction_run_id=sync_run_id,
                model="feedly-ai",
                prompt_version="feedly-entities",
                timestamp=published_dt,
            ))
            result.relations_created += 1

    # ── Process Feedly common topics ─────────────────────────
    for topic in entry.get("commonTopics", []):
        topic_label = topic.get("label", "").strip()
        if not topic_label:
            continue
        # map topic to a generic "topic" entity
        topic_entity = resolver.resolve(topic_label, entity_type="topic")
        topic_entity.attrs["origin"] = "feedly"
        graph_store.upsert_entities([topic_entity])
        result.entities_created += 1

        score = topic.get("score", 0)
        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate="tagged_with",
            object_id=topic_entity.id,
            confidence=min(float(score), 1.0) if isinstance(score, (int, float)) and score <= 1.0 else 0.8,
            attrs={"origin": "feedly", "topic_score": score},
        )
        stored = graph_store.upsert_relations([rel])[0]
        graph_store.attach_provenance(stored.id, Provenance(
            provenance_id=str(uuid4()),
            source_uri=source_uri,
            chunk_id=stored.id,
            start_offset=0, end_offset=0,
            snippet=f"Feedly topic: {title[:80]} tagged {topic_label}",
            extraction_run_id=sync_run_id,
            model="feedly-ai",
            prompt_version="feedly-topics",
            timestamp=published_dt,
        ))
        result.relations_created += 1

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
        graph_store.attach_provenance(stored.id, Provenance(
            provenance_id=str(uuid4()),
            source_uri=source_uri,
            chunk_id=stored.id,
            start_offset=0, end_offset=0,
            snippet=f"Feedly IOC: {ioc_type} {ioc_text[:80]}",
            extraction_run_id=sync_run_id,
            model="feedly-ai",
            prompt_version="feedly-ioc",
            timestamp=published_dt,
        ))
        result.relations_created += 1

    # ── Process keywords as lightweight tags ──────────────────
    for kw in entry.get("keywords", []):
        if not isinstance(kw, str) or len(kw) < 2:
            continue
        kw_entity = resolver.resolve(kw.lower(), entity_type="topic")
        kw_entity.attrs["origin"] = "feedly"
        graph_store.upsert_entities([kw_entity])
        result.entities_created += 1

        rel = Relation(
            id=str(uuid4()),
            subject_id=article_entity.id,
            predicate="tagged_with",
            object_id=kw_entity.id,
            confidence=0.5,
            attrs={"origin": "feedly", "tag_source": "keyword"},
        )
        stored = graph_store.upsert_relations([rel])[0]
        graph_store.attach_provenance(stored.id, Provenance(
            provenance_id=str(uuid4()),
            source_uri=source_uri,
            chunk_id=stored.id,
            start_offset=0, end_offset=0,
            snippet=f"Feedly keyword: {kw}",
            extraction_run_id=sync_run_id,
            model="feedly-ai",
            prompt_version="feedly-keywords",
            timestamp=published_dt,
        ))
        result.relations_created += 1

    # ── Optionally queue for LLM extraction ──────────────────
    if queue_for_llm and run_store and len(full_text) > settings.elastic_connector_min_text_chars:
        run_id = str(uuid4())
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
            run, source_uri, full_text,
            {
                "source": "feedly",
                "feed_name": feed_name,
                "title": title[:200],
                "url": canonical_url,
            },
        )
        result.articles_queued_for_llm += 1
