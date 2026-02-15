"""Intelligence & analytics routes — timelines, PIR, CTI, ask."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..ask_retrieval import gather_full_context
from ._helpers import _TIMELINE_INTERVALS
from ._helpers import bucket_start as _bucket_start
from ._helpers import graph_store, metrics_store
from ._helpers import parse_window_bounds as _parse_window_bounds
from ._helpers import resolve_entity as _resolve_entity
from ._helpers import run_store, settings
from ._helpers import to_utc as _to_utc

router = APIRouter()


# ── Entity timeline ──────────────────────────────────────────────


@router.get("/api/timeline/entity")
def entity_timeline(
    entity_id: Optional[str] = Query(default=None),
    entity_name: Optional[str] = Query(default=None),
    depth: int = Query(default=1, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    interval: str = Query(default="month", pattern="^(day|week|month|quarter|year)$"),
):
    """Show how an entity's connected relations evolve over time."""
    interval = interval.lower()
    if interval not in _TIMELINE_INTERVALS:
        raise HTTPException(
            status_code=400, detail="interval must be day|week|month|quarter|year"
        )

    entity = _resolve_entity(entity_id, entity_name)
    since_utc = _to_utc(since) if since else None
    until_utc = _to_utc(until) if until else None
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="since must be <= until")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=entity.id,
        depth=depth,
        min_confidence=min_confidence,
        source_uri=source_uri,
        since=since,
        until=until,
    )

    buckets: Dict[datetime, Dict[str, object]] = {}
    relation_ids = [edge.id for edge in subgraph.edges]
    relation_timestamps: Dict[str, List[datetime]] = {}
    bulk_ts_loader = getattr(graph_store, "get_relation_provenance_timestamps", None)
    use_bulk_timestamps = callable(bulk_ts_loader)
    if use_bulk_timestamps and relation_ids:
        relation_timestamps = bulk_ts_loader(
            relation_ids,
            source_uri=source_uri,
            since=since,
            until=until,
        )

    for edge in subgraph.edges:
        timestamps: List[datetime] = []
        if use_bulk_timestamps:
            timestamps = relation_timestamps.get(edge.id, [])
        else:
            try:
                _, provenance, _ = graph_store.explain_edge(edge.id)
            except KeyError:
                continue
            timestamps = [prov.timestamp for prov in provenance]

        for raw_ts in timestamps:
            ts = _to_utc(raw_ts)
            if since_utc and ts < since_utc:
                continue
            if until_utc and ts > until_utc:
                continue

            bucket_key = _bucket_start(ts, interval)
            if bucket_key not in buckets:
                buckets[bucket_key] = {
                    "relation_ids": set(),
                    "incoming_ids": set(),
                    "outgoing_ids": set(),
                    "evidence_count": 0,
                    "predicates": Counter(),
                }
            bucket = buckets[bucket_key]
            bucket["relation_ids"].add(edge.id)
            if edge.subject_id == entity.id:
                bucket["outgoing_ids"].add(edge.id)
            if edge.object_id == entity.id:
                bucket["incoming_ids"].add(edge.id)
            bucket["evidence_count"] = int(bucket["evidence_count"]) + 1
            bucket["predicates"][edge.predicate] += 1

    timeline = []
    for bstart in sorted(buckets):
        data = buckets[bstart]
        predicate_counts = data["predicates"]
        top_predicates = [
            {"predicate": pred, "count": count}
            for pred, count in predicate_counts.most_common(10)
        ]
        timeline.append(
            {
                "bucket_start": bstart.isoformat(),
                "relation_count": len(data["relation_ids"]),
                "incoming_relation_count": len(data["incoming_ids"]),
                "outgoing_relation_count": len(data["outgoing_ids"]),
                "evidence_count": int(data["evidence_count"]),
                "top_predicates": top_predicates,
            }
        )

    return {
        "entity": {"id": entity.id, "name": entity.name, "type": entity.type},
        "interval": interval,
        "depth": depth,
        "min_confidence": min_confidence,
        "source_uri": source_uri,
        "since": since_utc.isoformat() if since_utc else None,
        "until": until_utc.isoformat() if until_utc else None,
        "bucket_count": len(timeline),
        "buckets": timeline,
    }


# ── Threat-actor timeline ───────────────────────────────────────


@router.get("/api/timeline/threat-actors")
def threat_actor_timeline(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    interval: str = Query(default="month", pattern="^(day|week|month|quarter|year)$"),
    top_n: int = Query(default=10, ge=1, le=100),
):
    """Aggregate temporal activity for threat actors in a graph scope."""
    interval = interval.lower()
    if interval not in _TIMELINE_INTERVALS:
        raise HTTPException(
            status_code=400, detail="interval must be day|week|month|quarter|year"
        )

    since_utc = _to_utc(since) if since else None
    until_utc = _to_utc(until) if until else None
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="since must be <= until")

    seed_entity = None
    if seed_id or seed_name:
        seed_entity = _resolve_entity(seed_id, seed_name)
        subgraph = graph_store.get_subgraph(
            seed_entity_id=seed_entity.id,
            depth=depth,
            min_confidence=min_confidence,
            source_uri=source_uri,
            since=since,
            until=until,
        )
    else:
        subgraph = graph_store.get_full_graph(min_confidence=min_confidence)

    node_by_id = {node.id: node for node in subgraph.nodes}
    threat_actor_ids = {
        node.id for node in subgraph.nodes if node.type == "threat_actor"
    }

    actor_buckets: Dict[str, Dict[datetime, Dict[str, object]]] = {}
    actor_relation_ids: Dict[str, set] = {}
    actor_evidence_totals: Dict[str, int] = {}
    relation_ids = [edge.id for edge in subgraph.edges]
    relation_timestamps: Dict[str, List[datetime]] = {}
    bulk_ts_loader = getattr(graph_store, "get_relation_provenance_timestamps", None)
    use_bulk_timestamps = callable(bulk_ts_loader)
    if use_bulk_timestamps and relation_ids:
        relation_timestamps = bulk_ts_loader(
            relation_ids,
            source_uri=source_uri,
            since=since,
            until=until,
        )

    for edge in subgraph.edges:
        connected_actor_ids: List[str] = []
        if edge.subject_id in threat_actor_ids:
            connected_actor_ids.append(edge.subject_id)
        if edge.object_id in threat_actor_ids and edge.object_id != edge.subject_id:
            connected_actor_ids.append(edge.object_id)
        if not connected_actor_ids:
            continue

        if use_bulk_timestamps:
            timestamps = relation_timestamps.get(edge.id, [])
        else:
            try:
                _, provenance, _ = graph_store.explain_edge(edge.id)
            except KeyError:
                continue
            timestamps = [prov.timestamp for prov in provenance]

        filtered_timestamps: List[datetime] = []
        for raw_ts in timestamps:
            ts = _to_utc(raw_ts)
            if since_utc and ts < since_utc:
                continue
            if until_utc and ts > until_utc:
                continue
            filtered_timestamps.append(ts)

        if not filtered_timestamps:
            continue

        for actor_id in connected_actor_ids:
            actor_relation_ids.setdefault(actor_id, set()).add(edge.id)
            actor_evidence_totals[actor_id] = actor_evidence_totals.get(
                actor_id, 0
            ) + len(filtered_timestamps)
            by_bucket = actor_buckets.setdefault(actor_id, {})
            for ts in filtered_timestamps:
                bucket_key = _bucket_start(ts, interval)
                if bucket_key not in by_bucket:
                    by_bucket[bucket_key] = {
                        "relation_ids": set(),
                        "incoming_ids": set(),
                        "outgoing_ids": set(),
                        "evidence_count": 0,
                        "predicates": Counter(),
                    }
                bucket = by_bucket[bucket_key]
                bucket["relation_ids"].add(edge.id)
                if edge.subject_id == actor_id:
                    bucket["outgoing_ids"].add(edge.id)
                if edge.object_id == actor_id:
                    bucket["incoming_ids"].add(edge.id)
                bucket["evidence_count"] = int(bucket["evidence_count"]) + 1
                bucket["predicates"][edge.predicate] += 1

    active_actor_ids = [
        actor_id for actor_id in threat_actor_ids if actor_id in actor_relation_ids
    ]
    active_actor_ids.sort(
        key=lambda actor_id: (
            -len(actor_relation_ids.get(actor_id, set())),
            -actor_evidence_totals.get(actor_id, 0),
            (
                node_by_id.get(actor_id).name.lower()
                if actor_id in node_by_id
                else actor_id
            ),
        )
    )

    actors = []
    for actor_id in active_actor_ids[:top_n]:
        actor = node_by_id.get(actor_id)
        actor_timeline = []
        for bstart in sorted(actor_buckets.get(actor_id, {})):
            data = actor_buckets[actor_id][bstart]
            predicate_counts = data["predicates"]
            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in predicate_counts.most_common(10)
            ]
            actor_timeline.append(
                {
                    "bucket_start": bstart.isoformat(),
                    "relation_count": len(data["relation_ids"]),
                    "incoming_relation_count": len(data["incoming_ids"]),
                    "outgoing_relation_count": len(data["outgoing_ids"]),
                    "evidence_count": int(data["evidence_count"]),
                    "top_predicates": top_predicates,
                }
            )

        actors.append(
            {
                "entity": {
                    "id": actor_id,
                    "name": actor.name if actor else actor_id,
                    "type": actor.type if actor else "threat_actor",
                },
                "relation_count": len(actor_relation_ids.get(actor_id, set())),
                "evidence_count": actor_evidence_totals.get(actor_id, 0),
                "bucket_count": len(actor_timeline),
                "buckets": actor_timeline,
            }
        )

    return {
        "seed": (
            {"id": seed_entity.id, "name": seed_entity.name, "type": seed_entity.type}
            if seed_entity
            else None
        ),
        "interval": interval,
        "depth": depth,
        "min_confidence": min_confidence,
        "source_uri": source_uri,
        "since": since_utc.isoformat() if since_utc else None,
        "until": until_utc.isoformat() if until_utc else None,
        "top_n": top_n,
        "actor_count_total": len(threat_actor_ids),
        "actor_count_active": len(active_actor_ids),
        "actor_count_returned": len(actors),
        "actors": actors,
    }


# ── Lake overview ────────────────────────────────────────────────


@router.get("/api/lake/overview")
def lake_overview():
    """Summarize source coverage across queued documents and provenance evidence."""
    from ...lake import parse_source_uri

    run_client = getattr(run_store, "client", None)
    run_indices = getattr(run_store, "indices", None)
    if run_client is None or run_indices is None:
        raise HTTPException(
            status_code=501,
            detail="Lake overview is only available on Elasticsearch backend",
        )
    graph_client = getattr(graph_store, "client", None)
    graph_indices = getattr(graph_store, "indices", None)

    doc_agg_resp = run_client.search(
        index=run_indices.documents,
        size=0,
        aggs={
            "sources": {
                "terms": {
                    "field": "metadata.lake.source.keyword",
                    "size": 64,
                    "missing": "unknown",
                },
                "aggs": {
                    "collections": {
                        "terms": {
                            "field": "metadata.lake.collection.keyword",
                            "size": 256,
                            "missing": "",
                        }
                    }
                },
            }
        },
    )
    total_docs = int(
        run_client.count(index=run_indices.documents, query={"match_all": {}})["count"]
    )
    doc_source_rows: List[Dict[str, Any]] = []
    doc_buckets = (
        doc_agg_resp.get("aggregations", {}).get("sources", {}).get("buckets", [])
    )
    for bucket in doc_buckets:
        collections = [
            {"collection": c.get("key", ""), "docs": int(c.get("doc_count", 0))}
            for c in bucket.get("collections", {}).get("buckets", [])
        ]
        doc_source_rows.append(
            {
                "source": str(bucket.get("key", "unknown")),
                "docs": int(bucket.get("doc_count", 0)),
                "collections": collections,
            }
        )
    doc_source_rows.sort(key=lambda row: row["docs"], reverse=True)
    docs_exact = (
        sum(int(bucket.get("doc_count", 0)) for bucket in doc_buckets) == total_docs
    )

    provenance_total = 0
    provenance_source_rows: List[Dict[str, Any]] = []
    provenance_exact = True
    provenance_by_source_collection: Dict[tuple, int] = {}

    provenance_index = getattr(graph_indices, "provenance", None)
    if graph_client is not None and provenance_index:
        prov_agg_resp = graph_client.search(
            index=provenance_index,
            size=0,
            aggs={
                "source_uris": {
                    "terms": {
                        "field": "source_uri",
                        "size": 2048,
                    }
                }
            },
        )
        provenance_total = int(
            graph_client.count(index=provenance_index, query={"match_all": {}})["count"]
        )
        prov_buckets = (
            prov_agg_resp.get("aggregations", {})
            .get("source_uris", {})
            .get("buckets", [])
        )

        for bucket in prov_buckets:
            source_uri = str(bucket.get("key", "") or "")
            parsed = parse_source_uri(source_uri)
            source_key = str(parsed.get("source", "unknown") or "unknown")
            collection_key = str(parsed.get("collection", "") or "")
            key = (source_key, collection_key)
            provenance_by_source_collection[key] = provenance_by_source_collection.get(
                key, 0
            ) + int(bucket.get("doc_count", 0))

        provenance_exact = (
            sum(int(bucket.get("doc_count", 0)) for bucket in prov_buckets)
            == provenance_total
        )

        prov_grouped: Dict[str, Dict[str, Any]] = {}
        for (
            source_key,
            collection_key,
        ), count in provenance_by_source_collection.items():
            row = prov_grouped.setdefault(
                source_key,
                {"source": source_key, "provenance_records": 0, "collections": []},
            )
            row["provenance_records"] += count
            row["collections"].append(
                {"collection": collection_key, "provenance_records": count}
            )
        provenance_source_rows = list(prov_grouped.values())
        for row in provenance_source_rows:
            row["collections"].sort(
                key=lambda item: int(item["provenance_records"]), reverse=True
            )
        provenance_source_rows.sort(
            key=lambda item: int(item["provenance_records"]), reverse=True
        )

    combined: Dict[str, Dict[str, Any]] = {}
    for row in doc_source_rows:
        source_key = str(row["source"])
        combined_row = combined.setdefault(
            source_key,
            {
                "source": source_key,
                "docs": 0,
                "provenance_records": 0,
                "collections": {},
            },
        )
        combined_row["docs"] += int(row["docs"])
        for collection in row["collections"]:
            collection_key = str(collection.get("collection", "") or "")
            item = combined_row["collections"].setdefault(
                collection_key,
                {
                    "collection": collection_key,
                    "docs": 0,
                    "provenance_records": 0,
                },
            )
            item["docs"] += int(collection.get("docs", 0))

    for (source_key, collection_key), count in provenance_by_source_collection.items():
        combined_row = combined.setdefault(
            source_key,
            {
                "source": source_key,
                "docs": 0,
                "provenance_records": 0,
                "collections": {},
            },
        )
        combined_row["provenance_records"] += int(count)
        item = combined_row["collections"].setdefault(
            collection_key,
            {
                "collection": collection_key,
                "docs": 0,
                "provenance_records": 0,
            },
        )
        item["provenance_records"] += int(count)

    combined_source_rows: List[Dict[str, Any]] = []
    for source_key, row in combined.items():
        collections = list(row["collections"].values())
        collections.sort(
            key=lambda item: (int(item["docs"]) + int(item["provenance_records"])),
            reverse=True,
        )
        combined_source_rows.append(
            {
                "source": source_key,
                "docs": int(row["docs"]),
                "provenance_records": int(row["provenance_records"]),
                "collections": collections,
            }
        )
    combined_source_rows.sort(
        key=lambda item: (int(item["docs"]) + int(item["provenance_records"])),
        reverse=True,
    )

    return {
        "backend": "elasticsearch",
        "exact": docs_exact and provenance_exact,
        "documents_exact": docs_exact,
        "provenance_exact": provenance_exact,
        "documents_total": total_docs,
        "provenance_total": provenance_total,
        "sources": doc_source_rows,
        "provenance_sources": provenance_source_rows,
        "combined_sources": combined_source_rows,
    }


# ── PIR trending ─────────────────────────────────────────────────


@router.get("/api/pir/trending")
async def pir_trending(
    days: int = Query(default=7, ge=1, le=90),
    top_n: int = Query(default=10, ge=1, le=50),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """Priority Intelligence Requirements: trending entities for current vs previous window."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    kwargs: dict = {
        "top_n": top_n,
        "source_uri": source_uri,
        "days": days,
        "since": since_dt,
        "until": until_dt,
    }

    pir_metrics_fn = getattr(metrics_store, "get_pir_trending_summary", None)
    if callable(pir_metrics_fn):
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: pir_metrics_fn(**kwargs)),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            result = None
        except Exception:
            result = None

        if result:
            total_items = sum(
                len(q.get("items", [])) for q in (result or {}).get("questions", [])
            )
            if total_items > 0:
                return result

    pir_graph_fn = getattr(graph_store, "get_pir_trending_summary", None)
    if callable(pir_graph_fn):
        try:
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, lambda: pir_graph_fn(**kwargs)),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504, detail="PIR trending query timeout - dataset too large"
            )

    raise HTTPException(
        status_code=501,
        detail="PIR trending is only available on Elasticsearch backend",
    )


# ── CTI overview / trends ───────────────────────────────────────


@router.get("/api/cti/overview")
def cti_overview(
    days: int = Query(default=30, ge=1, le=3650),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """CTI overview from daily precomputed CTI assessment metrics."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    overview_fn = getattr(metrics_store, "get_cti_overview", None)
    if not callable(overview_fn):
        raise HTTPException(
            status_code=501,
            detail="CTI overview is only available on Elasticsearch backend",
        )
    return overview_fn(days=days, source_uri=source_uri, since=since_dt, until=until_dt)


@router.get("/api/cti/trends")
def cti_trends(
    days: int = Query(default=30, ge=1, le=3650),
    top_n: int = Query(default=10, ge=1, le=50),
    group_by: str = Query(default="activity", pattern="^(activity|domain|actor)$"),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """CTI trends grouped by activity, domain, or actor."""
    since_dt, until_dt = _parse_window_bounds(since, until)
    trends_fn = getattr(metrics_store, "get_cti_trends", None)
    if not callable(trends_fn):
        raise HTTPException(
            status_code=501,
            detail="CTI trends are only available on Elasticsearch backend",
        )
    return trends_fn(
        days=days,
        top_n=top_n,
        group_by=group_by,
        source_uri=source_uri,
        since=since_dt,
        until=until_dt,
    )


# ── PIR entity context ──────────────────────────────────────────


@router.get("/api/pir/entity-context")
def pir_entity_context(
    entity_id: str = Query(...),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
):
    """Return lightweight context for a PIR entity: attrs, neighbors, sources."""
    entity = graph_store.get_entity(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    subgraph = graph_store.get_subgraph(entity_id, depth=1)

    neighbors = []
    node_map = {n.id: n for n in subgraph.nodes}
    sources: List[Dict[str, Any]] = []
    seen_uris: set = set()

    for edge in subgraph.edges[:80]:
        other_id = edge.object_id if edge.subject_id == entity_id else edge.subject_id
        other = node_map.get(other_id)
        if not other:
            continue

        if other.type == "report":
            full_entity = graph_store.get_entity(other.id)
            attrs = full_entity.attrs if full_entity else {}
            url = (attrs or {}).get("source_url", "")
            published = (attrs or {}).get("published")
            if url and url not in seen_uris:
                seen_uris.add(url)
                sources.append(
                    {"uri": url, "title": other.name, "timestamp": published}
                )
            continue

        neighbors.append(
            {
                "id": other.id,
                "name": other.name,
                "type": other.type,
                "predicate": edge.predicate,
                "confidence": edge.confidence,
            }
        )

    neighbors.sort(key=lambda n: -n["confidence"])

    if since or until:
        filtered_sources = []
        for s in sources:
            ts = s.get("timestamp")
            if not ts:
                continue
            ts_str = str(ts)[:10]
            if since and ts_str < since[:10]:
                continue
            if until and ts_str > until[:10]:
                continue
            filtered_sources.append(s)
        sources = filtered_sources

    sources.sort(key=lambda s: s.get("timestamp") or "", reverse=True)

    return {
        "entity": {
            "id": entity.id,
            "name": entity.name,
            "type": entity.type,
            "attrs": entity.attrs or {},
        },
        "neighbors": neighbors[:30],
        "sources": sources[:15],
    }


# ── Ask (LLM-powered Q&A) ───────────────────────────────────────


@router.post("/api/ask")
async def ask_question(request: Request):
    """Ask a natural-language question about the knowledge graph.

    Uses Ollama to synthesize an answer from graph context.
    Streams the response token-by-token via SSE.
    """
    import json as _json

    import httpx

    from ...llm.prompts import render_prompt

    body = await request.json()
    question = (body.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    if len(question) > 4000:
        raise HTTPException(status_code=413, detail="question exceeds 4000 characters")

    context, search_terms = gather_full_context(
        question,
        graph_store,
        run_store=run_store,
    )

    prompt = render_prompt(
        "ask_knowledge_graph.jinja2",
        question=question,
        entities=context["entities"],
        relations=context["relations"],
        provenance=context["provenance"],
        chunks=context.get("chunks", []),
        stats=context["stats"],
    )

    async def _stream_response():
        sources_event = {
            "type": "sources",
            "entities_found": len(context["entities"]),
            "relations_found": len(context["relations"]),
            "provenance_found": len(context["provenance"]),
            "chunks_found": len(context.get("chunks", [])),
            "entities": context["entities"][:10],
            "search_terms": search_terms[:10],
        }
        yield f"data: {_json.dumps(sources_event)}\n\n"

        try:
            async with httpx.AsyncClient(
                base_url=settings.ollama_base_url,
                timeout=httpx.Timeout(settings.ollama_timeout_seconds, connect=10.0),
            ) as client:
                async with client.stream(
                    "POST",
                    "/api/generate",
                    json={
                        "model": settings.ollama_model,
                        "prompt": prompt,
                        "stream": True,
                    },
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = _json.loads(line)
                            token = chunk.get("response", "")
                            if token:
                                yield f"data: {_json.dumps({'type': 'token', 'content': token})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {_json.dumps({'type': 'done'})}\n\n"
                        except _json.JSONDecodeError:
                            continue
        except httpx.ConnectError:
            yield f"data: {_json.dumps({'type': 'error', 'message': 'Cannot connect to Ollama. Is it running?'})}\n\n"
        except httpx.TimeoutException:
            yield f"data: {_json.dumps({'type': 'error', 'message': 'Ollama request timed out.'})}\n\n"
        except Exception:
            import logging as _logging

            _logging.getLogger(__name__).exception("Ask endpoint error")
            yield f"data: {_json.dumps({'type': 'error', 'message': 'An internal error occurred while generating the answer.'})}\n\n"

    return StreamingResponse(
        _stream_response(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
