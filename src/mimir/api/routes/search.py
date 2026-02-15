"""Search & graph query routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Response

from ...graph_limits import limit_subgraph
from ...schemas import (
    ExplainEntityRelation,
    ExplainEntityResponse,
    ExplainResponse,
    PathResult,
    QueryRequest,
    Subgraph,
)
from ._helpers import graph_store, resolve_path_entity, settings

router = APIRouter()


@router.get("/api/search")
def search_entities(
    q: str = Query(..., min_length=1, max_length=settings.search_query_max_length),
    entity_type: Optional[str] = Query(default=None),
):
    """Search for entities by name."""
    normalized_type = (entity_type or "").strip() or None
    matches = graph_store.search_entities(q, entity_type=normalized_type)
    return [{"id": e.id, "name": e.name, "type": e.type} for e in matches[:50]]


@router.post("/query", response_model=Subgraph)
def query(payload: QueryRequest, response: Response) -> Subgraph:
    if payload.seed_id:
        seed = payload.seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif payload.seed_name:
        matches = graph_store.search_entities(payload.seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(status_code=400, detail="seed_id or seed_name required")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=payload.depth,
        min_confidence=payload.min_confidence,
        source_uri=payload.source_uri,
        since=payload.since,
        until=payload.until,
    )
    capped_subgraph, truncated = limit_subgraph(
        subgraph,
        seed_id=seed,
        max_nodes=(
            payload.max_nodes
            if payload.max_nodes is not None
            else settings.query_max_nodes
        ),
        max_edges=(
            payload.max_edges
            if payload.max_edges is not None
            else settings.query_max_edges
        ),
    )
    if truncated:
        response.headers["X-Mimir-Graph-Truncated"] = "1"
        response.headers["X-Mimir-Original-Nodes"] = str(len(subgraph.nodes))
        response.headers["X-Mimir-Original-Edges"] = str(len(subgraph.edges))
        response.headers["X-Mimir-Limited-Nodes"] = str(len(capped_subgraph.nodes))
        response.headers["X-Mimir-Limited-Edges"] = str(len(capped_subgraph.edges))
    return capped_subgraph


@router.get("/path/shortest", response_model=PathResult)
def shortest_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> PathResult:
    """Find the shortest path between two entities (BFS)."""
    src = resolve_path_entity(source_id, source_name, "source")
    tgt = resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_shortest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )


@router.get("/path/all", response_model=PathResult)
def all_paths(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=4, ge=1, le=8),
    max_paths: int = Query(default=20, ge=1, le=100),
) -> PathResult:
    """Find all simple paths between two entities (DFS, depth-limited)."""
    src = resolve_path_entity(source_id, source_name, "source")
    tgt = resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_all_paths(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
        max_paths=max_paths,
    )


@router.get("/path/longest", response_model=PathResult)
def longest_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> PathResult:
    """Find the longest simple path between two entities."""
    src = resolve_path_entity(source_id, source_name, "source")
    tgt = resolve_path_entity(target_id, target_name, "target")
    return graph_store.find_longest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )


@router.get("/explain", response_model=ExplainResponse | ExplainEntityResponse)
def explain(
    relation_id: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
):
    if relation_id:
        try:
            relation, provenance, runs = graph_store.explain_edge(relation_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Relation not found") from None
        return ExplainResponse(relation=relation, provenance=provenance, runs=runs)
    if entity_id:
        entity = graph_store.get_entity(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Entity not found")
        subgraph = graph_store.get_subgraph(entity_id, depth=1)
        relations = []
        for edge in subgraph.edges[:50]:
            relation, provenance, runs = graph_store.explain_edge(edge.id)
            relations.append(
                ExplainEntityRelation(
                    relation=relation, provenance=provenance, runs=runs
                )
            )
        return ExplainEntityResponse(entity=entity, relations=relations)
    raise HTTPException(status_code=400, detail="relation_id or entity_id required")
