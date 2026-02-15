"""UI routes — HTML pages served by the API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from ...graph_limits import limit_subgraph
from ...schemas import Subgraph
from ..ui import render_root_ui
from ..visualize import render_html
from ._helpers import graph_store, resolve_path_entity, settings

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> str:
    root_path = str(request.scope.get("root_path") or "")
    return render_root_ui(
        root_path=root_path,
        api_base_url=settings.mimir_api_base_url,
        ollama_model=settings.ollama_model,
    )


@router.get("/visualize", response_class=HTMLResponse)
def visualize(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=1, ge=0, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    source_uri: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
):
    if seed_id:
        seed = seed_id
        if not graph_store.get_entity(seed):
            raise HTTPException(status_code=404, detail="Seed entity not found")
    elif seed_name:
        matches = graph_store.search_entities(seed_name)
        if not matches:
            raise HTTPException(status_code=404, detail="Seed entity not found")
        seed = matches[0].id
    else:
        raise HTTPException(status_code=400, detail="seed_id or seed_name required")

    subgraph = graph_store.get_subgraph(
        seed_entity_id=seed,
        depth=depth,
        min_confidence=min_confidence,
        source_uri=source_uri,
        since=since,
        until=until,
    )
    subgraph, _ = limit_subgraph(
        subgraph,
        seed_id=seed,
        max_nodes=settings.query_max_nodes,
        max_edges=settings.query_max_edges,
    )
    title = f"Mimir Graph: {seed_name or seed_id}"
    return render_html(subgraph, title=title)


@router.get("/path/visualize", response_class=HTMLResponse)
def visualize_path(
    source_id: Optional[str] = Query(default=None),
    source_name: Optional[str] = Query(default=None),
    target_id: Optional[str] = Query(default=None),
    target_name: Optional[str] = Query(default=None),
    algorithm: str = Query(default="shortest"),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_depth: int = Query(default=6, ge=1, le=10),
) -> HTMLResponse:
    """Visualize a path between two entities in the graph explorer."""
    src = resolve_path_entity(source_id, source_name, "source")
    tgt = resolve_path_entity(target_id, target_name, "target")

    if algorithm == "longest":
        result = graph_store.find_longest_path(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )
    elif algorithm == "all":
        result = graph_store.find_all_paths(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )
    else:
        result = graph_store.find_shortest_path(
            source_id=src,
            target_id=tgt,
            min_confidence=min_confidence,
            max_depth=max_depth,
        )

    if not result.paths:
        raise HTTPException(status_code=404, detail="No path found between entities")

    all_nodes: dict[str, object] = {}
    all_edges: dict[str, object] = {}

    for path in result.paths:
        for node in path.nodes:
            all_nodes[node.id] = node
        for edge in path.edges:
            all_edges[edge.id] = edge

    subgraph = Subgraph(
        nodes=list(all_nodes.values()),
        edges=list(all_edges.values()),
    )

    src_entity = graph_store.get_entity(src)
    tgt_entity = graph_store.get_entity(tgt)
    src_label = src_entity.name if src_entity else src
    tgt_label = tgt_entity.name if tgt_entity else tgt
    title = (
        f"Path: {src_label} → {tgt_label} ({algorithm}, {len(result.paths)} path(s))"
    )

    return render_html(subgraph, title=title)
