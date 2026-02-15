"""Export routes — STIX, CSV, GraphML, JSON, Markdown."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from ...export import export_csv_zip, export_graphml, export_json, export_markdown
from ...schemas import Subgraph
from ...stix.exporter import export_stix_bundle
from ._helpers import graph_store, resolve_subgraph

router = APIRouter()


# ── GET exports (server-side subgraph resolution) ────────────────


@router.get("/api/export/stix")
def export_stix(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
):
    """Export a subgraph as a STIX 2.1 JSON bundle."""
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
    )
    return export_stix_bundle(subgraph)


@router.get("/api/export/csv")
def export_csv(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export entities & relations as CSV files in a ZIP archive."""
    subgraph = resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    data = export_csv_zip(subgraph)
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=mimir-export.zip"},
    )


@router.get("/api/export/graphml")
def export_graphml_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as GraphML (Gephi / Cytoscape / yEd)."""
    subgraph = resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    xml = export_graphml(subgraph)
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=mimir-export.graphml"},
    )


@router.get("/api/export/json")
def export_json_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as a plain JSON knowledge graph."""
    subgraph = resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    return export_json(subgraph)


@router.get("/api/export/markdown")
def export_markdown_endpoint(
    seed_id: Optional[str] = Query(default=None),
    seed_name: Optional[str] = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    scope: str = Query(default="seed", pattern="^(seed|all)$"),
):
    """Export as a human-readable Markdown report."""
    subgraph = resolve_subgraph(seed_id, seed_name, depth, min_confidence, scope)
    md = export_markdown(subgraph)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=mimir-export.md"},
    )


# ── POST exports (client-provided subgraph) ─────────────────────


@router.post("/api/export/stix")
def post_export_stix(payload: Subgraph):
    """Export a client-provided subgraph as STIX 2.1."""
    return export_stix_bundle(payload)


@router.post("/api/export/csv")
def post_export_csv(payload: Subgraph):
    """Export a client-provided subgraph as CSV ZIP."""
    data = export_csv_zip(payload)
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=mimir-export.zip"},
    )


@router.post("/api/export/graphml")
def post_export_graphml(payload: Subgraph):
    """Export a client-provided subgraph as GraphML."""
    xml = export_graphml(payload)
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=mimir-export.graphml"},
    )


@router.post("/api/export/json")
def post_export_json(payload: Subgraph):
    """Export a client-provided subgraph as plain JSON."""
    return export_json(payload)


@router.post("/api/export/markdown")
def post_export_markdown(payload: Subgraph):
    """Export a client-provided subgraph as Markdown."""
    md = export_markdown(payload)
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=mimir-export.md"},
    )
