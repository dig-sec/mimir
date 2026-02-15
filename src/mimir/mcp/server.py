"""Mimir MCP server – exposes the knowledge-graph to VS Code Copilot."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Bootstrap the graph / run / metrics stores using the same config as the API
# ---------------------------------------------------------------------------
from ..config import get_settings
from ..storage.factory import create_graph_store, create_metrics_store, create_run_store

settings = get_settings()
graph_store = create_graph_store(settings)
run_store = create_run_store(settings)
metrics_store = create_metrics_store(settings)

mcp = FastMCP(
    "Mimir",
    instructions=(
        "Mimir is an LLM-powered knowledge-graph platform focused on "
        "cyber-threat intelligence. Use these tools to search entities "
        "(malware, threat actors, campaigns …), explore their relationships, "
        "inspect provenance, and get high-level statistics."
    ),
)


# ── helpers ────────────────────────────────────────────────────────────────


def _entity_dict(e: Any) -> dict:
    return {
        "id": e.id,
        "name": e.name,
        "type": e.type,
        "aliases": getattr(e, "aliases", []),
    }


def _relation_dict(r: Any) -> dict:
    return {
        "id": r.id,
        "subject_id": r.subject_id,
        "predicate": r.predicate,
        "object_id": r.object_id,
        "confidence": r.confidence,
        "attrs": getattr(r, "attrs", {}),
    }


def _provenance_dict(p: Any) -> dict:
    return {
        "provenance_id": p.provenance_id,
        "source_uri": p.source_uri,
        "snippet": p.snippet,
        "model": p.model,
        "timestamp": p.timestamp.isoformat() if p.timestamp else None,
    }


def _run_dict(r: Any) -> dict:
    return {
        "run_id": r.run_id,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "model": r.model,
        "prompt_version": r.prompt_version,
        "status": r.status,
        "error": r.error,
    }


def _fmt(obj: Any) -> str:
    """Pretty-print a dict/list as indented JSON for the LLM."""
    return json.dumps(obj, indent=2, default=str)


# ── tools ──────────────────────────────────────────────────────────────────


@mcp.tool()
def search_entities(query: str, entity_type: Optional[str] = None) -> str:
    """Search for entities in the Mimir knowledge-graph.

    Args:
        query: Free-text search string (name, alias, keyword).
        entity_type: Optional filter – e.g. "malware", "threat_actor",
                     "campaign", "vulnerability", "indicator", "tool",
                     "attack_pattern", "infrastructure", "identity", "report".
    Returns:
        JSON list of matching entities (id, name, type, aliases).
    """
    matches = graph_store.search_entities(query, entity_type=entity_type)
    return _fmt([_entity_dict(e) for e in matches[:50]])


@mcp.tool()
def get_entity(entity_id: str) -> str:
    """Fetch a single entity by its ID.

    Args:
        entity_id: The unique entity identifier.
    Returns:
        JSON object with entity details, or an error message.
    """
    entity = graph_store.get_entity(entity_id)
    if not entity:
        return _fmt({"error": "Entity not found", "entity_id": entity_id})
    return _fmt(_entity_dict(entity))


@mcp.tool()
def get_subgraph(
    entity_name: Optional[str] = None,
    entity_id: Optional[str] = None,
    depth: int = 1,
    min_confidence: float = 0.0,
) -> str:
    """Retrieve the neighbourhood sub-graph around an entity.

    Provide *either* entity_name (fuzzy search) or entity_id (exact).

    Args:
        entity_name: Search for the seed entity by name.
        entity_id: Use an exact entity ID as seed.
        depth: How many hops to traverse (0-5, default 1).
        min_confidence: Minimum relation confidence to include (0.0-1.0).
    Returns:
        JSON with "nodes" and "edges" arrays.
    """
    if entity_id:
        seed = entity_id
        if not graph_store.get_entity(seed):
            return _fmt({"error": "Entity not found", "entity_id": seed})
    elif entity_name:
        matches = graph_store.search_entities(entity_name)
        if not matches:
            return _fmt({"error": "No entity found for query", "query": entity_name})
        seed = matches[0].id
    else:
        return _fmt({"error": "Provide entity_name or entity_id"})

    depth = max(0, min(depth, 5))
    sub = graph_store.get_subgraph(
        seed_entity_id=seed, depth=depth, min_confidence=min_confidence
    )
    return _fmt(
        {
            "seed": seed,
            "nodes": [{"id": n.id, "name": n.name, "type": n.type} for n in sub.nodes],
            "edges": [
                {
                    "id": e.id,
                    "subject_id": e.subject_id,
                    "predicate": e.predicate,
                    "object_id": e.object_id,
                    "confidence": e.confidence,
                }
                for e in sub.edges
            ],
        }
    )


@mcp.tool()
def explain_entity(
    entity_name: Optional[str] = None,
    entity_id: Optional[str] = None,
) -> str:
    """Show an entity with all its direct relations and source provenance.

    Provide *either* entity_name (fuzzy search) or entity_id (exact).

    Args:
        entity_name: Search for the entity by name.
        entity_id: Use an exact entity ID.
    Returns:
        JSON with entity details, related relations and provenance snippets.
    """
    if entity_id:
        entity = graph_store.get_entity(entity_id)
    elif entity_name:
        matches = graph_store.search_entities(entity_name)
        entity = matches[0] if matches else None
    else:
        return _fmt({"error": "Provide entity_name or entity_id"})

    if not entity:
        return _fmt({"error": "Entity not found"})

    sub = graph_store.get_subgraph(entity.id, depth=1)
    relations = []
    for edge in sub.edges[:30]:
        try:
            rel, prov, runs = graph_store.explain_edge(edge.id)
            relations.append(
                {
                    "relation": _relation_dict(rel),
                    "provenance": [_provenance_dict(p) for p in prov[:5]],
                    "runs": [_run_dict(r) for r in runs[:3]],
                }
            )
        except (KeyError, Exception):
            relations.append(
                {"relation": _relation_dict(edge), "provenance": [], "runs": []}
            )

    return _fmt({"entity": _entity_dict(entity), "relations": relations})


@mcp.tool()
def explain_relation(relation_id: str) -> str:
    """Explain a single relation – show its provenance and extraction runs.

    Args:
        relation_id: The relation / edge identifier.
    Returns:
        JSON with the relation, provenance snippets, and extraction run info.
    """
    try:
        rel, prov, runs = graph_store.explain_edge(relation_id)
    except KeyError:
        return _fmt({"error": "Relation not found", "relation_id": relation_id})
    return _fmt(
        {
            "relation": _relation_dict(rel),
            "provenance": [_provenance_dict(p) for p in prov],
            "runs": [_run_dict(r) for r in runs],
        }
    )


# ── path-finding tools ────────────────────────────────────────────────


def _path_dict(path: Any) -> dict:
    return {
        "nodes": [{"id": n.id, "name": n.name, "type": n.type} for n in path.nodes],
        "edges": [
            {
                "id": e.id,
                "subject_id": e.subject_id,
                "predicate": e.predicate,
                "object_id": e.object_id,
                "confidence": e.confidence,
            }
            for e in path.edges
        ],
        "length": path.length,
    }


def _resolve_seed(entity_name: str | None, entity_id: str | None) -> str | None:
    """Resolve an entity by name or ID, returning the entity ID or None."""
    if entity_id:
        if graph_store.get_entity(entity_id):
            return entity_id
        return None
    if entity_name:
        matches = graph_store.search_entities(entity_name)
        if matches:
            return matches[0].id
    return None


@mcp.tool()
def find_shortest_path(
    source_name: str | None = None,
    source_id: str | None = None,
    target_name: str | None = None,
    target_id: str | None = None,
    min_confidence: float = 0.0,
    max_depth: int = 6,
) -> str:
    """Find the shortest path between two entities in the knowledge graph.

    Provide *either* name (fuzzy search) or id for each endpoint.

    Args:
        source_name: Search for the source entity by name.
        source_id: Use an exact source entity ID.
        target_name: Search for the target entity by name.
        target_id: Use an exact target entity ID.
        min_confidence: Minimum relation confidence (0.0-1.0).
        max_depth: Maximum traversal depth / hops (1-10, default 6).
    Returns:
        JSON with source, target, the shortest path (nodes + edges), and hop count.
    """
    src = _resolve_seed(source_name, source_id)
    tgt = _resolve_seed(target_name, target_id)
    if not src:
        return _fmt({"error": "Source entity not found"})
    if not tgt:
        return _fmt({"error": "Target entity not found"})

    max_depth = max(1, min(max_depth, 10))
    result = graph_store.find_shortest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )
    return _fmt(
        {
            "source": {"id": result.source.id, "name": result.source.name},
            "target": {"id": result.target.id, "name": result.target.name},
            "algorithm": result.algorithm,
            "paths_found": len(result.paths),
            "paths": [_path_dict(p) for p in result.paths],
        }
    )


@mcp.tool()
def find_all_paths(
    source_name: str | None = None,
    source_id: str | None = None,
    target_name: str | None = None,
    target_id: str | None = None,
    min_confidence: float = 0.0,
    max_depth: int = 4,
    max_paths: int = 20,
) -> str:
    """Find all simple paths between two entities in the knowledge graph.

    Provide *either* name (fuzzy search) or id for each endpoint.

    Args:
        source_name: Search for the source entity by name.
        source_id: Use an exact source entity ID.
        target_name: Search for the target entity by name.
        target_id: Use an exact target entity ID.
        min_confidence: Minimum relation confidence (0.0-1.0).
        max_depth: Maximum path length in hops (1-8, default 4).
        max_paths: Maximum number of paths to return (1-100, default 20).
    Returns:
        JSON with all discovered paths sorted by length.
    """
    src = _resolve_seed(source_name, source_id)
    tgt = _resolve_seed(target_name, target_id)
    if not src:
        return _fmt({"error": "Source entity not found"})
    if not tgt:
        return _fmt({"error": "Target entity not found"})

    max_depth = max(1, min(max_depth, 8))
    max_paths = max(1, min(max_paths, 100))
    result = graph_store.find_all_paths(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    return _fmt(
        {
            "source": {"id": result.source.id, "name": result.source.name},
            "target": {"id": result.target.id, "name": result.target.name},
            "algorithm": result.algorithm,
            "paths_found": len(result.paths),
            "paths": [_path_dict(p) for p in result.paths],
        }
    )


@mcp.tool()
def find_longest_path(
    source_name: str | None = None,
    source_id: str | None = None,
    target_name: str | None = None,
    target_id: str | None = None,
    min_confidence: float = 0.0,
    max_depth: int = 6,
) -> str:
    """Find the longest simple path between two entities in the knowledge graph.

    Provide *either* name (fuzzy search) or id for each endpoint.

    Args:
        source_name: Search for the source entity by name.
        source_id: Use an exact source entity ID.
        target_name: Search for the target entity by name.
        target_id: Use an exact target entity ID.
        min_confidence: Minimum relation confidence (0.0-1.0).
        max_depth: Maximum traversal depth / hops (1-10, default 6).
    Returns:
        JSON with the longest path found between the two entities.
    """
    src = _resolve_seed(source_name, source_id)
    tgt = _resolve_seed(target_name, target_id)
    if not src:
        return _fmt({"error": "Source entity not found"})
    if not tgt:
        return _fmt({"error": "Target entity not found"})

    max_depth = max(1, min(max_depth, 10))
    result = graph_store.find_longest_path(
        source_id=src,
        target_id=tgt,
        min_confidence=min_confidence,
        max_depth=max_depth,
    )
    return _fmt(
        {
            "source": {"id": result.source.id, "name": result.source.name},
            "target": {"id": result.target.id, "name": result.target.name},
            "algorithm": result.algorithm,
            "paths_found": len(result.paths),
            "paths": [_path_dict(p) for p in result.paths],
        }
    )


@mcp.tool()
def graph_stats() -> str:
    """Get high-level statistics about the Mimir knowledge-graph.

    Returns:
        JSON with entity/relation counts, run stats, and throughput metrics.
    """
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    try:
        metrics = metrics_store.get_rollup_overview(days=30)
    except Exception:
        metrics = None

    return _fmt(
        {
            "entities": graph_store.count_entities(),
            "relations": graph_store.count_relations(),
            "runs_total": run_store.count_runs(),
            "runs_pending": run_store.count_runs(status="pending"),
            "runs_running": run_store.count_runs(status="running"),
            "runs_completed": run_store.count_runs(status="completed"),
            "runs_failed": run_store.count_runs(status="failed"),
            "rate_per_hour": run_store.count_runs(
                status="completed", since=one_hour_ago
            ),
            "metrics": metrics,
        }
    )


@mcp.tool()
def list_recent_runs(limit: int = 20) -> str:
    """List the most recent extraction runs.

    Args:
        limit: Maximum number of runs to return (default 20).
    Returns:
        JSON list of extraction runs with status and timing.
    """
    limit = max(1, min(limit, 100))
    runs = run_store.list_recent_runs(limit=limit)
    return _fmt([_run_dict(r) for r in runs])


# ── entrypoint ─────────────────────────────────────────────────────────────


def main():
    mcp.run()


if __name__ == "__main__":
    main()
