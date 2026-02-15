"""Tests for graph traversal path-finding features.

Covers:
  - Shortest path (BFS)
  - All paths (DFS)
  - Longest path
  - Edge cases: same node, missing nodes, disconnected graphs, cycles
  - Confidence filtering
  - API routes for /path/shortest, /path/all, /path/longest
  - Schema validation for GraphPath and PathResult
"""

from __future__ import annotations

import pytest

from mimir.schemas import (
    Entity,
    GraphPath,
    PathResult,
    Relation,
    SubgraphEdge,
    SubgraphNode,
)
from tests.in_memory_graph_store import InMemoryGraphStore


# ── helpers ────────────────────────────────────────────────────────────────


def _build_chain_graph(n: int = 5, confidence: float = 0.9) -> InMemoryGraphStore:
    """Build a linear chain: A -> B -> C -> D -> E."""
    store = InMemoryGraphStore()
    names = [chr(65 + i) for i in range(n)]  # A, B, C, ...
    entities = [Entity(id=f"e{i}", name=name, type="test") for i, name in enumerate(names)]
    store.upsert_entities(entities)

    relations = []
    for i in range(n - 1):
        relations.append(
            Relation(
                id=f"r{i}",
                subject_id=f"e{i}",
                predicate=f"connects_to",
                object_id=f"e{i+1}",
                confidence=confidence,
            )
        )
    store.upsert_relations(relations)
    return store


def _build_diamond_graph() -> InMemoryGraphStore:
    """
    Build a diamond graph:
        A
       / \\
      B   C
       \\ /
        D
    """
    store = InMemoryGraphStore()
    store.upsert_entities([
        Entity(id="a", name="A", type="test"),
        Entity(id="b", name="B", type="test"),
        Entity(id="c", name="C", type="test"),
        Entity(id="d", name="D", type="test"),
    ])
    store.upsert_relations([
        Relation(id="r_ab", subject_id="a", predicate="links", object_id="b", confidence=0.9),
        Relation(id="r_ac", subject_id="a", predicate="links", object_id="c", confidence=0.9),
        Relation(id="r_bd", subject_id="b", predicate="links", object_id="d", confidence=0.9),
        Relation(id="r_cd", subject_id="c", predicate="links", object_id="d", confidence=0.9),
    ])
    return store


def _build_complex_graph() -> InMemoryGraphStore:
    """
    Build a more complex graph with multiple paths:
        A -- B -- C
        |    |    |
        D -- E -- F
             |
             G
    """
    store = InMemoryGraphStore()
    store.upsert_entities([
        Entity(id="a", name="A", type="test"),
        Entity(id="b", name="B", type="test"),
        Entity(id="c", name="C", type="test"),
        Entity(id="d", name="D", type="test"),
        Entity(id="e", name="E", type="test"),
        Entity(id="f", name="F", type="test"),
        Entity(id="g", name="G", type="test"),
    ])
    store.upsert_relations([
        Relation(id="r_ab", subject_id="a", predicate="links", object_id="b", confidence=0.9),
        Relation(id="r_bc", subject_id="b", predicate="links", object_id="c", confidence=0.9),
        Relation(id="r_ad", subject_id="a", predicate="links", object_id="d", confidence=0.9),
        Relation(id="r_be", subject_id="b", predicate="links", object_id="e", confidence=0.9),
        Relation(id="r_cf", subject_id="c", predicate="links", object_id="f", confidence=0.9),
        Relation(id="r_de", subject_id="d", predicate="links", object_id="e", confidence=0.9),
        Relation(id="r_ef", subject_id="e", predicate="links", object_id="f", confidence=0.9),
        Relation(id="r_eg", subject_id="e", predicate="links", object_id="g", confidence=0.9),
    ])
    return store


# ── schema tests ──────────────────────────────────────────────────────────


class TestGraphPathSchema:
    def test_graph_path_basic(self):
        path = GraphPath(
            nodes=[SubgraphNode(id="a", name="A", type="test")],
            edges=[],
            length=0,
        )
        assert path.length == 0
        assert len(path.nodes) == 1
        assert len(path.edges) == 0

    def test_graph_path_with_edges(self):
        path = GraphPath(
            nodes=[
                SubgraphNode(id="a", name="A", type="test"),
                SubgraphNode(id="b", name="B", type="test"),
            ],
            edges=[
                SubgraphEdge(
                    id="r1", subject_id="a", predicate="links",
                    object_id="b", confidence=0.9,
                ),
            ],
            length=1,
        )
        assert path.length == 1
        assert len(path.nodes) == 2
        assert path.edges[0].predicate == "links"

    def test_path_result_schema(self):
        result = PathResult(
            source=SubgraphNode(id="a", name="A", type="test"),
            target=SubgraphNode(id="b", name="B", type="test"),
            paths=[],
            algorithm="shortest",
        )
        assert result.algorithm == "shortest"
        assert len(result.paths) == 0

    def test_path_result_with_paths(self):
        result = PathResult(
            source=SubgraphNode(id="a", name="A", type="test"),
            target=SubgraphNode(id="c", name="C", type="test"),
            paths=[
                GraphPath(
                    nodes=[
                        SubgraphNode(id="a", name="A", type="test"),
                        SubgraphNode(id="b", name="B", type="test"),
                        SubgraphNode(id="c", name="C", type="test"),
                    ],
                    edges=[
                        SubgraphEdge(id="r1", subject_id="a", predicate="to", object_id="b", confidence=0.8),
                        SubgraphEdge(id="r2", subject_id="b", predicate="to", object_id="c", confidence=0.7),
                    ],
                    length=2,
                ),
            ],
            algorithm="all",
        )
        assert len(result.paths) == 1
        assert result.paths[0].length == 2

    def test_path_result_serialization(self):
        result = PathResult(
            source=SubgraphNode(id="a", name="A", type=None),
            target=SubgraphNode(id="b", name="B", type=None),
            paths=[],
            algorithm="longest",
        )
        d = result.model_dump()
        assert d["algorithm"] == "longest"
        assert d["source"]["id"] == "a"
        assert d["paths"] == []


# ── shortest path tests ──────────────────────────────────────────────────


class TestShortestPath:
    def test_same_node(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("e0", "e0")
        assert result.algorithm == "shortest"
        assert len(result.paths) == 1
        assert result.paths[0].length == 0
        assert result.paths[0].nodes[0].id == "e0"

    def test_direct_neighbors(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("e0", "e1")
        assert len(result.paths) == 1
        assert result.paths[0].length == 1
        assert result.paths[0].nodes[0].id == "e0"
        assert result.paths[0].nodes[1].id == "e1"

    def test_chain_path(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("e0", "e4")
        assert len(result.paths) == 1
        assert result.paths[0].length == 4
        node_ids = [n.id for n in result.paths[0].nodes]
        assert node_ids == ["e0", "e1", "e2", "e3", "e4"]

    def test_diamond_shortest(self):
        """In a diamond A->B->D and A->C->D, shortest is 2 hops."""
        store = _build_diamond_graph()
        result = store.find_shortest_path("a", "d")
        assert len(result.paths) == 1
        assert result.paths[0].length == 2

    def test_reverse_direction(self):
        """Graph edges are traversed bidirectionally."""
        store = _build_chain_graph()
        result = store.find_shortest_path("e4", "e0")
        assert len(result.paths) == 1
        assert result.paths[0].length == 4

    def test_entity_not_found(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("e0", "nonexistent")
        assert len(result.paths) == 0

    def test_source_not_found(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("nonexistent", "e0")
        assert len(result.paths) == 0

    def test_disconnected_graph(self):
        """Two disconnected components -> no path."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        # No relations between them
        result = store.find_shortest_path("a", "b")
        assert len(result.paths) == 0

    def test_max_depth_exceeded(self):
        """Chain of 5 hops with max_depth=2 -> no path found."""
        store = _build_chain_graph(n=6)
        result = store.find_shortest_path("e0", "e5", max_depth=2)
        assert len(result.paths) == 0

    def test_max_depth_sufficient(self):
        store = _build_chain_graph(n=6)
        result = store.find_shortest_path("e0", "e5", max_depth=5)
        assert len(result.paths) == 1
        assert result.paths[0].length == 5

    def test_confidence_filter(self):
        """Low-confidence edges are excluded."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
            Entity(id="c", name="C", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="a", predicate="links", object_id="b", confidence=0.3),
            Relation(id="r2", subject_id="b", predicate="links", object_id="c", confidence=0.9),
        ])
        # With min_confidence=0.5, the a->b edge is excluded
        result = store.find_shortest_path("a", "c", min_confidence=0.5)
        assert len(result.paths) == 0

        # With min_confidence=0.0, the path is found
        result = store.find_shortest_path("a", "c", min_confidence=0.0)
        assert len(result.paths) == 1
        assert result.paths[0].length == 2

    def test_result_contains_edges(self):
        store = _build_chain_graph(n=3)
        result = store.find_shortest_path("e0", "e2")
        path = result.paths[0]
        assert len(path.edges) == 2
        assert all(e.predicate == "connects_to" for e in path.edges)

    def test_source_and_target_in_result(self):
        store = _build_chain_graph()
        result = store.find_shortest_path("e0", "e2")
        assert result.source.id == "e0"
        assert result.target.id == "e2"
        assert result.source.name == "A"
        assert result.target.name == "C"


# ── all paths tests ──────────────────────────────────────────────────────


class TestAllPaths:
    def test_same_node(self):
        store = _build_chain_graph()
        result = store.find_all_paths("e0", "e0")
        assert result.algorithm == "all"
        assert len(result.paths) == 1
        assert result.paths[0].length == 0

    def test_chain_single_path(self):
        store = _build_chain_graph()
        result = store.find_all_paths("e0", "e4", max_depth=4)
        assert len(result.paths) == 1
        assert result.paths[0].length == 4

    def test_diamond_two_paths(self):
        """Diamond graph A->D has two paths: A-B-D and A-C-D."""
        store = _build_diamond_graph()
        result = store.find_all_paths("a", "d", max_depth=3)
        assert len(result.paths) == 2
        lengths = sorted(p.length for p in result.paths)
        assert lengths == [2, 2]

    def test_complex_multiple_paths(self):
        """Complex graph A->F should have multiple paths."""
        store = _build_complex_graph()
        result = store.find_all_paths("a", "f", max_depth=5)
        assert len(result.paths) >= 2  # At least A-B-C-F and A-B-E-F and A-D-E-F etc.

    def test_all_paths_sorted_by_length(self):
        store = _build_complex_graph()
        result = store.find_all_paths("a", "f", max_depth=6)
        lengths = [p.length for p in result.paths]
        assert lengths == sorted(lengths)

    def test_max_paths_limit(self):
        store = _build_complex_graph()
        result = store.find_all_paths("a", "f", max_depth=6, max_paths=1)
        assert len(result.paths) <= 1

    def test_depth_limit_filters_long_paths(self):
        store = _build_complex_graph()
        result_short = store.find_all_paths("a", "f", max_depth=2)
        result_long = store.find_all_paths("a", "f", max_depth=6)
        # With shorter depth, fewer or shorter paths
        for p in result_short.paths:
            assert p.length <= 2
        assert len(result_long.paths) >= len(result_short.paths)

    def test_no_path_disconnected(self):
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        result = store.find_all_paths("a", "b")
        assert len(result.paths) == 0

    def test_entity_not_found(self):
        store = _build_chain_graph()
        result = store.find_all_paths("e0", "nonexistent")
        assert len(result.paths) == 0

    def test_paths_are_simple(self):
        """All paths should be simple (no repeated nodes)."""
        store = _build_complex_graph()
        result = store.find_all_paths("a", "f", max_depth=6)
        for path in result.paths:
            node_ids = [n.id for n in path.nodes]
            assert len(node_ids) == len(set(node_ids)), f"Repeated nodes in path: {node_ids}"


# ── longest path tests ──────────────────────────────────────────────────


class TestLongestPath:
    def test_chain_longest(self):
        store = _build_chain_graph()
        result = store.find_longest_path("e0", "e4")
        assert result.algorithm == "longest"
        assert len(result.paths) == 1
        assert result.paths[0].length == 4

    def test_diamond_longest(self):
        """In diamond, both paths are length 2, so longest is 2."""
        store = _build_diamond_graph()
        result = store.find_longest_path("a", "d")
        assert len(result.paths) == 1
        assert result.paths[0].length == 2

    def test_complex_longest(self):
        """In complex graph, longest A->F should be longer than shortest."""
        store = _build_complex_graph()
        shortest_result = store.find_shortest_path("a", "f")
        longest_result = store.find_longest_path("a", "f")
        assert len(longest_result.paths) == 1
        assert longest_result.paths[0].length >= shortest_result.paths[0].length

    def test_same_node_longest(self):
        store = _build_chain_graph()
        result = store.find_longest_path("e0", "e0")
        assert len(result.paths) == 1
        assert result.paths[0].length == 0

    def test_no_path_longest(self):
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        result = store.find_longest_path("a", "b")
        assert len(result.paths) == 0

    def test_entity_not_found_longest(self):
        store = _build_chain_graph()
        result = store.find_longest_path("e0", "missing")
        assert len(result.paths) == 0


# ── cycle handling tests ─────────────────────────────────────────────────


class TestCycleHandling:
    def test_triangle_cycle(self):
        """A cycle A-B-C-A should still find paths without infinite loop."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
            Entity(id="c", name="C", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="a", predicate="links", object_id="b", confidence=0.9),
            Relation(id="r2", subject_id="b", predicate="links", object_id="c", confidence=0.9),
            Relation(id="r3", subject_id="c", predicate="links", object_id="a", confidence=0.9),
        ])
        result = store.find_shortest_path("a", "c")
        assert len(result.paths) == 1
        # Shortest is 1 hop (c->a edge traversed as a->c) or 2 hops (a->b->c)
        assert result.paths[0].length <= 2

    def test_cycle_all_paths(self):
        """All paths in a cycle graph are simple (no loops)."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
            Entity(id="c", name="C", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="a", predicate="links", object_id="b", confidence=0.9),
            Relation(id="r2", subject_id="b", predicate="links", object_id="c", confidence=0.9),
            Relation(id="r3", subject_id="c", predicate="links", object_id="a", confidence=0.9),
        ])
        result = store.find_all_paths("a", "c", max_depth=5)
        assert len(result.paths) >= 1
        for path in result.paths:
            node_ids = [n.id for n in path.nodes]
            assert len(node_ids) == len(set(node_ids))

    def test_self_loop(self):
        """An entity with a self-referencing relation."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r_self", subject_id="a", predicate="self_ref", object_id="a", confidence=0.9),
            Relation(id="r_ab", subject_id="a", predicate="links", object_id="b", confidence=0.9),
        ])
        result = store.find_shortest_path("a", "b")
        assert len(result.paths) == 1
        assert result.paths[0].length == 1


# ── bidirectional traversal tests ─────────────────────────────────────────


class TestBidirectional:
    def test_forward_edge(self):
        """A->B: path from A to B uses forward edge."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="a", predicate="targets", object_id="b", confidence=0.9),
        ])
        result = store.find_shortest_path("a", "b")
        assert len(result.paths) == 1

    def test_backward_edge(self):
        """A->B: path from B to A uses backward traversal."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="a", name="A", type="test"),
            Entity(id="b", name="B", type="test"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="a", predicate="targets", object_id="b", confidence=0.9),
        ])
        result = store.find_shortest_path("b", "a")
        assert len(result.paths) == 1
        assert result.paths[0].length == 1


# ── threat-intelligence scenario tests ────────────────────────────────────


class TestCTIScenarios:
    def test_malware_to_threat_actor_path(self):
        """Realistic CTI: find path from malware to threat actor."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="m1", name="Emotet", type="malware"),
            Entity(id="ta1", name="TA542", type="threat_actor"),
            Entity(id="c1", name="Campaign-2024", type="campaign"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="ta1", predicate="uses", object_id="m1", confidence=0.95),
            Relation(id="r2", subject_id="ta1", predicate="attributed_to", object_id="c1", confidence=0.85),
        ])
        result = store.find_shortest_path("m1", "c1")
        assert len(result.paths) == 1
        assert result.paths[0].length == 2  # m1 -> ta1 -> c1

    def test_vulnerability_attack_chain(self):
        """Find path through a complex attack chain."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="v1", name="CVE-2024-1234", type="vulnerability"),
            Entity(id="e1", name="exploit-kit-1", type="tool"),
            Entity(id="m1", name="Cobalt Strike", type="malware"),
            Entity(id="ta1", name="APT29", type="threat_actor"),
            Entity(id="infra1", name="C2 Server", type="infrastructure"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="e1", predicate="exploits", object_id="v1", confidence=0.9),
            Relation(id="r2", subject_id="e1", predicate="delivers", object_id="m1", confidence=0.85),
            Relation(id="r3", subject_id="ta1", predicate="uses", object_id="m1", confidence=0.95),
            Relation(id="r4", subject_id="ta1", predicate="operates", object_id="infra1", confidence=0.88),
        ])
        # Shortest path from vulnerability to C2 server
        result = store.find_shortest_path("v1", "infra1")
        assert len(result.paths) == 1
        assert result.paths[0].length == 4  # v1-e1-m1-ta1-infra1

        # All paths
        all_result = store.find_all_paths("v1", "infra1", max_depth=5)
        assert len(all_result.paths) >= 1

    def test_disjoint_threat_actors(self):
        """Two unrelated threat actors have no path."""
        store = InMemoryGraphStore()
        store.upsert_entities([
            Entity(id="ta1", name="APT28", type="threat_actor"),
            Entity(id="m1", name="X-Agent", type="malware"),
            Entity(id="ta2", name="Lazarus", type="threat_actor"),
            Entity(id="m2", name="DTrack", type="malware"),
        ])
        store.upsert_relations([
            Relation(id="r1", subject_id="ta1", predicate="uses", object_id="m1", confidence=0.95),
            Relation(id="r2", subject_id="ta2", predicate="uses", object_id="m2", confidence=0.95),
        ])
        result = store.find_shortest_path("ta1", "ta2")
        assert len(result.paths) == 0


# ── API route tests ──────────────────────────────────────────────────────


class TestPathAPIRoutes:
    """Test the FastAPI path-finding routes using TestClient."""

    @pytest.fixture(autouse=True)
    def setup_routes(self, monkeypatch):
        """Patch the graph store in routes module with an in-memory store."""
        import importlib
        import sys

        self.store = _build_diamond_graph()

        import mimir.storage.factory as factory

        monkeypatch.setattr(factory, "create_graph_store", lambda settings: self.store)
        monkeypatch.setattr(
            factory, "create_run_store", lambda settings: type("RS", (), {
                "count_runs": lambda self, **kw: 0,
                "list_recent_runs": lambda self, **kw: [],
            })(),
        )
        monkeypatch.setattr(
            factory, "create_metrics_store", lambda settings: type("MS", (), {
                "get_rollup_overview": lambda self, **kw: None,
            })(),
        )

        sys.modules.pop("mimir.api.routes", None)
        routes = importlib.import_module("mimir.api.routes")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(routes.router)
        self.client = TestClient(app)
        self._routes = routes

    def test_shortest_path_by_id(self):
        resp = self.client.get("/path/shortest", params={"source_id": "a", "target_id": "d"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "shortest"
        assert len(data["paths"]) == 1
        assert data["paths"][0]["length"] == 2

    def test_shortest_path_by_name(self):
        resp = self.client.get("/path/shortest", params={"source_name": "A", "target_name": "D"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["paths"]) == 1

    def test_all_paths_by_id(self):
        resp = self.client.get("/path/all", params={"source_id": "a", "target_id": "d"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "all"
        assert len(data["paths"]) == 2  # Two paths in diamond

    def test_longest_path_by_id(self):
        resp = self.client.get("/path/longest", params={"source_id": "a", "target_id": "d"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "longest"
        assert len(data["paths"]) == 1

    def test_missing_source_returns_404(self):
        resp = self.client.get("/path/shortest", params={"source_id": "missing", "target_id": "d"})
        assert resp.status_code == 404

    def test_missing_params_returns_400(self):
        resp = self.client.get("/path/shortest", params={"target_id": "d"})
        assert resp.status_code == 400

    def test_same_source_target(self):
        resp = self.client.get("/path/shortest", params={"source_id": "a", "target_id": "a"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["paths"]) == 1
        assert data["paths"][0]["length"] == 0

    def test_path_visualize(self):
        resp = self.client.get(
            "/path/visualize",
            params={"source_id": "a", "target_id": "d", "algorithm": "shortest"},
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Path:" in resp.text

    def test_path_visualize_no_path(self):
        """Visualize endpoint returns 404 when no path exists."""
        store2 = InMemoryGraphStore()
        store2.upsert_entities([
            Entity(id="x", name="X", type="test"),
            Entity(id="y", name="Y", type="test"),
        ])
        original = self._routes.graph_store
        self._routes.graph_store = store2
        try:
            resp = self.client.get(
                "/path/visualize",
                params={"source_id": "x", "target_id": "y"},
            )
            assert resp.status_code == 404
        finally:
            self._routes.graph_store = original

    def test_max_depth_param(self):
        resp = self.client.get(
            "/path/shortest",
            params={"source_id": "a", "target_id": "d", "max_depth": "1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Diamond: a->d needs 2 hops, max_depth=1 means no path
        assert len(data["paths"]) == 0

    def test_confidence_filter_param(self):
        resp = self.client.get(
            "/path/shortest",
            params={"source_id": "a", "target_id": "d", "min_confidence": "0.95"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # All edges have confidence 0.9, so min_confidence=0.95 excludes them
        assert len(data["paths"]) == 0
