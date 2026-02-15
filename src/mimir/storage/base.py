from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from ..schemas import (
    Entity,
    ExtractionRun,
    GraphPath,
    PathResult,
    Provenance,
    Relation,
    Subgraph,
    SubgraphEdge,
    SubgraphNode,
)


class GraphStore(ABC):
    @abstractmethod
    def upsert_entities(self, entities: List[Entity]) -> List[Entity]:
        raise NotImplementedError

    @abstractmethod
    def upsert_relations(self, relations: List[Relation]) -> List[Relation]:
        raise NotImplementedError

    @abstractmethod
    def attach_provenance(self, relation_id: str, provenance: Provenance) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        raise NotImplementedError

    @abstractmethod
    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        canonical_key: Optional[str] = None,
    ) -> List[Entity]:
        raise NotImplementedError

    @abstractmethod
    def get_subgraph(
        self,
        seed_entity_id: str,
        depth: int = 1,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Subgraph:
        raise NotImplementedError

    @abstractmethod
    def get_full_graph(self, min_confidence: float = 0.0) -> Subgraph:
        raise NotImplementedError

    @abstractmethod
    def explain_edge(
        self, relation_id: str
    ) -> Tuple[Relation, List[Provenance], List[ExtractionRun]]:
        raise NotImplementedError

    @abstractmethod
    def count_entities(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def count_relations(self) -> int:
        raise NotImplementedError

    # ── path-finding helpers (concrete, built on get_subgraph) ─────────

    def _build_adjacency(
        self,
        subgraph: Subgraph,
    ) -> Tuple[
        Dict[str, SubgraphNode],
        Dict[str, List[Tuple[str, SubgraphEdge]]],
    ]:
        """Build adjacency list from a subgraph (undirected)."""
        node_map: Dict[str, SubgraphNode] = {n.id: n for n in subgraph.nodes}
        adj: Dict[str, List[Tuple[str, SubgraphEdge]]] = {}
        for edge in subgraph.edges:
            adj.setdefault(edge.subject_id, []).append((edge.object_id, edge))
            adj.setdefault(edge.object_id, []).append((edge.subject_id, edge))
        return node_map, adj

    def _reconstruct_path(
        self,
        predecessors: Dict[str, Tuple[str, SubgraphEdge]],
        node_map: Dict[str, SubgraphNode],
        source_id: str,
        target_id: str,
    ) -> GraphPath:
        """Walk backwards through *predecessors* to build a GraphPath."""
        path_nodes: list[SubgraphNode] = []
        path_edges: list[SubgraphEdge] = []
        current = target_id
        while current != source_id:
            path_nodes.append(node_map[current])
            prev_id, edge = predecessors[current]
            path_edges.append(edge)
            current = prev_id
        path_nodes.append(node_map[source_id])
        path_nodes.reverse()
        path_edges.reverse()
        return GraphPath(nodes=path_nodes, edges=path_edges, length=len(path_edges))

    def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        min_confidence: float = 0.0,
        max_depth: int = 6,
    ) -> PathResult:
        """BFS shortest path between two entities.

        The graph is expanded layer-by-layer up to *max_depth* hops using
        ``get_subgraph``, so the method works for both in-memory and
        Elasticsearch-backed stores.
        """
        source_entity = self.get_entity(source_id)
        target_entity = self.get_entity(target_id)
        if not source_entity or not target_entity:
            src_node = SubgraphNode(
                id=source_id, name=source_id, type=None
            )
            tgt_node = SubgraphNode(
                id=target_id, name=target_id, type=None
            )
            return PathResult(
                source=src_node, target=tgt_node, paths=[], algorithm="shortest"
            )

        src_node = SubgraphNode(
            id=source_entity.id, name=source_entity.name, type=source_entity.type
        )
        tgt_node = SubgraphNode(
            id=target_entity.id, name=target_entity.name, type=target_entity.type
        )

        if source_id == target_id:
            return PathResult(
                source=src_node,
                target=tgt_node,
                paths=[GraphPath(nodes=[src_node], edges=[], length=0)],
                algorithm="shortest",
            )

        # Expand the subgraph around the source up to max_depth hops
        subgraph = self.get_subgraph(
            seed_entity_id=source_id,
            depth=max_depth,
            min_confidence=min_confidence,
        )
        node_map, adj = self._build_adjacency(subgraph)

        if target_id not in node_map:
            return PathResult(
                source=src_node, target=tgt_node, paths=[], algorithm="shortest"
            )

        # BFS
        visited: Set[str] = {source_id}
        predecessors: Dict[str, Tuple[str, SubgraphEdge]] = {}
        queue: deque[str] = deque([source_id])

        while queue:
            current = queue.popleft()
            for neighbor_id, edge in adj.get(current, []):
                if neighbor_id in visited:
                    continue
                visited.add(neighbor_id)
                predecessors[neighbor_id] = (current, edge)
                if neighbor_id == target_id:
                    path = self._reconstruct_path(
                        predecessors, node_map, source_id, target_id
                    )
                    return PathResult(
                        source=src_node,
                        target=tgt_node,
                        paths=[path],
                        algorithm="shortest",
                    )
                queue.append(neighbor_id)

        return PathResult(
            source=src_node, target=tgt_node, paths=[], algorithm="shortest"
        )

    def find_all_paths(
        self,
        source_id: str,
        target_id: str,
        min_confidence: float = 0.0,
        max_depth: int = 4,
        max_paths: int = 20,
    ) -> PathResult:
        """DFS to enumerate all simple paths up to *max_depth* hops."""
        source_entity = self.get_entity(source_id)
        target_entity = self.get_entity(target_id)
        if not source_entity or not target_entity:
            src_node = SubgraphNode(id=source_id, name=source_id, type=None)
            tgt_node = SubgraphNode(id=target_id, name=target_id, type=None)
            return PathResult(
                source=src_node, target=tgt_node, paths=[], algorithm="all"
            )

        src_node = SubgraphNode(
            id=source_entity.id, name=source_entity.name, type=source_entity.type
        )
        tgt_node = SubgraphNode(
            id=target_entity.id, name=target_entity.name, type=target_entity.type
        )

        if source_id == target_id:
            return PathResult(
                source=src_node,
                target=tgt_node,
                paths=[GraphPath(nodes=[src_node], edges=[], length=0)],
                algorithm="all",
            )

        subgraph = self.get_subgraph(
            seed_entity_id=source_id,
            depth=max_depth,
            min_confidence=min_confidence,
        )
        node_map, adj = self._build_adjacency(subgraph)

        if target_id not in node_map:
            return PathResult(
                source=src_node, target=tgt_node, paths=[], algorithm="all"
            )

        paths: list[GraphPath] = []

        # Iterative DFS with explicit stack
        # Stack items: (current_node, path_nodes, path_edges, visited_set)
        stack: list[
            Tuple[str, list[SubgraphNode], list[SubgraphEdge], Set[str]]
        ] = [(source_id, [node_map[source_id]], [], {source_id})]

        while stack and len(paths) < max_paths:
            current, p_nodes, p_edges, p_visited = stack.pop()
            if current == target_id:
                paths.append(
                    GraphPath(
                        nodes=list(p_nodes),
                        edges=list(p_edges),
                        length=len(p_edges),
                    )
                )
                continue
            if len(p_edges) >= max_depth:
                continue
            for neighbor_id, edge in adj.get(current, []):
                if neighbor_id in p_visited:
                    continue
                new_visited = p_visited | {neighbor_id}
                stack.append((
                    neighbor_id,
                    p_nodes + [node_map[neighbor_id]],
                    p_edges + [edge],
                    new_visited,
                ))

        paths.sort(key=lambda p: p.length)
        return PathResult(
            source=src_node, target=tgt_node, paths=paths, algorithm="all"
        )

    def find_longest_path(
        self,
        source_id: str,
        target_id: str,
        min_confidence: float = 0.0,
        max_depth: int = 6,
    ) -> PathResult:
        """Find the longest simple path (by hop count) between two entities.

        Uses ``find_all_paths`` internally and picks the longest result.
        """
        all_result = self.find_all_paths(
            source_id=source_id,
            target_id=target_id,
            min_confidence=min_confidence,
            max_depth=max_depth,
            max_paths=100,  # explore more to find the longest
        )
        source_node = all_result.source
        target_node = all_result.target

        if not all_result.paths:
            return PathResult(
                source=source_node,
                target=target_node,
                paths=[],
                algorithm="longest",
            )

        longest = max(all_result.paths, key=lambda p: p.length)
        return PathResult(
            source=source_node,
            target=target_node,
            paths=[longest],
            algorithm="longest",
        )
