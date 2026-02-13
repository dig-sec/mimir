from mimir.graph_limits import limit_subgraph
from mimir.schemas import Subgraph, SubgraphEdge, SubgraphNode


def _node(node_id: str) -> SubgraphNode:
    return SubgraphNode(id=node_id, name=node_id, type="test")


def _edge(edge_id: str, source: str, target: str, confidence: float) -> SubgraphEdge:
    return SubgraphEdge(
        id=edge_id,
        subject_id=source,
        predicate="related_to",
        object_id=target,
        confidence=confidence,
        attrs={},
    )


def test_limit_subgraph_no_truncation_when_under_caps():
    subgraph = Subgraph(
        nodes=[_node("a"), _node("b")],
        edges=[_edge("e1", "a", "b", 0.8)],
    )

    limited, truncated = limit_subgraph(
        subgraph,
        seed_id="a",
        max_nodes=10,
        max_edges=10,
    )

    assert limited is subgraph
    assert not truncated


def test_limit_subgraph_prioritizes_seed_neighborhood_for_node_cap():
    subgraph = Subgraph(
        nodes=[_node("a"), _node("b"), _node("c"), _node("d")],
        edges=[
            _edge("e1", "a", "b", 0.9),
            _edge("e2", "b", "c", 0.8),
            _edge("e3", "c", "d", 0.7),
            _edge("e4", "a", "d", 0.2),
        ],
    )

    limited, truncated = limit_subgraph(
        subgraph,
        seed_id="a",
        max_nodes=3,
        max_edges=None,
    )

    assert truncated
    assert {n.id for n in limited.nodes} == {"a", "b", "d"}
    assert {e.id for e in limited.edges} == {"e1", "e4"}


def test_limit_subgraph_caps_edges_and_keeps_seed_node():
    subgraph = Subgraph(
        nodes=[_node("a"), _node("b"), _node("c")],
        edges=[
            _edge("e1", "a", "b", 0.9),
            _edge("e2", "b", "c", 0.8),
            _edge("e3", "a", "c", 0.1),
        ],
    )

    limited, truncated = limit_subgraph(
        subgraph,
        seed_id="c",
        max_nodes=None,
        max_edges=1,
    )

    assert truncated
    assert [e.id for e in limited.edges] == ["e1"]
    assert {n.id for n in limited.nodes} == {"a", "b", "c"}
