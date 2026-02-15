from __future__ import annotations

import importlib
import json
import sys
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class _Entity:
    id: str
    name: str
    type: str
    aliases: list[str]


class _DummyGraphStore:
    def __init__(self) -> None:
        self.search_calls: list[tuple[str, Optional[str]]] = []

    def search_entities(self, query: str, entity_type: Optional[str] = None):
        self.search_calls.append((query, entity_type))
        if query.lower().replace("-", "").replace(" ", "") == "dynowiper":
            return [
                _Entity(
                    id="97e1581f",
                    name="DynoWiper",
                    type="malware",
                    aliases=["DYNOWIPER"],
                )
            ]
        return []

    def get_entity(self, entity_id: str):  # pragma: no cover - helper only
        return None

    def get_subgraph(self, *args: Any, **kwargs: Any):  # pragma: no cover - helper only
        class _Sub:
            nodes = []
            edges = []

        return _Sub()

    def explain_edge(self, relation_id: str):  # pragma: no cover - helper only
        raise KeyError(relation_id)

    def count_entities(self) -> int:
        return 42

    def count_relations(self) -> int:
        return 24


class _DummyRunStore:
    def count_runs(self, status: Optional[str] = None, since: Any = None) -> int:
        if status == "completed":
            return 3
        return 0

    def list_recent_runs(self, limit: int = 20):  # pragma: no cover - helper only
        return []


class _DummyMetricsStore:
    def get_rollup_overview(self, days: int = 30):
        return {"active_actors": 7}


def _load_mcp_server(monkeypatch):
    import mimir.storage.factory as factory

    graph = _DummyGraphStore()
    monkeypatch.setattr(factory, "create_graph_store", lambda settings: graph)
    monkeypatch.setattr(factory, "create_run_store", lambda settings: _DummyRunStore())
    monkeypatch.setattr(
        factory, "create_metrics_store", lambda settings: _DummyMetricsStore()
    )

    sys.modules.pop("mimir.mcp.server", None)
    module = importlib.import_module("mimir.mcp.server")
    return module, graph


def test_mcp_search_entities_delegates_to_graph_store(monkeypatch):
    mcp_server, graph = _load_mcp_server(monkeypatch)

    payload = json.loads(
        mcp_server.search_entities("dyno-wiper", entity_type="malware")
    )

    assert graph.search_calls == [("dyno-wiper", "malware")]
    assert payload
    assert payload[0]["name"] == "DynoWiper"
    assert payload[0]["type"] == "malware"


def test_mcp_graph_stats_uses_shared_stores(monkeypatch):
    mcp_server, _graph = _load_mcp_server(monkeypatch)

    payload = json.loads(mcp_server.graph_stats())

    assert payload["entities"] == 42
    assert payload["relations"] == 24
    assert payload["runs_completed"] == 3
    assert payload["metrics"]["active_actors"] == 7
