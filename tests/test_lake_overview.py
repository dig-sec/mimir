from __future__ import annotations

import importlib
import sys


class _NoopStore:
    pass


def _load_routes(monkeypatch):
    import mimir.storage.factory as factory

    monkeypatch.setattr(factory, "create_graph_store", lambda settings: _NoopStore())
    monkeypatch.setattr(factory, "create_run_store", lambda settings: _NoopStore())
    monkeypatch.setattr(factory, "create_metrics_store", lambda settings: _NoopStore())

    for key in list(sys.modules):
        if key.startswith("mimir.api.routes"):
            sys.modules.pop(key, None)
    return importlib.import_module("mimir.api.routes")


class _LakeIndices:
    documents = "mimir-documents"
    provenance = "mimir-provenance"


class _LakeClient:
    def search(self, *, index, size=0, aggs=None):
        if index == "mimir-documents":
            return {
                "aggregations": {
                    "sources": {
                        "buckets": [
                            {
                                "key": "opencti",
                                "doc_count": 3,
                                "collections": {
                                    "buckets": [{"key": "report", "doc_count": 3}]
                                },
                            },
                            {
                                "key": "rss",
                                "doc_count": 2,
                                "collections": {
                                    "buckets": [
                                        {
                                            "key": "www.cisa.gov:cybersecurity-advisories_all.xml",
                                            "doc_count": 2,
                                        }
                                    ]
                                },
                            },
                        ]
                    }
                }
            }
        if index == "mimir-provenance":
            return {
                "aggregations": {
                    "source_uris": {
                        "buckets": [
                            {
                                "key": "rss://www.cisa.gov:cybersecurity-advisories_all.xml/abc123",
                                "doc_count": 4,
                            },
                            {
                                "key": "watcher://http://watcher.local:9002",
                                "doc_count": 5,
                            },
                            {"key": "gvm://127.0.0.1", "doc_count": 7},
                        ]
                    }
                }
            }
        raise AssertionError(f"Unexpected index {index}")

    def count(self, *, index, query):
        if index == "mimir-documents":
            return {"count": 5}
        if index == "mimir-provenance":
            return {"count": 16}
        raise AssertionError(f"Unexpected index {index}")


def test_lake_overview_combines_document_and_provenance_sources(monkeypatch):
    routes = _load_routes(monkeypatch)

    lake_client = _LakeClient()
    fake_run_store = type(
        "RunStore", (), {"client": lake_client, "indices": _LakeIndices()}
    )()
    fake_graph_store = type(
        "GraphStore",
        (),
        {"client": lake_client, "indices": _LakeIndices()},
    )()

    # Patch at the sub-module level so the function sees the new stores
    import mimir.api.routes.intelligence as _intel

    _intel.run_store = fake_run_store
    _intel.graph_store = fake_graph_store

    payload = routes.lake_overview()

    assert payload["backend"] == "elasticsearch"
    assert payload["documents_total"] == 5
    assert payload["provenance_total"] == 16
    assert payload["documents_exact"] is True
    assert payload["provenance_exact"] is True
    assert payload["exact"] is True

    combined = {row["source"]: row for row in payload["combined_sources"]}
    assert combined["rss"]["docs"] == 2
    assert combined["rss"]["provenance_records"] == 4
    rss_collection = {row["collection"]: row for row in combined["rss"]["collections"]}[
        "www.cisa.gov:cybersecurity-advisories_all.xml"
    ]
    assert rss_collection["docs"] == 2
    assert rss_collection["provenance_records"] == 4

    assert combined["watcher"]["docs"] == 0
    assert combined["watcher"]["provenance_records"] == 5
    assert combined["watcher"]["collections"][0]["collection"] == "instance"

    assert combined["gvm"]["docs"] == 0
    assert combined["gvm"]["provenance_records"] == 7
    assert combined["gvm"]["collections"][0]["collection"] == "instance"
