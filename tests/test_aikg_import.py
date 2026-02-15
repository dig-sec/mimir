from __future__ import annotations

import pytest

from mimir.connectors.aikg import ingest_aikg_triples, parse_aikg_file
from tests.in_memory_graph_store import InMemoryGraphStore


def test_parse_aikg_file_accepts_array_shape():
    raw = b'[{"subject":"APT28","predicate":"targets","object":"Defense Industry"}]'
    rows = parse_aikg_file(raw, "aikg.json")
    assert len(rows) == 1
    assert rows[0]["subject"] == "APT28"


def test_parse_aikg_file_rejects_non_triples_json():
    with pytest.raises(ValueError):
        parse_aikg_file(b'{"foo":"bar"}', "bad.json")


def test_ingest_aikg_skips_inferred_by_default():
    store = InMemoryGraphStore()
    triples = [
        {"subject": "APT28", "predicate": "targets", "object": "Defense Industry"},
        {
            "subject": "APT28",
            "predicate": "operations via threat",
            "object": "credential access",
            "inferred": True,
        },
    ]

    result = ingest_aikg_triples(
        triples,
        store,
        source_uri="upload://aikg.json",
    )

    assert result.triples_seen == 2
    assert result.triples_imported == 1
    assert result.skipped_inferred == 1
    assert len(store.relations) == 1
    rel = next(iter(store.relations.values()))
    assert rel.predicate == "targets"
    assert rel.attrs.get("origin") == "aikg-import"


def test_ingest_aikg_filters_low_confidence_inferred_triples():
    store = InMemoryGraphStore()
    triples = [
        {
            "subject": "APT28",
            "predicate": "related to",
            "object": "credential access",
            "inferred": True,
        }
    ]

    result = ingest_aikg_triples(
        triples,
        store,
        source_uri="upload://aikg.json",
        include_inferred=True,
        min_inferred_confidence=0.60,
    )

    assert result.triples_seen == 1
    assert result.triples_imported == 0
    assert result.skipped_low_confidence == 1
    assert len(store.relations) == 0


def test_ingest_aikg_infers_types_and_normalizes_predicate():
    store = InMemoryGraphStore()
    triples = [
        {"subject": "CVE-2023-1111", "predicate": "related to", "object": "T1059"},
        {
            "subject": "APT28",
            "predicate": "used",
            "object": "https://evil.example/payload",
        },
    ]

    result = ingest_aikg_triples(
        triples,
        store,
        source_uri="upload://aikg.json",
    )

    assert result.triples_imported == 2
    by_name = {(e.name, e.type): e for e in store.entities.values()}
    assert ("CVE-2023-1111", "vulnerability") in by_name
    assert ("T1059", "attack_pattern") in by_name
    assert ("APT28", "threat_actor") in by_name

    predicates = {r.predicate for r in store.relations.values()}
    assert "related_to" in predicates
    assert "uses" in predicates
