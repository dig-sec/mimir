from __future__ import annotations

from mimir.storage.elastic import ElasticGraphStore, _ElasticIndices


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return {"hits": {"hits": []}}


def _make_store(client: _FakeClient) -> ElasticGraphStore:
    store = object.__new__(ElasticGraphStore)
    store.client = client
    store.indices = _ElasticIndices("test")
    return store


def test_search_entities_uses_safe_prefix_wildcard_query():
    client = _FakeClient()
    store = _make_store(client)

    result = store.search_entities("  ap?t*  ", entity_type="malware")

    assert result == []
    assert len(client.calls) == 1
    request = client.calls[0]
    bool_query = request["query"]["bool"]
    wildcard_clauses = [
        clause["wildcard"] for clause in bool_query["should"] if "wildcard" in clause
    ]
    name_wildcard = next(
        wildcard for wildcard in wildcard_clauses if "name.keyword" in wildcard
    )
    alias_wildcard = next(
        wildcard for wildcard in wildcard_clauses if "aliases" in wildcard
    )
    wildcard_value = name_wildcard["name.keyword"]["value"]

    assert request["size"] == 50
    assert bool_query["minimum_should_match"] == 1
    assert bool_query["filter"] == [{"term": {"type": "malware"}}]
    assert wildcard_value.endswith("*")
    assert not wildcard_value.startswith("*")
    assert "\\?" in wildcard_value
    assert "\\*" in wildcard_value
    assert alias_wildcard["aliases"]["value"] == wildcard_value


def test_search_entities_uses_canonical_key_filter_path():
    client = _FakeClient()
    store = _make_store(client)

    result = store.search_entities(
        "",
        canonical_key="ada lovelace|person",
        entity_type="person",
    )

    assert result == []
    assert len(client.calls) == 1
    assert client.calls[0]["query"] == {
        "bool": {
            "filter": [
                {"term": {"keys": "ada lovelace|person"}},
                {"term": {"type": "person"}},
            ]
        }
    }
    assert client.calls[0]["size"] == 50


def test_search_entities_skips_blank_query():
    client = _FakeClient()
    store = _make_store(client)

    result = store.search_entities("   ")

    assert result == []
    assert client.calls == []


def test_search_entities_adds_fuzzy_and_compact_clauses():
    client = _FakeClient()
    store = _make_store(client)

    result = store.search_entities("Dyno-Wiper")

    assert result == []
    assert len(client.calls) == 1
    bool_query = client.calls[0]["query"]["bool"]
    should_clauses = bool_query["should"]

    # Fuzzy match clause for typo-tolerant lookup.
    fuzzy_match = next(
        (
            clause["match"]["name"]
            for clause in should_clauses
            if "match" in clause
            and "name" in clause["match"]
            and isinstance(clause["match"]["name"], dict)
            and clause["match"]["name"].get("fuzziness") == "AUTO"
        ),
        None,
    )
    assert fuzzy_match is not None
    assert fuzzy_match["prefix_length"] == 1

    # Compact lookup clauses bridge punctuation differences.
    assert {"term": {"name_compact": "dynowiper"}} in should_clauses
    keyword_wildcards = [
        clause["wildcard"]
        for clause in should_clauses
        if "wildcard" in clause and "name.keyword" in clause["wildcard"]
    ]
    assert keyword_wildcards
    assert keyword_wildcards[-1]["name.keyword"]["value"] == "dynowiper*"
    compact_wildcards = [
        clause["wildcard"]
        for clause in should_clauses
        if "wildcard" in clause and "name_compact" in clause["wildcard"]
    ]
    assert compact_wildcards
    assert compact_wildcards[0]["name_compact"]["value"] == "dynowiper*"
