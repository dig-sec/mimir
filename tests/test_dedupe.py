from mimir.dedupe import EntityResolver
from tests.in_memory_graph_store import InMemoryGraphStore


def test_entity_dedupe_by_key():
    store = InMemoryGraphStore()
    resolver = EntityResolver(store)
    e1 = resolver.resolve("Ada Lovelace", "person")
    e2 = resolver.resolve("Ada Lovelace", "person")
    assert e1.id == e2.id
