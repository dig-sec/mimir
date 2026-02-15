from mimir.schemas import Entity, Relation
from tests.in_memory_graph_store import InMemoryGraphStore


def test_relation_merge_sums_numeric_attrs():
    store = InMemoryGraphStore()
    subject = Entity(id="s1", name="Subject", type=None)
    obj = Entity(id="o1", name="Object", type=None)
    store.upsert_entities([subject, obj])

    rel1 = Relation(
        id="r1",
        subject_id=subject.id,
        predicate="co_occurs_with",
        object_id=obj.id,
        confidence=0.1,
        attrs={"origin": "cooccurrence", "co_occurrence_count": 1},
    )
    rel2 = Relation(
        id="r2",
        subject_id=subject.id,
        predicate="co_occurs_with",
        object_id=obj.id,
        confidence=0.2,
        attrs={"origin": "cooccurrence", "co_occurrence_count": 2},
    )

    stored = store.upsert_relations([rel1])
    stored = store.upsert_relations([rel2])

    assert stored[0].confidence == 0.2
    assert stored[0].attrs["co_occurrence_count"] == 3
