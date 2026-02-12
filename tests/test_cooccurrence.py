from wellspring.pipeline.runner import _build_cooccurrence_relations
from wellspring.schemas import Entity


def test_cooccurrence_limits_entities():
    entities = [Entity(id=str(i), name=f"E{i}") for i in range(5)]
    relations = _build_cooccurrence_relations(entities, max_entities=3)
    # 3 entities -> 3 pairs
    assert len(relations) == 3
    assert all(r.predicate == "co_occurs_with" for r in relations)
