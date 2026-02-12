from wellspring.pipeline.runner import _infer_is_a_relations
from wellspring.schemas import Relation


def test_infer_is_a_transitive():
    r1 = Relation(
        id="1",
        subject_id="A",
        predicate="is_a",
        object_id="B",
        confidence=0.8,
        attrs={"origin": "extracted"},
    )
    r2 = Relation(
        id="2",
        subject_id="B",
        predicate="is_a",
        object_id="C",
        confidence=0.6,
        attrs={"origin": "extracted"},
    )
    inferred = _infer_is_a_relations([r1, r2])
    assert len(inferred) == 1
    assert inferred[0].subject_id == "A"
    assert inferred[0].object_id == "C"
    assert inferred[0].attrs["origin"] == "inferred"
