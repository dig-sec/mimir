from mimir.normalize import (
    canonical_entity_key,
    normalize_entity_name,
    normalize_predicate,
)


def test_normalize_predicate():
    assert normalize_predicate("Wrote Notes") == "wrote_notes"
    assert normalize_predicate("  founded-by ") == "founded_by"


def test_canonical_entity_key():
    assert canonical_entity_key("Ada Lovelace", "Person") == "ada lovelace|person"
    assert normalize_entity_name("  Ada   Lovelace ") == "Ada Lovelace"
