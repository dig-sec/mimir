from __future__ import annotations

from mimir.opencti.client import _INLINE, _QUERY_NAME_MAP
from mimir.opencti.sync import _TYPE_MAP, OPENCTI_DEFAULT_ENTITY_TYPES
from mimir.worker.opencti_worker import DEFAULT_ENTITY_TYPES


def test_opencti_type_map_normalizes_location_variants():
    location_types = [
        "Country",
        "Region",
        "City",
        "Administrative-Area",
        "Administrative Area",
        "Position",
        "Location",
    ]
    for entity_type in location_types:
        assert _TYPE_MAP[entity_type] == "location"


def test_opencti_default_pull_includes_location_entity_types():
    for entity_type in (
        "Country",
        "Region",
        "City",
        "Administrative-Area",
        "Position",
    ):
        assert entity_type in OPENCTI_DEFAULT_ENTITY_TYPES


def test_opencti_worker_uses_shared_default_entity_types():
    assert DEFAULT_ENTITY_TYPES == list(OPENCTI_DEFAULT_ENTITY_TYPES)


def test_opencti_query_name_map_includes_location_queries():
    assert _QUERY_NAME_MAP["Country"] == "countries"
    assert _QUERY_NAME_MAP["Region"] == "regions"
    assert _QUERY_NAME_MAP["City"] == "cities"
    assert _QUERY_NAME_MAP["Administrative-Area"] == "administrativeAreas"
    assert _QUERY_NAME_MAP["Position"] == "positions"


def test_opencti_inline_fragments_include_location_names():
    for fragment in (
        "... on Country { name }",
        "... on Region { name }",
        "... on City { name }",
        "... on AdministrativeArea { name }",
        "... on Position { name }",
    ):
        assert fragment in _INLINE
