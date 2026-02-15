"""Tests for mimir.utils.provenance — deterministic provenance-ID generation."""

from __future__ import annotations

from uuid import UUID

from mimir.utils.provenance import (
    NS_PROVENANCE_AIKG,
    NS_PROVENANCE_DEFAULT,
    NS_PROVENANCE_GVM,
    NS_PROVENANCE_MALWARE,
    NS_PROVENANCE_WATCHER,
    det_prov_id,
)


def _base_args(**overrides):
    """Return minimal valid kwargs for det_prov_id with optional overrides."""
    defaults = dict(
        source_uri="https://example.com/report",
        relation_id="rel-123",
        model="test-model",
        chunk_id="chunk-1",
        start_offset=0,
        end_offset=100,
        snippet="APT29 targets government sector",
    )
    defaults.update(overrides)
    return defaults


class TestDetProvId:
    def test_returns_valid_uuid_string(self):
        result = det_prov_id(**_base_args())
        # Should be a valid UUID
        parsed = UUID(result)
        assert str(parsed) == result

    def test_deterministic_same_inputs(self):
        id1 = det_prov_id(**_base_args())
        id2 = det_prov_id(**_base_args())
        assert id1 == id2

    def test_different_snippet_different_id(self):
        id1 = det_prov_id(**_base_args(snippet="snippet A"))
        id2 = det_prov_id(**_base_args(snippet="snippet B"))
        assert id1 != id2

    def test_different_source_uri_different_id(self):
        id1 = det_prov_id(**_base_args(source_uri="https://a.com"))
        id2 = det_prov_id(**_base_args(source_uri="https://b.com"))
        assert id1 != id2

    def test_different_offsets_different_id(self):
        id1 = det_prov_id(**_base_args(start_offset=0, end_offset=100))
        id2 = det_prov_id(**_base_args(start_offset=50, end_offset=200))
        assert id1 != id2

    def test_default_offsets_zero(self):
        explicit = det_prov_id(**_base_args(start_offset=0, end_offset=0))
        # Calling without offset args should use defaults
        args = _base_args()
        args.pop("start_offset")
        args.pop("end_offset")
        implicit = det_prov_id(**args)
        assert explicit == implicit


class TestNamespaceIsolation:
    """Same key material in different namespaces must produce different IDs."""

    def test_default_vs_gvm(self):
        args = _base_args()
        id_default = det_prov_id(namespace=NS_PROVENANCE_DEFAULT, **args)
        id_gvm = det_prov_id(namespace=NS_PROVENANCE_GVM, **args)
        assert id_default != id_gvm

    def test_all_namespaces_distinct(self):
        args = _base_args()
        ids = set()
        for ns in (
            NS_PROVENANCE_DEFAULT,
            NS_PROVENANCE_GVM,
            NS_PROVENANCE_WATCHER,
            NS_PROVENANCE_MALWARE,
            NS_PROVENANCE_AIKG,
        ):
            ids.add(det_prov_id(namespace=ns, **args))
        assert len(ids) == 5

    def test_namespaces_are_valid_uuids(self):
        for ns in (
            NS_PROVENANCE_DEFAULT,
            NS_PROVENANCE_GVM,
            NS_PROVENANCE_WATCHER,
            NS_PROVENANCE_MALWARE,
            NS_PROVENANCE_AIKG,
        ):
            assert isinstance(ns, UUID)
