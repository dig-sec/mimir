"""Tests for the GVM (Greenbone Vulnerability Management) connector.

Uses an in-memory graph store and synthetic GVM XML result elements
to validate entity extraction, relation creation, and provenance
attachment without needing a live GVM instance.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from mimir.config import Settings
from mimir.connectors.gvm import (
    GvmSyncResult,
    _extract_cve_entities,
    _extract_cves,
    _extract_host_entity,
    _extract_port_entity,
    _extract_service_entity,
    _extract_technology_entity,
    _extract_vulnerability_entity,
    _parse_iso_datetime,
    _parse_port_proto,
    _process_result,
    _severity_label,
    _xml_float,
    _xml_int,
    _xml_text,
    sync_gvm,
)
from mimir.dedupe import EntityResolver
from mimir.schemas import Entity

from .in_memory_graph_store import InMemoryGraphStore


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture
def graph_store() -> InMemoryGraphStore:
    return InMemoryGraphStore()


@pytest.fixture
def resolver(graph_store: InMemoryGraphStore) -> EntityResolver:
    return EntityResolver(store=graph_store)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        gvm_worker_enabled=True,
        gvm_connection_type="unix",
        gvm_socket_path="/run/gvmd/gvmd.sock",
        gvm_host="127.0.0.1",
        gvm_port=9390,
        gvm_username="admin",
        gvm_password="admin",
        gvm_max_results=500,
        gvm_min_qod=30,
    )


# ── Helpers to build GMP result XML ─────────────────────────


def _build_result_xml(
    *,
    result_id: str = "r-001",
    host: str = "10.0.0.1",
    hostname: str = "",
    port: str = "443/tcp",
    nvt_oid: str = "1.3.6.1.4.1.25623.1.0.100001",
    nvt_name: str = "Test NVT",
    nvt_family: str = "General",
    severity: str = "7.5",
    qod_value: str = "80",
    qod_type: str = "remote_banner",
    description: str = "Test vulnerability found.",
    cve_refs: Optional[List[str]] = None,
    tags: str = "",
    modification_time: str = "2026-02-15T10:00:00Z",
    solution_type: str = "VendorFix",
    solution_text: str = "Upgrade to latest version.",
) -> ET.Element:
    """Build a synthetic <result> XML element mimicking GMP output."""
    root = ET.Element("result", attrib={"id": result_id})

    host_elem = ET.SubElement(root, "host")
    host_elem.text = host
    if hostname:
        hn = ET.SubElement(host_elem, "hostname")
        hn.text = hostname
    asset = ET.SubElement(host_elem, "asset", attrib={"asset_id": f"asset-{host}"})

    port_elem = ET.SubElement(root, "port")
    port_elem.text = port

    nvt_elem = ET.SubElement(root, "nvt", attrib={"oid": nvt_oid})
    name_elem = ET.SubElement(nvt_elem, "name")
    name_elem.text = nvt_name
    family_elem = ET.SubElement(nvt_elem, "family")
    family_elem.text = nvt_family
    tags_elem = ET.SubElement(nvt_elem, "tags")
    tags_elem.text = tags

    if cve_refs:
        refs_elem = ET.SubElement(nvt_elem, "refs")
        for cve in cve_refs:
            ET.SubElement(refs_elem, "ref", attrib={"type": "cve", "id": cve})

    sol = ET.SubElement(nvt_elem, "solution", attrib={"type": solution_type})
    sol.text = solution_text

    sev = ET.SubElement(root, "severity")
    sev.text = severity

    qod_elem = ET.SubElement(root, "qod")
    qval = ET.SubElement(qod_elem, "value")
    qval.text = qod_value
    qtyp = ET.SubElement(qod_elem, "type")
    qtyp.text = qod_type

    desc = ET.SubElement(root, "description")
    desc.text = description

    mod = ET.SubElement(root, "modification_time")
    mod.text = modification_time

    return root


def _build_service_detection_result(
    *,
    host: str = "10.0.0.2",
    port: str = "22/tcp",
    product: str = "OpenSSH",
    version: str = "8.9",
) -> ET.Element:
    """Build a result from a Service detection NVT."""
    return _build_result_xml(
        host=host,
        port=port,
        nvt_name=f"{product} Detection",
        nvt_family="Service detection",
        severity="0.0",
        description=f"Detected {product} version: {version} on port {port}",
    )


def _build_product_detection_result(
    *,
    host: str = "10.0.0.3",
    port: str = "80/tcp",
    product: str = "Apache HTTP Server",
    version: str = "2.4.58",
) -> ET.Element:
    """Build a result from a Product detection NVT."""
    return _build_result_xml(
        host=host,
        port=port,
        nvt_name=f"{product} Detection",
        nvt_family="Product detection",
        severity="0.0",
        description=f"Detected product: {product} version: {version}",
    )


# ── XML helper tests ────────────────────────────────────────


class TestXmlHelpers:
    def test_xml_text_found(self):
        elem = _build_result_xml(host="1.2.3.4")
        assert _xml_text(elem, "host") == "1.2.3.4"

    def test_xml_text_missing(self):
        elem = _build_result_xml()
        assert _xml_text(elem, "nonexistent") == ""

    def test_xml_text_none_element(self):
        assert _xml_text(None, "anything") == ""

    def test_xml_float(self):
        elem = _build_result_xml(severity="9.8")
        assert _xml_float(elem, "severity") == 9.8

    def test_xml_float_missing(self):
        elem = _build_result_xml()
        assert _xml_float(elem, "nonexistent") == 0.0

    def test_xml_int(self):
        elem = _build_result_xml(qod_value="75")
        assert _xml_int(elem, "qod/value") == 75

    def test_xml_int_missing(self):
        elem = _build_result_xml()
        assert _xml_int(elem, "nonexistent") == 0


# ── Parsing tests ────────────────────────────────────────────


class TestParsing:
    def test_severity_label_critical(self):
        assert _severity_label(9.8) == "critical"
        assert _severity_label(9.0) == "critical"

    def test_severity_label_high(self):
        assert _severity_label(7.5) == "high"
        assert _severity_label(7.0) == "high"

    def test_severity_label_medium(self):
        assert _severity_label(5.5) == "medium"
        assert _severity_label(4.0) == "medium"

    def test_severity_label_low(self):
        assert _severity_label(2.0) == "low"
        assert _severity_label(0.1) == "low"

    def test_severity_label_log(self):
        assert _severity_label(0.0) == "log"

    def test_parse_port_proto_tcp(self):
        num, proto = _parse_port_proto("443/tcp")
        assert num == 443
        assert proto == "tcp"

    def test_parse_port_proto_udp(self):
        num, proto = _parse_port_proto("53/udp")
        assert num == 53
        assert proto == "udp"

    def test_parse_port_proto_invalid(self):
        num, proto = _parse_port_proto("general/tcp")
        assert num is None
        assert proto is None

    def test_parse_port_proto_empty(self):
        num, proto = _parse_port_proto("")
        assert num is None
        assert proto is None

    def test_parse_iso_datetime(self):
        dt = _parse_iso_datetime("2026-02-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 2

    def test_parse_iso_datetime_empty(self):
        assert _parse_iso_datetime("") is None
        assert _parse_iso_datetime("   ") is None

    def test_extract_cves(self):
        text = "This affects CVE-2024-1234 and CVE-2023-45678."
        cves = _extract_cves(text)
        assert "CVE-2024-1234" in cves
        assert "CVE-2023-45678" in cves

    def test_extract_cves_none(self):
        assert _extract_cves("No vulnerabilities here.") == []


# ── Entity extraction tests ─────────────────────────────────


class TestHostExtraction:
    def test_basic_host(self, resolver):
        elem = _build_result_xml(host="192.168.1.10")
        entity = _extract_host_entity(elem, resolver)
        assert entity is not None
        assert entity.name == "192.168.1.10"
        assert entity.type == "ip_address"
        assert entity.attrs["origin"] == "gvm"
        assert entity.attrs["version"] == "ipv4"

    def test_host_with_hostname(self, resolver):
        elem = _build_result_xml(host="10.0.0.1", hostname="server1.example.com")
        entity = _extract_host_entity(elem, resolver)
        assert entity is not None
        assert entity.attrs["hostname"] == "server1.example.com"
        assert "server1.example.com" in entity.aliases

    def test_host_with_asset_id(self, resolver):
        elem = _build_result_xml(host="10.0.0.1")
        entity = _extract_host_entity(elem, resolver)
        assert entity is not None
        assert "gvm_asset_id" in entity.attrs

    def test_no_host(self, resolver):
        elem = ET.Element("result")
        entity = _extract_host_entity(elem, resolver)
        assert entity is None

    def test_ipv6_host(self, resolver):
        elem = _build_result_xml(host="::1")
        entity = _extract_host_entity(elem, resolver)
        assert entity is not None
        assert entity.attrs["version"] == "ipv6"


class TestPortExtraction:
    def test_basic_port(self, resolver):
        elem = _build_result_xml(port="443/tcp")
        entity = _extract_port_entity(elem, resolver, "10.0.0.1")
        assert entity is not None
        assert entity.type == "port"
        assert entity.attrs["number"] == 443
        assert entity.attrs["protocol"] == "tcp"
        assert entity.attrs["state"] == "open"
        assert entity.attrs["host"] == "10.0.0.1"

    def test_udp_port(self, resolver):
        elem = _build_result_xml(port="161/udp")
        entity = _extract_port_entity(elem, resolver, "10.0.0.1")
        assert entity is not None
        assert entity.attrs["protocol"] == "udp"

    def test_general_port_skipped(self, resolver):
        elem = _build_result_xml(port="general/tcp")
        entity = _extract_port_entity(elem, resolver, "10.0.0.1")
        assert entity is None


class TestVulnerabilityExtraction:
    def test_basic_vulnerability(self, resolver):
        elem = _build_result_xml(
            nvt_name="SSL/TLS: OpenSSL Buffer Overflow (CVE-2024-1234)",
            severity="9.8",
            qod_value="80",
            description="A critical buffer overflow vulnerability.",
        )
        entity = _extract_vulnerability_entity(elem, resolver)
        assert entity is not None
        assert entity.type == "vulnerability"
        assert entity.attrs["cvss"] == 9.8
        assert entity.attrs["severity"] == "critical"
        assert entity.attrs["origin"] == "gvm"
        assert entity.attrs["qod"] == 80

    def test_vulnerability_with_solution(self, resolver):
        elem = _build_result_xml(
            solution_type="VendorFix",
            solution_text="Update to version 2.0.",
        )
        entity = _extract_vulnerability_entity(elem, resolver)
        assert entity is not None
        assert entity.attrs["solution_type"] == "VendorFix"
        assert "Update to version 2.0." in entity.attrs["solution"]

    def test_no_nvt(self, resolver):
        elem = ET.Element("result")
        entity = _extract_vulnerability_entity(elem, resolver)
        assert entity is None


class TestServiceExtraction:
    def test_service_detection(self, resolver):
        elem = _build_service_detection_result(
            host="10.0.0.2",
            port="22/tcp",
            product="OpenSSH",
            version="8.9",
        )
        entity = _extract_service_entity(elem, resolver, "10.0.0.2", 22, "tcp")
        assert entity is not None
        assert entity.type == "service"
        assert entity.attrs["origin"] == "gvm"
        assert entity.attrs["host"] == "10.0.0.2"
        assert entity.attrs["port"] == 22
        assert entity.attrs["version"] == "8.9"

    def test_non_service_family_skipped(self, resolver):
        elem = _build_result_xml(nvt_family="General")
        entity = _extract_service_entity(elem, resolver, "10.0.0.1", 80, "tcp")
        assert entity is None


class TestTechnologyExtraction:
    def test_product_detection(self, resolver):
        elem = _build_product_detection_result(
            host="10.0.0.3",
            product="Apache HTTP Server",
            version="2.4.58",
        )
        entity = _extract_technology_entity(elem, resolver, "10.0.0.3")
        assert entity is not None
        assert entity.type == "technology"
        assert entity.attrs["detected_by"] == "gvm"
        assert entity.attrs["version"] == "2.4.58"

    def test_non_detection_family_skipped(self, resolver):
        elem = _build_result_xml(nvt_family="Web Servers")
        entity = _extract_technology_entity(elem, resolver, "10.0.0.1")
        assert entity is None


class TestCveExtraction:
    def test_cve_from_refs(self, resolver):
        elem = _build_result_xml(
            cve_refs=["CVE-2024-1234", "CVE-2024-5678"],
            severity="8.0",
        )
        entities = _extract_cve_entities(elem, resolver)
        assert len(entities) == 2
        cve_ids = {e.attrs["id"] for e in entities}
        assert "CVE-2024-1234" in cve_ids
        assert "CVE-2024-5678" in cve_ids
        for ent in entities:
            assert ent.type == "cve"
            assert ent.attrs["severity"] == "HIGH"

    def test_cve_from_description(self, resolver):
        elem = _build_result_xml(
            description="Affected by CVE-2023-99999.",
            severity="5.3",
        )
        entities = _extract_cve_entities(elem, resolver)
        assert len(entities) == 1
        assert entities[0].attrs["id"] == "CVE-2023-99999"

    def test_cve_deduplication(self, resolver):
        elem = _build_result_xml(
            cve_refs=["CVE-2024-1234"],
            description="Also affected by CVE-2024-1234.",
        )
        entities = _extract_cve_entities(elem, resolver)
        assert len(entities) == 1

    def test_no_cves(self, resolver):
        elem = _build_result_xml(description="No CVEs.")
        entities = _extract_cve_entities(elem, resolver)
        assert len(entities) == 0


# ── End-to-end result processing ────────────────────────────


class TestProcessResult:
    def test_full_result_creates_entities_and_relations(self, graph_store, resolver):
        elem = _build_result_xml(
            host="192.168.1.100",
            port="443/tcp",
            nvt_name="Apache Log4j RCE",
            nvt_family="Web Servers",
            severity="10.0",
            cve_refs=["CVE-2021-44228"],
            description="Critical Log4Shell vulnerability detected.",
        )
        result = GvmSyncResult()
        _process_result(
            elem, graph_store, resolver, "gvm://localhost", result
        )

        assert result.entities_created > 0
        assert result.relations_created > 0

        # Check host entity was created
        host_entities = [
            e for e in graph_store.entities.values()
            if e.type == "ip_address"
        ]
        assert len(host_entities) >= 1
        assert host_entities[0].name == "192.168.1.100"

        # Check vulnerability entity
        vuln_entities = [
            e for e in graph_store.entities.values()
            if e.type == "vulnerability"
        ]
        assert len(vuln_entities) >= 1
        assert vuln_entities[0].attrs["cvss"] == 10.0

        # Check CVE entity
        cve_entities = [
            e for e in graph_store.entities.values()
            if e.type == "cve"
        ]
        assert len(cve_entities) >= 1
        assert cve_entities[0].attrs["id"] == "CVE-2021-44228"

        # Check port entity
        port_entities = [
            e for e in graph_store.entities.values()
            if e.type == "port"
        ]
        assert len(port_entities) >= 1
        assert port_entities[0].attrs["number"] == 443

    def test_provenance_attached(self, graph_store, resolver):
        elem = _build_result_xml(
            nvt_name="Test Vuln",
            severity="5.0",
        )
        result = GvmSyncResult()
        _process_result(
            elem, graph_store, resolver, "gvm://localhost", result
        )

        # At least one relation should have provenance
        assert len(graph_store.provenance_by_relation) > 0

    def test_result_without_port(self, graph_store, resolver):
        """Results with general/tcp port should still create host + vuln."""
        elem = _build_result_xml(
            host="10.0.0.5",
            port="general/tcp",
            nvt_name="OS Detection",
            severity="0.0",
        )
        result = GvmSyncResult()
        _process_result(
            elem, graph_store, resolver, "gvm://localhost", result
        )

        # Host should still be created
        host_entities = [
            e for e in graph_store.entities.values()
            if e.type == "ip_address"
        ]
        assert len(host_entities) >= 1

    def test_service_detection_entities(self, graph_store, resolver):
        elem = _build_service_detection_result(
            host="10.0.0.10",
            port="22/tcp",
            product="OpenSSH",
            version="9.0",
        )
        result = GvmSyncResult()
        _process_result(
            elem, graph_store, resolver, "gvm://localhost", result
        )

        service_entities = [
            e for e in graph_store.entities.values()
            if e.type == "service"
        ]
        assert len(service_entities) >= 1

        # Should have runs_service relation
        runs_service = [
            r for r in graph_store.relations.values()
            if r.predicate == "runs_service"
        ]
        assert len(runs_service) >= 1

    def test_multiple_cves_create_multiple_relations(self, graph_store, resolver):
        elem = _build_result_xml(
            host="10.0.0.20",
            port="80/tcp",
            nvt_name="Multiple CVE Vuln",
            severity="8.5",
            cve_refs=["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
        )
        result = GvmSyncResult()
        _process_result(
            elem, graph_store, resolver, "gvm://localhost", result
        )

        cve_rels = [
            r for r in graph_store.relations.values()
            if r.predicate == "references_cve"
        ]
        assert len(cve_rels) == 3


# ── Sync function tests (mocked GMP) ───────────────────────


class TestSyncGvm:
    def test_sync_processes_results(self, graph_store, settings):
        results = [
            _build_result_xml(
                result_id="r-001",
                host="10.0.0.1",
                port="443/tcp",
                nvt_name="SSL Weak Cipher",
                severity="5.3",
                cve_refs=["CVE-2024-1111"],
            ),
            _build_result_xml(
                result_id="r-002",
                host="10.0.0.2",
                port="22/tcp",
                nvt_name="SSH Weak Key",
                severity="6.5",
            ),
        ]

        with patch(
            "mimir.connectors.gvm._iter_gvm_results",
            return_value=iter(results),
        ):
            since = datetime.now(timezone.utc) - timedelta(hours=3)
            sync_result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
            )

        assert sync_result.results_processed == 2
        assert sync_result.hosts_seen == 2
        assert sync_result.entities_created > 0
        assert sync_result.relations_created > 0
        assert len(sync_result.errors) == 0

    def test_sync_skips_low_qod(self, graph_store, settings):
        results = [
            _build_result_xml(
                result_id="r-low",
                host="10.0.0.1",
                port="80/tcp",
                nvt_name="Low QoD finding",
                severity="3.0",
                qod_value="10",  # Below gvm_min_qod=30
            ),
        ]

        with patch(
            "mimir.connectors.gvm._iter_gvm_results",
            return_value=iter(results),
        ):
            since = datetime.now(timezone.utc) - timedelta(hours=3)
            sync_result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
            )

        assert sync_result.results_processed == 0
        assert sync_result.skipped_low_qod == 1

    def test_sync_handles_connection_error(self, graph_store, settings):
        with patch(
            "mimir.connectors.gvm._iter_gvm_results",
            side_effect=ConnectionRefusedError("GVM not available"),
        ):
            since = datetime.now(timezone.utc) - timedelta(hours=3)
            sync_result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
            )

        assert sync_result.results_processed == 0
        assert len(sync_result.errors) == 1
        assert "GVM" in sync_result.errors[0]

    def test_sync_empty_results(self, graph_store, settings):
        with patch(
            "mimir.connectors.gvm._iter_gvm_results",
            return_value=iter([]),
        ):
            since = datetime.now(timezone.utc) - timedelta(hours=3)
            sync_result = sync_gvm(
                settings=settings,
                graph_store=graph_store,
                since=since,
            )

        assert sync_result.results_processed == 0
        assert sync_result.hosts_seen == 0
        assert sync_result.entities_created == 0
        assert sync_result.relations_created == 0


# ── Config tests ─────────────────────────────────────────────


class TestGvmConfig:
    def test_default_settings(self):
        s = Settings()
        assert s.gvm_worker_enabled is False
        assert s.gvm_connection_type == "unix"
        assert s.gvm_min_qod == 30
        assert s.gvm_max_results == 500

    def test_gvm_in_source_confidence_rules(self):
        s = Settings()
        rules = s.cti_source_confidence_rules_map
        assert "gvm" in rules
        assert rules["gvm"] == 0.88
