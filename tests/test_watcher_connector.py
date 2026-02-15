"""Tests for the Watcher (Thales CERT) connector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from mimir.config import Settings
from mimir.connectors.watcher import (
    WatcherSyncResult,
    _det_prov_id,
    _infer_trendy_word_type,
    _iter_api_pages,
    _parse_datetime,
    _process_data_leaks,
    _process_dns_twisted,
    _process_sites,
    _process_trendy_words,
    sync_watcher,
)
from mimir.dedupe import EntityResolver
from mimir.schemas import Entity, Relation

from .in_memory_graph_store import InMemoryGraphStore


# ── Helpers ──────────────────────────────────────────────────


def _make_settings(**overrides: Any) -> Settings:
    """Create Settings with Watcher defaults and optional overrides."""
    defaults = {
        "watcher_worker_enabled": True,
        "watcher_base_url": "http://watcher.local:9002",
        "watcher_api_token": "test-token-123",
        "watcher_verify_tls": False,
        "watcher_timeout_seconds": 10.0,
        "watcher_page_size": 100,
        "watcher_pull_trendy_words": True,
        "watcher_pull_data_leaks": True,
        "watcher_pull_dns_twisted": True,
        "watcher_pull_site_monitoring": True,
        "watcher_min_trendy_score": 0.0,
        "watcher_min_trendy_occurrences": 1,
        "watcher_worker_interval_minutes": 30,
        "watcher_worker_lookback_minutes": 180,
    }
    defaults.update(overrides)
    return Settings(**defaults)


class FakeResponse:
    """Minimal httpx.Response stand-in."""

    def __init__(self, data: Any, status_code: int = 200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError(
                "error", request=MagicMock(), response=MagicMock()
            )

    def json(self) -> Any:
        return self._data


class FakeClient:
    """Minimal httpx.Client stand-in for testing API pagination."""

    def __init__(self, pages: Dict[str, List[Any]]):
        """pages: mapping of path -> list of result pages (each a list of items)."""
        self._pages = pages
        self._page_index: Dict[str, int] = {}

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> FakeResponse:
        params = params or {}
        page = params.get("page", 1)
        pages = self._pages.get(path, [])
        idx = page - 1
        if idx < 0 or idx >= len(pages):
            return FakeResponse({"count": 0, "next": None, "results": []})
        items = pages[idx]
        has_next = idx + 1 < len(pages)
        return FakeResponse(
            {
                "count": sum(len(p) for p in pages),
                "next": f"http://test/api?page={page + 1}" if has_next else None,
                "results": items,
            }
        )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ── Unit tests: parsing helpers ──────────────────────────────


class TestParseHelpers:
    def test_parse_datetime_iso(self):
        dt = _parse_datetime("2025-05-11T10:20:42Z")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 5
        assert dt.tzinfo is not None

    def test_parse_datetime_iso_with_offset(self):
        dt = _parse_datetime("2025-05-11T10:20:42+02:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_parse_datetime_empty(self):
        assert _parse_datetime("") is None
        assert _parse_datetime(None) is None

    def test_parse_datetime_invalid(self):
        assert _parse_datetime("not a date") is None

    def test_parse_datetime_object(self):
        now = datetime.now(timezone.utc)
        assert _parse_datetime(now) == now

    def test_parse_datetime_naive(self):
        dt = _parse_datetime("2025-01-15T12:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc


class TestInferTrendyWordType:
    def test_cve(self):
        assert _infer_trendy_word_type("CVE-2025-59287") == "vulnerability"
        assert _infer_trendy_word_type("cve-2024-1234") == "vulnerability"

    def test_apt(self):
        assert _infer_trendy_word_type("APT28") == "threat_actor"
        assert _infer_trendy_word_type("APT-29") == "threat_actor"
        assert _infer_trendy_word_type("apt 41") == "threat_actor"

    def test_known_threat_actor(self):
        assert _infer_trendy_word_type("Lazarus") == "threat_actor"
        assert _infer_trendy_word_type("Volt Typhoon") == "threat_actor"
        assert _infer_trendy_word_type("Midnight Blizzard") == "threat_actor"

    def test_malware(self):
        assert _infer_trendy_word_type("LockBit") == "malware"
        assert _infer_trendy_word_type("Emotet") == "malware"
        assert _infer_trendy_word_type("Ransomware") == "malware"

    def test_generic_word(self):
        assert _infer_trendy_word_type("Nvidia") == "trendy_word"
        assert _infer_trendy_word_type("Microsoft") == "trendy_word"
        assert _infer_trendy_word_type("Atlas") == "trendy_word"

    def test_case_insensitive(self):
        assert _infer_trendy_word_type("LOCKBIT") == "malware"
        assert _infer_trendy_word_type("lazarus") == "threat_actor"


class TestDetProvId:
    def test_deterministic(self):
        args = {
            "source_uri": "watcher://test",
            "relation_id": "rel-1",
            "model": "watcher-connector",
            "chunk_id": "chunk-1",
            "snippet": "test snippet",
        }
        id1 = _det_prov_id(**args)
        id2 = _det_prov_id(**args)
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        base = {
            "source_uri": "watcher://test",
            "relation_id": "rel-1",
            "model": "watcher-connector",
            "chunk_id": "chunk-1",
            "snippet": "snippet A",
        }
        id1 = _det_prov_id(**base)
        base["snippet"] = "snippet B"
        id2 = _det_prov_id(**base)
        assert id1 != id2


# ── Unit tests: API pagination ───────────────────────────────


class TestApiPagination:
    def test_single_page(self):
        client = FakeClient(
            {"/api/test/": [[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]]}
        )
        items = list(_iter_api_pages(client, "/api/test/"))
        assert len(items) == 2
        assert items[0]["id"] == 1

    def test_multi_page(self):
        client = FakeClient(
            {"/api/test/": [[{"id": 1}], [{"id": 2}], [{"id": 3}]]}
        )
        items = list(_iter_api_pages(client, "/api/test/"))
        assert len(items) == 3

    def test_empty_response(self):
        client = FakeClient({"/api/test/": [[]]})
        items = list(_iter_api_pages(client, "/api/test/"))
        assert len(items) == 0

    def test_missing_path(self):
        client = FakeClient({})
        items = list(_iter_api_pages(client, "/api/nonexistent/"))
        assert len(items) == 0

    def test_since_filter(self):
        since = datetime(2025, 5, 11, 10, 0, 0, tzinfo=timezone.utc)
        client = FakeClient(
            {
                "/api/test/": [
                    [
                        {"id": 1, "created_at": "2025-05-11T09:00:00Z"},  # before
                        {"id": 2, "created_at": "2025-05-11T11:00:00Z"},  # after
                        {"id": 3, "created_at": "2025-05-12T00:00:00Z"},  # after
                    ]
                ]
            }
        )
        items = list(_iter_api_pages(client, "/api/test/", since=since))
        assert len(items) == 2
        assert items[0]["id"] == 2

    def test_non_paginated_list(self):
        """Handle raw JSON list (non-DRF paginated) responses."""
        client = MagicMock()
        client.get.return_value = FakeResponse([{"id": 1}, {"id": 2}])
        items = list(_iter_api_pages(client, "/api/test/"))
        assert len(items) == 2


# ── Integration tests: trendy words ─────────────────────────


class TestTrendyWords:
    def test_basic_trendy_word(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 1,
                            "name": "Nvidia",
                            "occurrences": 11,
                            "score": 65.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:20:42Z",
                        }
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.trendy_words_processed == 1
        assert result.entities_created == 1
        ent = list(store.entities.values())[0]
        assert ent.type == "trendy_word"
        assert ent.attrs["occurrences"] == 11
        assert ent.attrs["reliability_score"] == 65.0

    def test_cve_trendy_word_inferred_as_vulnerability(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 4,
                            "name": "CVE-2025-59287",
                            "occurrences": 25,
                            "score": 80.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:18:58Z",
                        }
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.trendy_words_processed == 1
        ent = list(store.entities.values())[0]
        assert ent.type == "vulnerability"

    def test_min_score_filter(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings(watcher_min_trendy_score=70.0)
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 1,
                            "name": "Nvidia",
                            "occurrences": 11,
                            "score": 65.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:20:42Z",
                        },
                        {
                            "id": 5,
                            "name": "Atlas",
                            "occurrences": 55,
                            "score": 100.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:18:37Z",
                        },
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.trendy_words_processed == 1  # Only Atlas
        assert result.skipped_low_score == 1

    def test_min_occurrences_filter(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings(watcher_min_trendy_occurrences=10)
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 3,
                            "name": "Dante",
                            "occurrences": 5,
                            "score": 71.7,
                            "posturls": [],
                            "created_at": "2025-05-11T10:19:25Z",
                        }
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.trendy_words_processed == 0
        assert result.skipped_low_occurrences == 1

    def test_posturls_string_format(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 1,
                            "name": "TestWord",
                            "occurrences": 3,
                            "score": 50.0,
                            "posturls": [
                                "https://cert.example.com/alert1,2025-05-11T10:00:00Z",
                                "https://cert.example.com/alert2,2025-05-11T11:00:00Z",
                            ],
                            "created_at": "2025-05-11T10:20:42Z",
                        }
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        ent = list(store.entities.values())[0]
        assert "source_urls" in ent.attrs
        assert len(ent.attrs["source_urls"]) == 2
        assert ent.attrs["source_urls"][0] == "https://cert.example.com/alert1"

    def test_threat_actor_inference(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 10,
                            "name": "Lazarus",
                            "occurrences": 8,
                            "score": 90.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_trendy_words(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        ent = list(store.entities.values())[0]
        assert ent.type == "threat_actor"


# ── Integration tests: data leaks ───────────────────────────


class TestDataLeaks:
    def test_basic_data_leak(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/data_leak/alert/": [
                    [
                        {
                            "id": 42,
                            "keyword": {"id": 1, "name": "api_key_corp"},
                            "url": "https://pastebin.com/raw/abc123",
                            "content": "Found API key: sk-...",
                            "status": True,
                            "created_at": "2025-05-10T08:30:00Z",
                        }
                    ]
                ]
            }
        )

        _process_data_leaks(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.data_leaks_processed == 1
        assert result.entities_created == 2  # alert + keyword
        assert result.relations_created == 1

        # Find the alert entity
        alert = next(
            e for e in store.entities.values() if e.type == "data_leak_alert"
        )
        assert alert.attrs["url"] == "https://pastebin.com/raw/abc123"
        assert alert.attrs["status"] == "active"

        # Find the keyword entity
        kw = next(
            e for e in store.entities.values() if e.type == "data_leak_keyword"
        )
        assert "api_key_corp" in kw.name

        # Verify relation + provenance
        assert len(store.relations) == 1
        rel = list(store.relations.values())[0]
        assert rel.predicate == "matches_keyword"
        assert len(store.provenance_by_relation) == 1

    def test_leak_without_keyword(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/data_leak/alert/": [
                    [
                        {
                            "id": 43,
                            "keyword": {},
                            "url": "https://github.com/leaked/repo",
                            "content": "credentials found",
                            "status": False,
                            "created_at": "2025-05-10T09:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_data_leaks(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.data_leaks_processed == 1
        assert result.entities_created == 1  # Only alert, no keyword
        assert result.relations_created == 0


# ── Integration tests: DNS twisted ──────────────────────────


class TestDnsTwisted:
    def test_basic_twisted_domain(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/dns_finder/dns_twisted/": [
                    [
                        {
                            "id": 100,
                            "domain_name": "examp1e.com",
                            "dns_monitored": {
                                "id": 1,
                                "domain_name": "example.com",
                            },
                            "keyword_monitored": None,
                            "fuzzer": "homoglyph",
                            "created_at": "2025-05-10T14:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_dns_twisted(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.dns_twisted_processed == 1
        assert result.entities_created == 2  # twisted + monitored
        assert result.relations_created == 1

        twisted = next(
            e for e in store.entities.values() if e.type == "twisted_domain"
        )
        assert twisted.attrs["fuzzer"] == "homoglyph"

        monitored = next(
            e for e in store.entities.values() if e.type == "monitored_domain"
        )
        assert "example.com" in monitored.name

        rel = list(store.relations.values())[0]
        assert rel.predicate == "impersonates"

    def test_twisted_with_keyword_monitored(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/dns_finder/dns_twisted/": [
                    [
                        {
                            "id": 101,
                            "domain_name": "mycorp-login.com",
                            "dns_monitored": None,
                            "keyword_monitored": {
                                "id": 5,
                                "name": "mycorp",
                            },
                            "fuzzer": "",
                            "created_at": "2025-05-10T15:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_dns_twisted(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.dns_twisted_processed == 1
        assert result.entities_created == 2  # twisted + keyword

        kw = next(e for e in store.entities.values() if e.type == "indicator")
        assert kw.attrs["detection_method"] == "certstream"

        rel = list(store.relations.values())[0]
        assert rel.predicate == "detected_by_keyword"

    def test_twisted_domain_only(self):
        """Twisted domain without monitored domain or keyword."""
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/dns_finder/dns_twisted/": [
                    [
                        {
                            "id": 102,
                            "domain_name": "phishing-site.tk",
                            "dns_monitored": None,
                            "keyword_monitored": None,
                            "fuzzer": "typo",
                            "created_at": "2025-05-10T16:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_dns_twisted(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.dns_twisted_processed == 1
        assert result.entities_created == 1
        assert result.relations_created == 0


# ── Integration tests: site monitoring ──────────────────────


class TestSiteMonitoring:
    def test_basic_site(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/site_monitoring/site/": [
                    [
                        {
                            "id": 200,
                            "domain_name": "suspicious-site.com",
                            "ip": "93.184.216.34",
                            "ip_second": None,
                            "web_status": 200,
                            "registrar": "Namecheap Inc",
                            "legitimacy": 3,
                            "monitored": True,
                            "takedown_request": False,
                            "legal_team": False,
                            "blocking_request": False,
                            "content_fuzzy_hash": "T1abc123",
                            "domain_expiry": "2026-01-15",
                            "mail_A_record_ip": None,
                            "MX_records": ["mx1.example.com", "mx2.example.com"],
                            "created_at": "2025-05-09T12:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_sites(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.sites_processed == 1
        assert result.entities_created == 2  # site + IP
        assert result.relations_created == 1

        site = next(
            e for e in store.entities.values() if e.type == "monitored_site"
        )
        assert site.attrs["http_status"] == 200
        assert site.attrs["registrar"] == "Namecheap Inc"
        assert site.attrs["legitimacy"] == "suspicious"
        assert site.attrs["content_fuzzy_hash"] == "T1abc123"
        assert site.attrs["mx_records"] == ["mx1.example.com", "mx2.example.com"]

        ip = next(
            e for e in store.entities.values() if e.type == "ip_address"
        )
        assert ip.name == "93.184.216.34"

        rel = list(store.relations.values())[0]
        assert rel.predicate == "resolves_to"

    def test_site_with_two_ips_and_mail(self):
        store = InMemoryGraphStore()
        resolver = EntityResolver(store)
        result = WatcherSyncResult()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        client = FakeClient(
            {
                "/api/site_monitoring/site/": [
                    [
                        {
                            "id": 201,
                            "domain_name": "bad-clone.com",
                            "ip": "10.0.0.1",
                            "ip_second": "10.0.0.2",
                            "web_status": 403,
                            "registrar": None,
                            "legitimacy": 4,
                            "monitored": True,
                            "takedown_request": True,
                            "legal_team": True,
                            "blocking_request": False,
                            "content_fuzzy_hash": None,
                            "domain_expiry": None,
                            "mail_A_record_ip": "10.0.0.3",
                            "MX_records": [],
                            "created_at": "2025-05-09T13:00:00Z",
                        }
                    ]
                ]
            }
        )

        _process_sites(
            client, store, resolver, settings, since,
            "watcher://test", result,
        )

        assert result.sites_processed == 1
        # site + ip + ip_second + mail_ip = 4 entities
        assert result.entities_created == 4
        # resolves_to x2 + mail_resolves_to = 3 relations
        assert result.relations_created == 3

        site = next(
            e for e in store.entities.values() if e.type == "monitored_site"
        )
        assert site.attrs["legitimacy"] == "malicious_online"
        assert site.attrs["takedown_request"] is True

    def test_site_malicious_legitimacy_codes(self):
        """Verify all legitimacy codes map correctly."""
        from mimir.connectors.watcher import _LEGITIMACY_MAP

        assert _LEGITIMACY_MAP[1] == "unknown"
        assert _LEGITIMACY_MAP[2] == "legitimate"
        assert _LEGITIMACY_MAP[3] == "suspicious"
        assert _LEGITIMACY_MAP[4] == "malicious_online"
        assert _LEGITIMACY_MAP[5] == "malicious_down"
        assert _LEGITIMACY_MAP[6] == "malicious_disabled"


# ── Integration tests: full sync ────────────────────────────


class TestSyncWatcher:
    @patch("mimir.connectors.watcher._create_client")
    def test_full_sync_all_modules(self, mock_create_client):
        """End-to-end sync hitting all four modules."""
        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 1,
                            "name": "CVE-2025-59287",
                            "occurrences": 25,
                            "score": 80.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:18:58Z",
                        }
                    ]
                ],
                "/api/data_leak/alert/": [
                    [
                        {
                            "id": 42,
                            "keyword": {"id": 1, "name": "secret_key"},
                            "url": "https://pastebin.com/raw/xyz",
                            "content": "leaked data",
                            "status": True,
                            "created_at": "2025-05-10T08:00:00Z",
                        }
                    ]
                ],
                "/api/dns_finder/dns_twisted/": [
                    [
                        {
                            "id": 100,
                            "domain_name": "g00gle.com",
                            "dns_monitored": {
                                "id": 1,
                                "domain_name": "google.com",
                            },
                            "keyword_monitored": None,
                            "fuzzer": "homoglyph",
                            "created_at": "2025-05-10T14:00:00Z",
                        }
                    ]
                ],
                "/api/site_monitoring/site/": [
                    [
                        {
                            "id": 200,
                            "domain_name": "evil-site.ru",
                            "ip": "192.168.1.1",
                            "ip_second": None,
                            "web_status": 200,
                            "registrar": "ShadyReg",
                            "legitimacy": 6,
                            "monitored": True,
                            "takedown_request": False,
                            "legal_team": False,
                            "blocking_request": False,
                            "content_fuzzy_hash": None,
                            "domain_expiry": None,
                            "mail_A_record_ip": None,
                            "MX_records": [],
                            "created_at": "2025-05-09T12:00:00Z",
                        }
                    ]
                ],
            }
        )
        mock_create_client.return_value = client

        store = InMemoryGraphStore()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        result = sync_watcher(
            settings=settings,
            graph_store=store,
            since=since,
        )

        assert result.trendy_words_processed == 1
        assert result.data_leaks_processed == 1
        assert result.dns_twisted_processed == 1
        assert result.sites_processed == 1
        assert result.entities_created > 0
        assert result.relations_created > 0
        assert len(result.errors) == 0

    @patch("mimir.connectors.watcher._create_client")
    def test_sync_selective_modules(self, mock_create_client):
        """Only trendy words enabled."""
        client = FakeClient(
            {
                "/api/threats_watcher/trendyword/": [
                    [
                        {
                            "id": 1,
                            "name": "TestWord",
                            "occurrences": 5,
                            "score": 50.0,
                            "posturls": [],
                            "created_at": "2025-05-11T10:00:00Z",
                        }
                    ]
                ],
            }
        )
        mock_create_client.return_value = client

        store = InMemoryGraphStore()
        settings = _make_settings(
            watcher_pull_data_leaks=False,
            watcher_pull_dns_twisted=False,
            watcher_pull_site_monitoring=False,
        )
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        result = sync_watcher(settings=settings, graph_store=store, since=since)

        assert result.trendy_words_processed == 1
        assert result.data_leaks_processed == 0
        assert result.dns_twisted_processed == 0
        assert result.sites_processed == 0

    @patch("mimir.connectors.watcher._create_client")
    def test_sync_handles_api_error(self, mock_create_client):
        """Sync continues even if one module fails."""
        mock_create_client.side_effect = Exception("Connection refused")

        store = InMemoryGraphStore()
        settings = _make_settings()
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)

        result = sync_watcher(settings=settings, graph_store=store, since=since)

        assert len(result.errors) == 1
        assert "Connection refused" in result.errors[0]


# ── Config tests ─────────────────────────────────────────────


class TestWatcherConfig:
    def test_default_settings(self):
        settings = Settings()
        assert settings.watcher_worker_enabled is False
        assert settings.watcher_base_url == "http://127.0.0.1:9002"
        assert settings.watcher_page_size == 200
        assert settings.watcher_pull_trendy_words is True
        assert settings.watcher_pull_dns_twisted is True
        assert settings.watcher_min_trendy_score == 0.0
        assert settings.watcher_min_trendy_occurrences == 1

    def test_watcher_in_source_confidence_rules(self):
        settings = Settings()
        rules = settings.cti_source_confidence_rules_map
        assert "watcher" in rules
        assert rules["watcher"] == 0.80
