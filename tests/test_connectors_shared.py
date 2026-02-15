"""Tests for mimir.connectors._shared — shared connector helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from mimir.connectors._shared import create_source_es_client


def _settings(**overrides):
    defaults = dict(
        elastic_connector_hosts_list=["http://localhost:9200"],
        elastic_connector_verify_certs=True,
        elastic_connector_timeout_seconds=30,
        elastic_connector_user="",
        elastic_connector_password="",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestCreateSourceEsClient:
    @patch("mimir.connectors._shared.Elasticsearch")
    def test_creates_client_without_auth(self, MockES):
        settings = _settings()
        create_source_es_client(settings)

        MockES.assert_called_once()
        kwargs = MockES.call_args[1]
        assert kwargs["hosts"] == ["http://localhost:9200"]
        assert kwargs["verify_certs"] is True
        assert kwargs["request_timeout"] == 30
        assert "basic_auth" not in kwargs

    @patch("mimir.connectors._shared.Elasticsearch")
    def test_creates_client_with_auth(self, MockES):
        settings = _settings(
            elastic_connector_user="admin",
            elastic_connector_password="secret",
        )
        create_source_es_client(settings)

        kwargs = MockES.call_args[1]
        assert kwargs["basic_auth"] == ("admin", "secret")

    @patch("mimir.connectors._shared.Elasticsearch")
    def test_passes_custom_timeout(self, MockES):
        settings = _settings(elastic_connector_timeout_seconds=120)
        create_source_es_client(settings)

        kwargs = MockES.call_args[1]
        assert kwargs["request_timeout"] == 120

    @patch("mimir.connectors._shared.Elasticsearch")
    def test_multiple_hosts(self, MockES):
        settings = _settings(
            elastic_connector_hosts_list=[
                "http://es1:9200",
                "http://es2:9200",
            ]
        )
        create_source_es_client(settings)

        kwargs = MockES.call_args[1]
        assert kwargs["hosts"] == ["http://es1:9200", "http://es2:9200"]
