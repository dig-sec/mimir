"""Shared helpers used by multiple connectors.

Provides the common Elasticsearch source client factory that was
previously duplicated in ``connectors/__init__`` (Feedly) and
``connectors/malware``.
"""

from __future__ import annotations

from typing import Any, Dict

from elasticsearch import Elasticsearch

from ..config import Settings


def create_source_es_client(settings: Settings) -> Elasticsearch:
    """Build an Elasticsearch client for connector source indices.

    Uses the ``elastic_connector_*`` settings (hosts, user, password,
    verify_certs, timeout).
    """
    hosts = settings.elastic_connector_hosts_list
    kwargs: Dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": settings.elastic_connector_verify_certs,
        "request_timeout": settings.elastic_connector_timeout_seconds,
    }
    if settings.elastic_connector_user:
        kwargs["basic_auth"] = (
            settings.elastic_connector_user,
            settings.elastic_connector_password,
        )
    return Elasticsearch(**kwargs)
