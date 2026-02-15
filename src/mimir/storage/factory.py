from __future__ import annotations

from typing import TYPE_CHECKING

from .base import GraphStore
from .elastic_store import ElasticGraphStore, ElasticMetricsStore, ElasticRunStore
from .metrics_store import MetricsStore
from .run_store import RunStore

if TYPE_CHECKING:
    from ..config import Settings


def create_graph_store(settings: "Settings") -> GraphStore:
    return ElasticGraphStore(
        hosts=settings.elastic_hosts_list,
        username=settings.elastic_user,
        password=settings.elastic_password,
        index_prefix=settings.elastic_index_prefix,
        verify_certs=settings.elastic_verify_certs,
    )


def create_run_store(settings: "Settings") -> RunStore:
    return ElasticRunStore(
        hosts=settings.elastic_hosts_list,
        username=settings.elastic_user,
        password=settings.elastic_password,
        index_prefix=settings.elastic_index_prefix,
        verify_certs=settings.elastic_verify_certs,
    )


def create_metrics_store(settings: "Settings") -> MetricsStore:
    return ElasticMetricsStore(
        hosts=settings.elastic_hosts_list,
        username=settings.elastic_user,
        password=settings.elastic_password,
        index_prefix=settings.elastic_index_prefix,
        verify_certs=settings.elastic_verify_certs,
        cti_level_thresholds=settings.cti_level_thresholds_list,
        cti_source_confidence_rules=settings.cti_source_confidence_rules_map,
    )
