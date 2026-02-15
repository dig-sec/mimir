"""Backward-compatibility shim — real implementation lives in ``elastic/``."""
from .elastic import (  # noqa: F401
    ElasticGraphStore,
    ElasticMetricsStore,
    ElasticRunStore,
    _ElasticBase,
    _ElasticIndices,
)
