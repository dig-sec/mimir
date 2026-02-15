from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    TypeVar,
)
from uuid import UUID, uuid5

from elasticsearch import ApiError, ConflictError
from elasticsearch import ConnectionError as ESConnectionError
from elasticsearch import ConnectionTimeout, Elasticsearch, NotFoundError

from ...normalize import canonical_entity_key

logger = logging.getLogger(__name__)

# Namespace UUID for deterministic entity/relation IDs
_NS_ENTITY = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
_NS_RELATION = UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")

T = TypeVar("T")
_COMPACT_RE = re.compile(r"[^a-z0-9]+")


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not value:
        return datetime.utcnow()
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _normalize_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat()
    return value.astimezone(timezone.utc).isoformat()


def _merge_attrs(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if (
            key in merged
            and isinstance(merged[key], (int, float))
            and isinstance(value, (int, float))
        ):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


def _compact_text(value: str) -> str:
    return _COMPACT_RE.sub("", str(value or "").lower())


def _entity_keys(
    name: str, entity_type: Optional[str], aliases: List[str]
) -> List[str]:
    keys = {canonical_entity_key(name, entity_type)}
    for alias in aliases:
        keys.add(canonical_entity_key(alias, entity_type))
    return sorted(k for k in keys if k)


def _deterministic_entity_id(canonical_key: str) -> str:
    """Generate a stable UUID from a canonical entity key.

    Same (name, type) always produces the same ID, so re-ingesting
    the same entity is an update rather than a duplicate insert.
    """
    return str(uuid5(_NS_ENTITY, canonical_key))


def _triple_key(subject_id: str, predicate: str, object_id: str) -> str:
    return f"{subject_id}|{predicate}|{object_id}"


def _deterministic_relation_id(triple_key: str) -> str:
    """Stable UUID from a triple key so relations are idempotent."""
    return str(uuid5(_NS_RELATION, triple_key))


def _create_client(
    hosts: List[str],
    username: Optional[str],
    password: Optional[str],
    verify_certs: bool,
) -> Elasticsearch:
    kwargs: Dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": verify_certs,
        "request_timeout": 60,  # Increased from 30 to 60 for bulk ops
    }
    if username:
        kwargs["basic_auth"] = (username, password or "")
    return Elasticsearch(**kwargs)


def _retry_with_backoff(
    func: Callable[..., T],
    *args,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    **kwargs,
) -> T:
    """Retry a function with exponential backoff for transient ES errors.

    Retries on:
    - ApiError with status 429 (too many requests) or 503 (service unavailable)
    - ConnectionError or timeout

    Raises immediately on:
    - NotFoundError
    - ConflictError
    - Other exceptions
    """
    delay = initial_delay
    last_exception: Optional[Exception] = None

    for attempt in range(max(max_attempts, 1)):
        try:
            return func(*args, **kwargs)
        except (NotFoundError, ConflictError):
            # Don't retry these
            raise
        except ApiError as exc:
            # Only retry on transient errors
            if exc.status_code not in (429, 503):
                raise
            last_exception = exc
            if attempt < max_attempts - 1:
                logger.debug(
                    "ES request failed with %d (attempt %d/%d), retrying in %.1fs",
                    exc.status_code,
                    attempt + 1,
                    max_attempts,
                    delay,
                )
                import time

                time.sleep(delay)
                delay *= 2  # Exponential backoff
        except (ESConnectionError, ConnectionTimeout, OSError) as exc:
            # Retry on connection/timeout errors only
            last_exception = exc
            if attempt < max_attempts - 1:
                logger.debug(
                    "ES request failed with %s (attempt %d/%d), retrying in %.1fs",
                    type(exc).__name__,
                    attempt + 1,
                    max_attempts,
                    delay,
                )
                import time

                time.sleep(delay)
                delay *= 2

    # All retries exhausted
    if last_exception:
        raise last_exception
    raise RuntimeError(f"Failed after {max_attempts} attempts")


class _ElasticIndices:
    def __init__(self, prefix: str) -> None:
        self.entities = f"{prefix}-entities"
        self.relations = f"{prefix}-relations"
        self.provenance = f"{prefix}-provenance"
        self.relation_provenance = f"{prefix}-relation-provenance"
        self.metrics = f"{prefix}-metrics"
        self.runs = f"{prefix}-runs"
        self.documents = f"{prefix}-documents"
        self.chunks = f"{prefix}-chunks"


class _ElasticBase:
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str],
        password: Optional[str],
        index_prefix: str,
        verify_certs: bool,
    ) -> None:
        if not hosts:
            raise ValueError("At least one Elasticsearch host is required")
        self.client = _create_client(hosts, username, password, verify_certs)
        self.indices = _ElasticIndices(index_prefix)

    def _ensure_index(self, name: str, properties: Dict[str, Any]) -> None:
        if self.client.indices.exists(index=name):
            return
        try:
            self.client.indices.create(
                index=name,
                mappings={"properties": properties},
            )
        except ApiError as exc:
            err = getattr(exc, "error", None)
            if (
                err == "resource_already_exists_exception"
                or "resource_already_exists_exception" in str(exc)
            ):
                return
            raise

    def _iter_search_hits(
        self,
        index: str,
        query: Dict[str, Any],
        sort: List[Dict[str, Any]],
        size: int = 500,
    ) -> Iterator[Dict[str, Any]]:
        normalized_sort: List[Dict[str, Any]] = []
        has_shard_doc = False
        for sort_item in sort:
            if not isinstance(sort_item, dict) or not sort_item:
                continue
            field, spec = next(iter(sort_item.items()))
            if field == "_id":
                field = "_shard_doc"
                spec = "asc"
            if field == "_shard_doc":
                has_shard_doc = True
            normalized_sort.append({field: spec})
        if not normalized_sort:
            normalized_sort = [{"_shard_doc": "asc"}]
            has_shard_doc = True
        if not has_shard_doc:
            normalized_sort.append({"_shard_doc": "asc"})

        search_after: Optional[List[Any]] = None
        while True:
            params: Dict[str, Any] = {
                "index": index,
                "query": query,
                "sort": normalized_sort,
                "size": size,
            }
            if search_after:
                params["search_after"] = search_after
            response = self.client.search(**params)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                yield hit
            if len(hits) < size:
                return
            search_after = hits[-1].get("sort")
            if not search_after:
                return
