"""Elasticsearch source client for document connector ingestion."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Optional

from elasticsearch import Elasticsearch


class ElasticsearchSourceClient:
    """Synchronous Elasticsearch client for connector reads."""

    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_certs: bool = True,
        timeout: float = 60.0,
    ) -> None:
        kwargs: Dict[str, Any] = {
            "hosts": hosts,
            "verify_certs": verify_certs,
            "request_timeout": timeout,
        }
        if username:
            kwargs["basic_auth"] = (username, password or "")
        self._client = Elasticsearch(**kwargs)

    def close(self) -> None:
        self._client.close()

    def get_mapping_field_types(self, index: str) -> Dict[str, str]:
        """Return flattened field types for an index mapping."""
        response = self._client.indices.get_mapping(index=index)
        field_types: Dict[str, str] = {}

        for _, data in response.items():
            properties = data.get("mappings", {}).get("properties", {}) or {}
            self._flatten_properties("", properties, field_types)

        return field_types

    @classmethod
    def _flatten_properties(
        cls,
        prefix: str,
        properties: Dict[str, Any],
        output: Dict[str, str],
    ) -> None:
        for field_name, spec in properties.items():
            full_name = f"{prefix}.{field_name}" if prefix else field_name
            field_type = spec.get("type")
            if isinstance(field_type, str):
                output[full_name] = field_type
            nested_props = spec.get("properties")
            if isinstance(nested_props, dict):
                cls._flatten_properties(full_name, nested_props, output)

    def iter_documents(
        self,
        index: str,
        query: Dict[str, Any],
        sort: List[Dict[str, Any]],
        page_size: int = 200,
        max_docs: int = 0,
        source_includes: Optional[List[str]] = None,
        on_page: Optional[Callable[[int], None]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield documents page-by-page using search_after."""
        yielded = 0
        search_after: Optional[List[Any]] = None

        while True:
            request: Dict[str, Any] = {
                "index": index,
                "query": query,
                "sort": sort,
                "size": page_size,
                "track_total_hits": False,
                "seq_no_primary_term": True,
            }
            if source_includes:
                request["source_includes"] = source_includes
            if search_after is not None:
                request["search_after"] = search_after

            response = self._client.search(**request)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                return

            for hit in hits:
                yielded += 1
                yield hit
                if max_docs and yielded >= max_docs:
                    return

            if on_page:
                on_page(yielded)

            search_after = hits[-1].get("sort")
            if not search_after or len(hits) < page_size:
                return
