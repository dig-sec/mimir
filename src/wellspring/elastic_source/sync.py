"""Sync documents from Elasticsearch source indices into run queue."""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..config import Settings
from ..schemas import ExtractionRun
from ..storage.run_store import RunStore
from .client import ElasticsearchSourceClient

_DATE_FIELD_TYPES = {"date", "date_nanos"}
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\f\v]+")
_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")
_SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([,.;:!?])")


@dataclass
class ElasticSyncResult:
    indexes_scanned: int = 0
    documents_seen: int = 0
    runs_queued: int = 0
    skipped_existing: int = 0
    skipped_empty: int = 0
    errors: List[str] = field(default_factory=list)


def _get_nested(source: Dict[str, Any], field_path: str) -> Any:
    current: Any = source
    for part in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts = [_coerce_text(item) for item in value]
        return "\n".join([part for part in parts if part]).strip()
    if isinstance(value, dict):
        for key in ("text", "content", "value", "body", "summary", "title"):
            text = _coerce_text(value.get(key))
            if text:
                return text
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def _normalize_text(
    text: str,
    *,
    strip_html: bool,
    normalize_whitespace: bool,
) -> str:
    if not text:
        return ""

    out = html.unescape(text)
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    if strip_html and "<" in out and ">" in out:
        out = _TAG_RE.sub(" ", out)
    if normalize_whitespace:
        lines = []
        for line in out.split("\n"):
            compact = _WS_RE.sub(" ", line).strip()
            compact = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", compact)
            if compact:
                lines.append(compact)
            else:
                lines.append("")
        out = "\n".join(lines)
        out = _MULTI_NEWLINE_RE.sub("\n\n", out)
    return out.strip()


def _first_non_empty_text(source: Dict[str, Any], field_paths: Iterable[str]) -> str:
    for field_path in field_paths:
        text = _coerce_text(_get_nested(source, field_path))
        if text:
            return text
    return ""


def _collect_texts(source: Dict[str, Any], field_paths: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    items: List[str] = []
    for field_path in field_paths:
        text = _coerce_text(_get_nested(source, field_path))
        if text and text not in seen:
            seen.add(text)
            items.append(text)
    return items


def _build_document_text(
    source: Dict[str, Any],
    title_fields: List[str],
    text_fields: List[str],
    *,
    strip_html: bool,
    normalize_whitespace: bool,
) -> Tuple[str, str]:
    title = _normalize_text(
        _first_non_empty_text(source, title_fields),
        strip_html=strip_html,
        normalize_whitespace=normalize_whitespace,
    )
    body_parts = _collect_texts(source, text_fields)
    aligned_parts = [
        _normalize_text(
            part,
            strip_html=strip_html,
            normalize_whitespace=normalize_whitespace,
        )
        for part in body_parts
    ]
    aligned_parts = [part for part in aligned_parts if part]
    if title:
        aligned_parts = [part for part in aligned_parts if part != title]

    text_parts: List[str] = []
    if title:
        text_parts.append(title)
    if aligned_parts:
        text_parts.append("\n\n".join(aligned_parts))

    if not text_parts:
        fallback = []
        for key, value in source.items():
            if isinstance(value, str) and value.strip():
                cleaned = _normalize_text(
                    value,
                    strip_html=strip_html,
                    normalize_whitespace=normalize_whitespace,
                )
                if cleaned:
                    fallback.append(f"{key}: {cleaned}")
        if fallback:
            text_parts.append("\n".join(fallback[:20]))

    return title, "\n\n".join(text_parts).strip()


def _select_timestamp_field(
    field_types: Dict[str, str], candidates: List[str]
) -> Optional[str]:
    first_existing: Optional[str] = None
    for candidate in candidates:
        field_type = field_types.get(candidate)
        if field_type in _DATE_FIELD_TYPES:
            return candidate
        if field_type and first_existing is None:
            first_existing = candidate
    if first_existing:
        return first_existing
    for candidate in candidates:
        if candidate:
            return candidate
    return None


def _select_existing_fields(
    field_types: Dict[str, str], candidates: List[str]
) -> List[str]:
    return [candidate for candidate in candidates if candidate in field_types]


def _build_version_token(
    hit: Dict[str, Any],
    timestamp_value: Optional[Any],
    text: str,
) -> str:
    seq_no = hit.get("_seq_no")
    primary_term = hit.get("_primary_term")
    parts: List[str] = []
    if timestamp_value not in (None, ""):
        parts.append(f"ts:{timestamp_value}")
    if seq_no is not None and primary_term is not None:
        parts.append(f"seq:{seq_no}:{primary_term}")
    if parts:
        return "|".join(parts)

    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
    return f"text:{digest}"


def _build_run_id(index: str, doc_id: str, version_token: str) -> str:
    digest = hashlib.sha1(
        f"{index}|{doc_id}|{version_token}".encode("utf-8")
    ).hexdigest()
    return f"es-{digest}"


def _align_document(
    source: Dict[str, Any],
    *,
    title_fields: List[str],
    text_fields: List[str],
    url_fields: List[str],
    timestamp_field: Optional[str],
    strip_html: bool,
    normalize_whitespace: bool,
) -> Dict[str, Any]:
    title, text = _build_document_text(
        source,
        title_fields,
        text_fields,
        strip_html=strip_html,
        normalize_whitespace=normalize_whitespace,
    )
    url = _normalize_text(
        _first_non_empty_text(source, url_fields),
        strip_html=False,
        normalize_whitespace=True,
    )
    timestamp_value = _get_nested(source, timestamp_field) if timestamp_field else None
    return {
        "title": title,
        "text": text,
        "url": url,
        "timestamp_value": timestamp_value,
    }


def pull_from_elasticsearch(
    elastic: ElasticsearchSourceClient,
    run_store: RunStore,
    settings: Settings,
    indices: List[str],
    max_per_index: int = 500,
    lookback_minutes: int = 180,
    min_text_chars: int = 50,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> ElasticSyncResult:
    """Fetch source docs from Elasticsearch indices and queue extraction runs."""
    result = ElasticSyncResult()

    def _progress(message: str) -> None:
        if progress_cb:
            progress_cb(message)

    total_indexes = len(indices)
    for index_number, index_name in enumerate(indices, start=1):
        _progress(f"[{index_number}/{total_indexes}] Reading index {index_name}...")

        try:
            field_types = elastic.get_mapping_field_types(index_name)
        except Exception as exc:
            result.errors.append(f"{index_name}: mapping error: {exc}")
            continue

        title_fields = _select_existing_fields(
            field_types, settings.elastic_connector_title_fields_list
        )
        text_fields = _select_existing_fields(
            field_types, settings.elastic_connector_text_fields_list
        )
        url_fields = _select_existing_fields(
            field_types, settings.elastic_connector_url_fields_list
        )
        timestamp_field = _select_timestamp_field(
            field_types,
            settings.elastic_connector_timestamp_fields_list,
        )

        query: Dict[str, Any] = {"match_all": {}}
        sort: List[Dict[str, Any]] = [{"_shard_doc": "desc"}]

        if timestamp_field:
            sort = [
                {timestamp_field: {"order": "desc", "missing": "_last"}},
                {"_shard_doc": "desc"},
            ]
            if lookback_minutes > 0:
                since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
                query = {"range": {timestamp_field: {"gte": since.isoformat()}}}

        source_includes: Optional[List[str]] = None
        content_fields = [*title_fields, *text_fields, *url_fields]
        if content_fields:
            source_includes = list(
                dict.fromkeys(
                    [
                        *content_fields,
                        *([timestamp_field] if timestamp_field else []),
                    ]
                )
            )

        per_index_seen = 0
        per_index_queued = 0

        try:
            for hit in elastic.iter_documents(
                index=index_name,
                query=query,
                sort=sort,
                page_size=settings.elastic_connector_page_size,
                max_docs=max_per_index,
                source_includes=source_includes,
                on_page=lambda n: _progress(
                    f"[{index_number}/{total_indexes}] {index_name}: scanned {n}, queued {per_index_queued}"
                ),
            ):
                per_index_seen += 1
                result.documents_seen += 1

                source = hit.get("_source") or {}
                doc_id = str(hit.get("_id", "unknown"))

                try:
                    aligned = _align_document(
                        source,
                        title_fields=title_fields,
                        text_fields=text_fields,
                        url_fields=url_fields,
                        timestamp_field=timestamp_field,
                        strip_html=settings.elastic_connector_strip_html,
                        normalize_whitespace=settings.elastic_connector_normalize_whitespace,
                    )
                    title = aligned["title"]
                    text = aligned["text"]
                    if len(text.strip()) < min_text_chars:
                        result.skipped_empty += 1
                        continue

                    timestamp_value = aligned["timestamp_value"]
                    version_token = _build_version_token(hit, timestamp_value, text)
                    run_id = _build_run_id(index_name, doc_id, version_token)

                    if run_store.get_run(run_id):
                        result.skipped_existing += 1
                        continue

                    run = ExtractionRun(
                        run_id=run_id,
                        started_at=datetime.utcnow(),
                        model=settings.ollama_model,
                        prompt_version=settings.prompt_version,
                        params={
                            "chunk_size": settings.chunk_size,
                            "chunk_overlap": settings.chunk_overlap,
                            "connector": "elasticsearch",
                            "source_index": index_name,
                        },
                        status="pending",
                        error=None,
                    )

                    source_uri = f"elasticsearch://{index_name}/{doc_id}"
                    metadata: Dict[str, Any] = {
                        "connector": "elasticsearch",
                        "index": index_name,
                        "document_id": doc_id,
                    }
                    if title:
                        metadata["title"] = title
                    if timestamp_field:
                        metadata["timestamp_field"] = timestamp_field
                    if timestamp_value is not None:
                        metadata["timestamp_value"] = timestamp_value
                    url = aligned["url"]
                    if url:
                        metadata["url"] = url
                    metadata["aligned"] = {
                        "strip_html": settings.elastic_connector_strip_html,
                        "normalize_whitespace": settings.elastic_connector_normalize_whitespace,
                    }

                    run_store.create_run(run, source_uri, text, metadata=metadata)
                    per_index_queued += 1
                    result.runs_queued += 1

                    if per_index_seen % 50 == 0:
                        _progress(
                            f"[{index_number}/{total_indexes}] {index_name}: "
                            f"scanned {per_index_seen}, queued {per_index_queued}"
                        )
                except Exception as exc:
                    result.errors.append(f"{index_name}/{doc_id}: {exc}")
        except Exception as exc:
            result.errors.append(f"{index_name}: search error: {exc}")
            continue

        result.indexes_scanned += 1
        _progress(
            f"[{index_number}/{total_indexes}] {index_name}: "
            f"done, scanned {per_index_seen}, queued {per_index_queued}"
        )

    return result
