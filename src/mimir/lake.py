from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _to_utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()


def _split_source_uri(source_uri: str) -> tuple[str, str]:
    uri = str(source_uri or "").strip()
    if not uri:
        return "unknown", ""
    if "://" not in uri:
        return uri.lower(), ""
    scheme, rest = uri.split("://", 1)
    return scheme.lower(), rest


def _normalize_collection_token(value: str) -> str:
    token = str(value or "").strip().lower()
    if not token:
        return ""
    return token.replace(" ", "_").replace("-", "_")


def infer_source(source_uri: str) -> str:
    scheme, _ = _split_source_uri(source_uri)
    return scheme or "unknown"


def parse_source_uri(source_uri: str) -> Dict[str, str]:
    source, rest = _split_source_uri(source_uri)
    collection = ""
    record_id = ""

    if rest:
        if source in {"opencti", "elasticsearch", "malware"} and "/" in rest:
            collection, record_id = rest.split("/", 1)
            if source == "opencti":
                collection = _normalize_collection_token(collection)
        elif source == "rss" and "/" in rest:
            collection, record_id = rest.split("/", 1)
        elif source in {"upload", "stix"}:
            record_id = rest
        elif source == "file":
            collection = "filesystem"
            record_id = rest
        elif source == "feedly":
            collection = "feedly"
            record_id = rest
        elif source in {"gvm", "watcher"}:
            collection = "instance"
            record_id = rest
        else:
            record_id = rest

    return {
        "source": source or "unknown",
        "collection": collection,
        "record_id": record_id,
    }


def build_lake_metadata(
    source_uri: str,
    metadata: Optional[Dict[str, Any]] = None,
    *,
    ingested_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    doc: Dict[str, Any] = dict(metadata or {})
    parsed = parse_source_uri(source_uri)
    existing_lake = doc.get("lake")
    lake: Dict[str, Any] = (
        dict(existing_lake) if isinstance(existing_lake, dict) else {}
    )

    lake["version"] = int(lake.get("version") or 1)
    lake["source_uri"] = source_uri
    lake["source"] = parsed["source"]
    lake["collection"] = parsed["collection"]
    lake["record_id"] = parsed["record_id"]
    lake["ingested_at"] = _to_utc_iso(ingested_at or datetime.now(timezone.utc))

    # Keep compatibility with older metadata consumers.
    doc.setdefault("source", parsed["source"])
    doc["lake"] = lake
    return doc
