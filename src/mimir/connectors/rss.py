"""Public RSS/Atom feed connector.

Pulls public threat-intelligence/news feeds and queues unseen entries for
LLM extraction. This connector does not require API credentials or paid licenses.
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from ..config import Settings
from ..schemas import ExtractionRun
from ..storage.run_store import RunStore

logger = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


@dataclass
class RssPullResult:
    feeds_scanned: int = 0
    items_seen: int = 0
    runs_queued: int = 0
    skipped_existing: int = 0
    skipped_old: int = 0
    skipped_empty: int = 0
    errors: List[str] = field(default_factory=list)


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1].lower()
    return str(tag).lower()


def _child_text(node: ET.Element, names: List[str]) -> str:
    wanted = {name.lower() for name in names}
    for child in list(node):
        if _local_name(child.tag) in wanted:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _extract_link(node: ET.Element) -> str:
    # RSS: <link>https://...</link>
    link_text = _child_text(node, ["link"])
    if link_text.startswith("http://") or link_text.startswith("https://"):
        return link_text

    # Atom: <link href="..." rel="alternate" />
    first_href = ""
    for child in list(node):
        if _local_name(child.tag) != "link":
            continue
        href = str(child.attrib.get("href") or "").strip()
        if not href:
            continue
        rel = str(child.attrib.get("rel") or "").strip().lower()
        if not first_href:
            first_href = href
        if rel in {"", "alternate"}:
            return href
    return first_href


def _normalize_text(value: str) -> str:
    if not value:
        return ""
    out = html.unescape(value)
    if "<" in out and ">" in out:
        out = _TAG_RE.sub(" ", out)
    out = _WS_RE.sub(" ", out).strip()
    return out


def _parse_datetime(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None

    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        pass

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _feed_slug(feed_url: str) -> str:
    parsed = urlparse(feed_url)
    host = (parsed.netloc or "feed").lower()
    path = parsed.path.strip("/").replace("/", "_")
    if not path:
        path = "root"
    return f"{host}:{path}"


def _build_source_uri(feed_url: str, item_key: str) -> str:
    slug = _feed_slug(feed_url)
    digest = hashlib.sha1(item_key.encode("utf-8")).hexdigest()[:24]
    return f"rss://{slug}/{digest}"


def _build_run_id(feed_url: str, item_key: str) -> str:
    digest = hashlib.sha1(f"{feed_url}|{item_key}".encode("utf-8")).hexdigest()
    return f"rss-{digest}"


def _parse_feed_entries(xml_text: str) -> tuple[str, List[Dict[str, str]]]:
    root = ET.fromstring(xml_text)
    root_name = _local_name(root.tag)
    entries: List[Dict[str, str]] = []
    feed_title = ""

    if root_name in {"rss", "rdf"}:
        channel = None
        for child in list(root):
            if _local_name(child.tag) == "channel":
                channel = child
                break
        container = channel if channel is not None else root
        feed_title = _normalize_text(_child_text(container, ["title"]))
        for child in list(container):
            if _local_name(child.tag) != "item":
                continue
            title = _normalize_text(_child_text(child, ["title"]))
            link = _normalize_text(_extract_link(child))
            guid = _normalize_text(_child_text(child, ["guid"]))
            published = _normalize_text(_child_text(child, ["pubDate", "date"]))
            summary = _normalize_text(
                _child_text(
                    child,
                    ["description", "summary", "encoded", "content"],
                )
            )
            entries.append(
                {
                    "title": title,
                    "link": link,
                    "guid": guid,
                    "published": published,
                    "summary": summary,
                }
            )
        return feed_title, entries

    if root_name == "feed":
        feed_title = _normalize_text(_child_text(root, ["title"]))
        for child in list(root):
            if _local_name(child.tag) != "entry":
                continue
            title = _normalize_text(_child_text(child, ["title"]))
            link = _normalize_text(_extract_link(child))
            guid = _normalize_text(_child_text(child, ["id"]))
            published = _normalize_text(_child_text(child, ["published", "updated"]))
            summary = _normalize_text(
                _child_text(child, ["summary", "content", "description"])
            )
            entries.append(
                {
                    "title": title,
                    "link": link,
                    "guid": guid,
                    "published": published,
                    "summary": summary,
                }
            )
        return feed_title, entries

    raise ValueError(f"Unsupported feed root element: {root.tag}")


def _fetch_feed_text(client: httpx.Client, feed_url: str) -> str:
    response = client.get(feed_url)
    response.raise_for_status()
    return response.text


def pull_from_rss_feeds(
    run_store: RunStore,
    settings: Settings,
    feed_urls: List[str],
    *,
    lookback_hours: int = 168,
    max_items_per_feed: int = 200,
    min_text_chars: int = 80,
    timeout_seconds: float = 20.0,
    progress_cb: Optional[Callable[[str], None]] = None,
    fetch_feed: Optional[Callable[[httpx.Client, str], str]] = None,
) -> RssPullResult:
    """Pull RSS/Atom entries and queue unseen items for extraction."""
    result = RssPullResult()
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=max(lookback_hours, 0))
    fetch = fetch_feed or _fetch_feed_text

    if not feed_urls:
        return result

    def _progress(message: str) -> None:
        if progress_cb:
            progress_cb(message)

    headers = {"User-Agent": "mimir-rss-worker/1.0 (+https://github.com/)"}
    with httpx.Client(
        timeout=max(float(timeout_seconds), 1.0),
        follow_redirects=True,
        headers=headers,
    ) as client:
        total_feeds = len(feed_urls)
        for feed_number, feed_url in enumerate(feed_urls, start=1):
            _progress(f"[{feed_number}/{total_feeds}] Reading feed {feed_url}")
            try:
                xml_text = fetch(client, feed_url)
                feed_title, entries = _parse_feed_entries(xml_text)
            except Exception as exc:
                result.errors.append(f"{feed_url}: fetch/parse failed: {exc}")
                logger.warning("RSS feed failed %s: %s", feed_url, exc)
                continue

            result.feeds_scanned += 1
            queued_for_feed = 0
            for entry in entries[: max_items_per_feed if max_items_per_feed > 0 else None]:
                result.items_seen += 1
                title = str(entry.get("title") or "").strip()
                link = str(entry.get("link") or "").strip()
                guid = str(entry.get("guid") or "").strip()
                published_raw = str(entry.get("published") or "").strip()
                summary = str(entry.get("summary") or "").strip()

                published_dt = _parse_datetime(published_raw)
                if published_dt is not None and lookback_hours > 0 and published_dt < since:
                    result.skipped_old += 1
                    continue

                item_key = guid or link or f"{title}|{published_raw}|{summary[:120]}"
                item_key = item_key.strip()
                if not item_key:
                    result.skipped_empty += 1
                    continue

                source_uri = _build_source_uri(feed_url, item_key)
                run_id = _build_run_id(feed_url, item_key)
                if run_store.get_run(run_id):
                    result.skipped_existing += 1
                    continue

                text_parts = []
                if title:
                    text_parts.append(title)
                if summary and summary != title:
                    text_parts.append(summary)
                if link:
                    text_parts.append(f"Source URL: {link}")
                text = "\n\n".join(part for part in text_parts if part).strip()
                if len(text) < max(int(min_text_chars), 1):
                    result.skipped_empty += 1
                    continue

                run = ExtractionRun(
                    run_id=run_id,
                    started_at=datetime.now(timezone.utc),
                    model=settings.ollama_model,
                    prompt_version=settings.prompt_version,
                    params={
                        "chunk_size": settings.chunk_size,
                        "chunk_overlap": settings.chunk_overlap,
                        "connector": "rss",
                        "feed_url": feed_url,
                    },
                    status="pending",
                    error=None,
                )
                metadata: Dict[str, str] = {
                    "connector": "rss",
                    "feed_url": feed_url,
                }
                if feed_title:
                    metadata["feed_title"] = feed_title
                if title:
                    metadata["title"] = title[:300]
                if link:
                    metadata["url"] = link
                if published_raw:
                    metadata["published"] = published_raw

                run_store.create_run(run, source_uri, text, metadata=metadata)
                result.runs_queued += 1
                queued_for_feed += 1

                if result.items_seen % 25 == 0:
                    _progress(
                        f"[{feed_number}/{total_feeds}] "
                        f"{feed_url}: seen {result.items_seen}, queued {queued_for_feed}"
                    )

            _progress(
                f"[{feed_number}/{total_feeds}] {feed_url}: "
                f"done, queued {queued_for_feed}"
            )

    return result
