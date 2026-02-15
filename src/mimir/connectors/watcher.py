"""Watcher (Thales CERT) → Mimir connector.

Pulls threat-intelligence data from a Watcher instance via its REST API
and imports structured entities and relationships into the Mimir
knowledge graph.

Imported modules
~~~~~~~~~~~~~~~~
* **Trendy Words** — trending threat keywords (CVEs, threat actors,
  malware families) with reliability scores and source post URLs.
* **Data Leaks** — detected data exposures on Pastebin, GitHub, etc.
* **DNS Twisted** — typosquatting / phishing domains detected via
  dnstwist and certificate transparency monitoring.
* **Site Monitoring** — suspicious website tracking with IP, MX,
  content-change, registrar, and legitimacy metadata.

Mapped entity types
~~~~~~~~~~~~~~~~~~~
* **trendy_word** — trending keyword with occurrence count and score
* **data_leak_alert** — data leak finding
* **data_leak_keyword** — keyword being monitored for leaks
* **twisted_domain** — typosquatting / phishing domain
* **monitored_domain** — corporate domain being protected
* **monitored_site** — suspicious website under surveillance
* **vulnerability** — CVE extracted from trendy words
* **threat_actor** — threat actor name extracted from trendy words
* **malware** — malware family name extracted from trendy words
* **domain** — legitimate domain entity
* **ip_address** — IP address from site monitoring

Design goals
~~~~~~~~~~~~
* **Structured-first**: exploit Watcher's pre-extracted threat data
  so we get graph data instantly, without waiting for an LLM pass.
* **Incremental**: filter by ``created_at`` to only sync new records.
* **Memory-constant**: page through API results.
* **Non-blocking**: all public functions are synchronous and designed to
  run inside ``asyncio.to_thread()``.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from uuid import UUID, uuid4, uuid5

import httpx

from ..config import Settings
from ..dedupe import EntityResolver
from ..normalize import canonical_entity_key
from ..schemas import Entity, Provenance, Relation
from ..storage.base import GraphStore

logger = logging.getLogger(__name__)

# Namespace UUID for deterministic provenance IDs
_NS_PROVENANCE = UUID("e4c8a2b6-f1d3-49e7-8c5a-2d6b0e9f3a71")

# Pattern matchers for entity-type inference from trendy word names
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_APT_RE = re.compile(r"\bAPT[- ]?\d{1,3}\b", re.IGNORECASE)
_THREAT_ACTOR_TERMS = frozenset({
    "lazarus", "kimsuky", "turla", "cozy bear", "fancy bear",
    "sandworm", "equation group", "apt28", "apt29", "apt30",
    "apt31", "apt32", "apt33", "apt34", "apt35", "apt36",
    "apt37", "apt38", "apt39", "apt40", "apt41",
    "charming kitten", "phosphorus", "nobelium", "hafnium",
    "lapsus$", "scattered spider", "volt typhoon",
    "salt typhoon", "midnight blizzard",
})
_MALWARE_TERMS = frozenset({
    "ransomware", "trojan", "wiper", "botnet", "rootkit",
    "backdoor", "keylogger", "infostealer", "stealer",
    "loader", "dropper", "rat", "cobra", "lockbit",
    "blackcat", "alphv", "clop", "conti", "hive",
    "revil", "ryuk", "wannacry", "emotet", "trickbot",
    "qakbot", "icedid", "dridex", "raccoon", "redline",
    "vidar", "formbook", "agent tesla", "asyncrat",
    "remcos", "njrat", "darkgate", "pikabot",
})


# ── Results ──────────────────────────────────────────────────


@dataclass
class WatcherSyncResult:
    """Tracks statistics for a Watcher sync cycle."""

    trendy_words_processed: int = 0
    data_leaks_processed: int = 0
    dns_twisted_processed: int = 0
    sites_processed: int = 0
    entities_created: int = 0
    relations_created: int = 0
    skipped_low_score: int = 0
    skipped_low_occurrences: int = 0
    errors: List[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────


def _det_prov_id(
    *,
    source_uri: str,
    relation_id: str,
    model: str,
    chunk_id: str,
    snippet: str,
) -> str:
    """Deterministic provenance ID."""
    snippet_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()
    material = f"{source_uri}|{relation_id}|{model}|{chunk_id}|{snippet_hash}"
    return str(uuid5(_NS_PROVENANCE, material))


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Best-effort parse of a datetime value from Watcher API."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _infer_trendy_word_type(name: str) -> str:
    """Infer what kind of entity a trendy word represents."""
    lower = name.strip().lower()
    if _CVE_RE.match(name.strip()):
        return "vulnerability"
    if _APT_RE.search(name):
        return "threat_actor"
    if lower in _THREAT_ACTOR_TERMS:
        return "threat_actor"
    if lower in _MALWARE_TERMS:
        return "malware"
    return "trendy_word"


# ── API client ───────────────────────────────────────────────


def _create_client(settings: Settings) -> httpx.Client:
    """Create an httpx client configured for the Watcher API."""
    headers: Dict[str, str] = {
        "Accept": "application/json",
    }
    if settings.watcher_api_token:
        headers["Authorization"] = f"Token {settings.watcher_api_token}"
    return httpx.Client(
        base_url=settings.watcher_base_url.rstrip("/"),
        headers=headers,
        verify=settings.watcher_verify_tls,
        timeout=settings.watcher_timeout_seconds,
    )


def _iter_api_pages(
    client: httpx.Client,
    path: str,
    *,
    page_size: int = 200,
    since: Optional[datetime] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    """Page through a Watcher DRF list endpoint.

    Yields individual result dicts. Stops when there are no more pages.
    """
    query: Dict[str, Any] = {"page_size": page_size}
    if params:
        query.update(params)

    page = 1
    while True:
        query["page"] = page
        try:
            resp = client.get(path, params=query)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("Watcher API request failed: %s %s -> %s", path, query, exc)
            break

        data = resp.json()

        # DRF paginated response: {"count": N, "next": url, "results": [...]}
        if isinstance(data, dict) and "results" in data:
            results = data["results"]
            if not results:
                break

            for item in results:
                # Filter by created_at if since is specified
                if since is not None:
                    created = _parse_datetime(item.get("created_at"))
                    if created is not None and created < since:
                        continue
                yield item

            if not data.get("next"):
                break
            page += 1
        elif isinstance(data, list):
            # Non-paginated response
            for item in data:
                if since is not None:
                    created = _parse_datetime(item.get("created_at"))
                    if created is not None and created < since:
                        continue
                yield item
            break
        else:
            break


# ── Trendy words ─────────────────────────────────────────────


def _process_trendy_words(
    client: httpx.Client,
    graph_store: GraphStore,
    resolver: EntityResolver,
    settings: Settings,
    since: datetime,
    source_uri: str,
    result: WatcherSyncResult,
) -> None:
    """Import trending threat keywords from Watcher."""
    min_score = settings.watcher_min_trendy_score
    min_occ = settings.watcher_min_trendy_occurrences

    for item in _iter_api_pages(
        client,
        "/api/threats_watcher/trendyword/",
        page_size=settings.watcher_page_size,
        since=since,
    ):
        try:
            name = str(item.get("name", "")).strip()
            if not name:
                continue

            occurrences = int(item.get("occurrences", 1))
            score = float(item.get("score", 0.0))

            if score < min_score:
                result.skipped_low_score += 1
                continue
            if occurrences < min_occ:
                result.skipped_low_occurrences += 1
                continue

            entity_type = _infer_trendy_word_type(name)
            created = _parse_datetime(item.get("created_at")) or datetime.now(
                timezone.utc
            )

            entity = resolver.resolve(name, entity_type=entity_type)
            entity.attrs["origin"] = "watcher"
            entity.attrs["source"] = "watcher-trendy"
            entity.attrs["occurrences"] = occurrences
            entity.attrs["reliability_score"] = score
            entity.attrs["source_uri"] = source_uri
            entity.attrs["watcher_id"] = item.get("id")

            # Extract post URLs
            posturls = item.get("posturls", [])
            if isinstance(posturls, list) and posturls:
                urls = []
                for pu in posturls:
                    if isinstance(pu, str):
                        # Format: "url,created_at"
                        url_part = pu.split(",")[0].strip()
                        if url_part:
                            urls.append(url_part)
                    elif isinstance(pu, dict):
                        url_part = str(pu.get("url", "")).strip()
                        if url_part:
                            urls.append(url_part)
                if urls:
                    entity.attrs["source_urls"] = urls[:10]

            graph_store.upsert_entities([entity])
            result.entities_created += 1
            result.trendy_words_processed += 1

        except Exception as exc:
            errmsg = f"trendy word '{item.get('name', '?')}': {exc}"
            logger.warning("Watcher trendy word processing failed: %s", errmsg)
            result.errors.append(errmsg)


# ── Data leaks ───────────────────────────────────────────────


def _process_data_leaks(
    client: httpx.Client,
    graph_store: GraphStore,
    resolver: EntityResolver,
    settings: Settings,
    since: datetime,
    source_uri: str,
    result: WatcherSyncResult,
) -> None:
    """Import data leak alerts from Watcher."""
    for item in _iter_api_pages(
        client,
        "/api/data_leak/alert/",
        page_size=settings.watcher_page_size,
        since=since,
    ):
        try:
            alert_id = item.get("id", "")
            url = str(item.get("url", "")).strip()
            content = str(item.get("content", "")).strip()
            status = item.get("status", True)
            created = _parse_datetime(item.get("created_at")) or datetime.now(
                timezone.utc
            )

            # Keyword entity
            keyword_data = item.get("keyword", {})
            if isinstance(keyword_data, dict):
                kw_name = str(keyword_data.get("name", "")).strip()
            else:
                kw_name = str(keyword_data).strip() if keyword_data else ""

            if not kw_name and not url:
                continue

            entities: List[Entity] = []
            relations: List[Relation] = []

            # Create data_leak_alert entity
            alert_key = f"leak-{alert_id}" if alert_id else f"leak-{url}"
            alert_entity = resolver.resolve(alert_key, entity_type="data_leak_alert")
            alert_entity.attrs["origin"] = "watcher"
            alert_entity.attrs["source"] = "watcher-data-leak"
            alert_entity.attrs["url"] = url
            alert_entity.attrs["status"] = "active" if status else "resolved"
            alert_entity.attrs["source_uri"] = source_uri
            alert_entity.attrs["watcher_id"] = alert_id
            if content:
                alert_entity.attrs["content_preview"] = content[:500]
            entities.append(alert_entity)

            # Create data_leak_keyword entity and link
            if kw_name:
                kw_entity = resolver.resolve(kw_name, entity_type="data_leak_keyword")
                kw_entity.attrs["origin"] = "watcher"
                kw_entity.attrs["source"] = "watcher-data-leak"
                entities.append(kw_entity)

                relations.append(
                    Relation(
                        id=str(uuid4()),
                        subject_id=alert_entity.id,
                        predicate="matches_keyword",
                        object_id=kw_entity.id,
                        confidence=0.90,
                        attrs={
                            "origin": "watcher",
                            "source_uri": source_uri,
                        },
                    )
                )

            graph_store.upsert_entities(entities)
            if relations:
                stored = graph_store.upsert_relations(relations)
                for rel in stored:
                    snippet = f"Data leak alert: {kw_name} found at {url}"
                    prov = Provenance(
                        provenance_id=_det_prov_id(
                            source_uri=source_uri,
                            relation_id=rel.id,
                            model="watcher-connector",
                            chunk_id=f"data-leak-{alert_id}",
                            snippet=snippet,
                        ),
                        source_uri=source_uri,
                        chunk_id=f"data-leak-{alert_id}",
                        start_offset=0,
                        end_offset=0,
                        snippet=snippet,
                        extraction_run_id=f"watcher-leak-{alert_id}",
                        model="watcher-connector",
                        prompt_version="watcher-v1",
                        timestamp=created,
                    )
                    graph_store.attach_provenance(rel.id, prov)
                result.relations_created += len(stored)

            result.entities_created += len(entities)
            result.data_leaks_processed += 1

        except Exception as exc:
            errmsg = f"data leak {item.get('id', '?')}: {exc}"
            logger.warning("Watcher data leak processing failed: %s", errmsg)
            result.errors.append(errmsg)


# ── DNS Twisted (typosquatting / phishing domains) ───────────


def _process_dns_twisted(
    client: httpx.Client,
    graph_store: GraphStore,
    resolver: EntityResolver,
    settings: Settings,
    since: datetime,
    source_uri: str,
    result: WatcherSyncResult,
) -> None:
    """Import typosquatting / phishing domains from Watcher DNS finder."""
    for item in _iter_api_pages(
        client,
        "/api/dns_finder/dns_twisted/",
        page_size=settings.watcher_page_size,
        since=since,
    ):
        try:
            domain_name = str(item.get("domain_name", "")).strip()
            if not domain_name:
                continue

            created = _parse_datetime(item.get("created_at")) or datetime.now(
                timezone.utc
            )
            fuzzer = str(item.get("fuzzer", "")).strip()
            item_id = item.get("id", "")

            entities: List[Entity] = []
            relations: List[Relation] = []

            # Twisted domain entity
            twisted_entity = resolver.resolve(
                domain_name, entity_type="twisted_domain"
            )
            twisted_entity.attrs["origin"] = "watcher"
            twisted_entity.attrs["source"] = "watcher-dns-finder"
            twisted_entity.attrs["source_uri"] = source_uri
            twisted_entity.attrs["watcher_id"] = item_id
            if fuzzer:
                twisted_entity.attrs["fuzzer"] = fuzzer
            entities.append(twisted_entity)

            # Link to monitored domain (corporate domain being protected)
            dns_monitored = item.get("dns_monitored")
            if isinstance(dns_monitored, dict):
                mon_domain = str(dns_monitored.get("domain_name", "")).strip()
                if mon_domain:
                    mon_entity = resolver.resolve(
                        mon_domain, entity_type="monitored_domain"
                    )
                    mon_entity.attrs["origin"] = "watcher"
                    mon_entity.attrs["source"] = "watcher-dns-finder"
                    entities.append(mon_entity)

                    relations.append(
                        Relation(
                            id=str(uuid4()),
                            subject_id=twisted_entity.id,
                            predicate="impersonates",
                            object_id=mon_entity.id,
                            confidence=0.85,
                            attrs={
                                "origin": "watcher",
                                "source_uri": source_uri,
                                "fuzzer": fuzzer,
                            },
                        )
                    )

            # Link to keyword monitored (certstream-based detection)
            kw_monitored = item.get("keyword_monitored")
            if isinstance(kw_monitored, dict):
                kw_name = str(kw_monitored.get("name", "")).strip()
                if kw_name:
                    kw_entity = resolver.resolve(kw_name, entity_type="indicator")
                    kw_entity.attrs["origin"] = "watcher"
                    kw_entity.attrs["source"] = "watcher-dns-finder"
                    kw_entity.attrs["detection_method"] = "certstream"
                    entities.append(kw_entity)

                    relations.append(
                        Relation(
                            id=str(uuid4()),
                            subject_id=twisted_entity.id,
                            predicate="detected_by_keyword",
                            object_id=kw_entity.id,
                            confidence=0.80,
                            attrs={
                                "origin": "watcher",
                                "source_uri": source_uri,
                            },
                        )
                    )

            graph_store.upsert_entities(entities)
            if relations:
                stored = graph_store.upsert_relations(relations)
                for rel in stored:
                    snippet = f"Twisted domain {domain_name} detected"
                    if fuzzer:
                        snippet += f" (fuzzer: {fuzzer})"
                    prov = Provenance(
                        provenance_id=_det_prov_id(
                            source_uri=source_uri,
                            relation_id=rel.id,
                            model="watcher-connector",
                            chunk_id=f"dns-twisted-{item_id}",
                            snippet=snippet,
                        ),
                        source_uri=source_uri,
                        chunk_id=f"dns-twisted-{item_id}",
                        start_offset=0,
                        end_offset=0,
                        snippet=snippet,
                        extraction_run_id=f"watcher-dns-{item_id}",
                        model="watcher-connector",
                        prompt_version="watcher-v1",
                        timestamp=created,
                    )
                    graph_store.attach_provenance(rel.id, prov)
                result.relations_created += len(stored)

            result.entities_created += len(entities)
            result.dns_twisted_processed += 1

        except Exception as exc:
            errmsg = f"dns_twisted '{item.get('domain_name', '?')}': {exc}"
            logger.warning("Watcher DNS twisted processing failed: %s", errmsg)
            result.errors.append(errmsg)


# ── Site monitoring (suspicious websites) ────────────────────


_LEGITIMACY_MAP = {
    1: "unknown",
    2: "legitimate",
    3: "suspicious",
    4: "malicious_online",
    5: "malicious_down",
    6: "malicious_disabled",
}


def _process_sites(
    client: httpx.Client,
    graph_store: GraphStore,
    resolver: EntityResolver,
    settings: Settings,
    since: datetime,
    source_uri: str,
    result: WatcherSyncResult,
) -> None:
    """Import monitored suspicious websites from Watcher."""
    for item in _iter_api_pages(
        client,
        "/api/site_monitoring/site/",
        page_size=settings.watcher_page_size,
        since=since,
    ):
        try:
            domain_name = str(item.get("domain_name", "")).strip()
            if not domain_name:
                continue

            created = _parse_datetime(item.get("created_at")) or datetime.now(
                timezone.utc
            )
            item_id = item.get("id", "")

            entities: List[Entity] = []
            relations: List[Relation] = []

            # Site entity
            site_entity = resolver.resolve(domain_name, entity_type="monitored_site")
            site_entity.attrs["origin"] = "watcher"
            site_entity.attrs["source"] = "watcher-site-monitoring"
            site_entity.attrs["source_uri"] = source_uri
            site_entity.attrs["watcher_id"] = item_id

            # Metadata
            web_status = item.get("web_status")
            if web_status is not None:
                site_entity.attrs["http_status"] = web_status

            registrar = str(item.get("registrar", "") or "").strip()
            if registrar:
                site_entity.attrs["registrar"] = registrar

            legitimacy = item.get("legitimacy")
            if legitimacy is not None:
                site_entity.attrs["legitimacy"] = _LEGITIMACY_MAP.get(
                    legitimacy, "unknown"
                )
                site_entity.attrs["legitimacy_code"] = legitimacy

            for flag in ("monitored", "takedown_request", "legal_team", "blocking_request"):
                val = item.get(flag)
                if val is not None:
                    site_entity.attrs[flag] = val

            content_hash = str(item.get("content_fuzzy_hash", "") or "").strip()
            if content_hash:
                site_entity.attrs["content_fuzzy_hash"] = content_hash

            domain_expiry = item.get("domain_expiry")
            if domain_expiry:
                site_entity.attrs["domain_expiry"] = str(domain_expiry)

            mx_records = item.get("MX_records")
            if isinstance(mx_records, list) and mx_records:
                site_entity.attrs["mx_records"] = mx_records[:10]

            entities.append(site_entity)

            # IP address entities
            for ip_field in ("ip", "ip_second"):
                ip_val = str(item.get(ip_field, "") or "").strip()
                if ip_val:
                    ip_entity = resolver.resolve(ip_val, entity_type="ip_address")
                    ip_entity.attrs["origin"] = "watcher"
                    ip_entity.attrs["source"] = "watcher-site-monitoring"
                    ip_entity.attrs["version"] = "ipv4" if "." in ip_val else "ipv6"
                    entities.append(ip_entity)

                    relations.append(
                        Relation(
                            id=str(uuid4()),
                            subject_id=site_entity.id,
                            predicate="resolves_to",
                            object_id=ip_entity.id,
                            confidence=0.90,
                            attrs={
                                "origin": "watcher",
                                "source_uri": source_uri,
                                "ip_field": ip_field,
                            },
                        )
                    )

            # Mail A record IP
            mail_ip = str(item.get("mail_A_record_ip", "") or "").strip()
            if mail_ip:
                mail_ip_entity = resolver.resolve(mail_ip, entity_type="ip_address")
                mail_ip_entity.attrs["origin"] = "watcher"
                mail_ip_entity.attrs["source"] = "watcher-site-monitoring"
                mail_ip_entity.attrs["role"] = "mail"
                entities.append(mail_ip_entity)

                relations.append(
                    Relation(
                        id=str(uuid4()),
                        subject_id=site_entity.id,
                        predicate="mail_resolves_to",
                        object_id=mail_ip_entity.id,
                        confidence=0.85,
                        attrs={
                            "origin": "watcher",
                            "source_uri": source_uri,
                        },
                    )
                )

            graph_store.upsert_entities(entities)
            if relations:
                stored = graph_store.upsert_relations(relations)
                for rel in stored:
                    snippet = f"Monitored site {domain_name}"
                    leg = site_entity.attrs.get("legitimacy", "")
                    if leg:
                        snippet += f" (legitimacy: {leg})"
                    prov = Provenance(
                        provenance_id=_det_prov_id(
                            source_uri=source_uri,
                            relation_id=rel.id,
                            model="watcher-connector",
                            chunk_id=f"site-{item_id}",
                            snippet=snippet,
                        ),
                        source_uri=source_uri,
                        chunk_id=f"site-{item_id}",
                        start_offset=0,
                        end_offset=0,
                        snippet=snippet,
                        extraction_run_id=f"watcher-site-{item_id}",
                        model="watcher-connector",
                        prompt_version="watcher-v1",
                        timestamp=created,
                    )
                    graph_store.attach_provenance(rel.id, prov)
                result.relations_created += len(stored)

            result.entities_created += len(entities)
            result.sites_processed += 1

        except Exception as exc:
            errmsg = f"site '{item.get('domain_name', '?')}': {exc}"
            logger.warning("Watcher site processing failed: %s", errmsg)
            result.errors.append(errmsg)


# ── Main sync function ──────────────────────────────────────


def sync_watcher(
    *,
    settings: Settings,
    graph_store: GraphStore,
    since: datetime,
    until: Optional[datetime] = None,
) -> WatcherSyncResult:
    """Pull data from a Watcher instance and import into Mimir.

    Parameters
    ----------
    settings:
        Application settings (contains Watcher connection details).
    graph_store:
        The graph store to upsert entities/relations into.
    since:
        Only process records created after this time.
    until:
        Ignored (kept for interface consistency with other connectors).
    """
    result = WatcherSyncResult()
    resolver = EntityResolver(graph_store)
    source_uri = f"watcher://{settings.watcher_base_url.rstrip('/')}"

    logger.info(
        "Watcher sync started: base_url=%s, since=%s",
        settings.watcher_base_url,
        since.isoformat(),
    )

    try:
        client = _create_client(settings)
    except Exception as exc:
        errmsg = f"Watcher client creation failed: {exc}"
        logger.error(errmsg)
        result.errors.append(errmsg)
        return result

    with client:
        # ── Trendy Words ──
        if settings.watcher_pull_trendy_words:
            try:
                _process_trendy_words(
                    client, graph_store, resolver, settings,
                    since, source_uri, result,
                )
            except Exception as exc:
                errmsg = f"Trendy words sync failed: {exc}"
                logger.error(errmsg)
                result.errors.append(errmsg)

        # ── Data Leaks ──
        if settings.watcher_pull_data_leaks:
            try:
                _process_data_leaks(
                    client, graph_store, resolver, settings,
                    since, source_uri, result,
                )
            except Exception as exc:
                errmsg = f"Data leaks sync failed: {exc}"
                logger.error(errmsg)
                result.errors.append(errmsg)

        # ── DNS Twisted ──
        if settings.watcher_pull_dns_twisted:
            try:
                _process_dns_twisted(
                    client, graph_store, resolver, settings,
                    since, source_uri, result,
                )
            except Exception as exc:
                errmsg = f"DNS twisted sync failed: {exc}"
                logger.error(errmsg)
                result.errors.append(errmsg)

        # ── Site Monitoring ──
        if settings.watcher_pull_site_monitoring:
            try:
                _process_sites(
                    client, graph_store, resolver, settings,
                    since, source_uri, result,
                )
            except Exception as exc:
                errmsg = f"Site monitoring sync failed: {exc}"
                logger.error(errmsg)
                result.errors.append(errmsg)

    logger.info(
        "Watcher sync complete: %d trendy, %d leaks, %d twisted, %d sites, "
        "%d entities, %d relations, %d errors",
        result.trendy_words_processed,
        result.data_leaks_processed,
        result.dns_twisted_processed,
        result.sites_processed,
        result.entities_created,
        result.relations_created,
        len(result.errors),
    )

    return result
