from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

_log = logging.getLogger(__name__)

_WHITESPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")
_QUOTED_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'')
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")
_CTI_TOKEN_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,8}|TA\d{4}|T\d{4}(?:\.\d{3})?|S\d{4})\b",
    re.IGNORECASE,
)
_HASH_TOKEN_RE = re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "about",
        "can",
        "could",
        "for",
        "from",
        "give",
        "how",
        "i",
        "in",
        "is",
        "it",
        "its",
        "me",
        "of",
        "on",
        "or",
        "please",
        "regarding",
        "show",
        "tell",
        "that",
        "the",
        "their",
        "them",
        "this",
        "those",
        "to",
        "us",
        "was",
        "we",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "with",
        "you",
        "your",
    }
)


def _normalize_space(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", str(text or "").strip())


def _dedupe_preserve(values: Iterable[str], *, limit: int) -> List[str]:
    seen: set[str] = set()
    deduped: List[str] = []
    for value in values:
        token = _normalize_space(value)
        if not token:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(token)
        if len(deduped) >= limit:
            break
    return deduped


def _is_structured_token(token: str) -> bool:
    return bool(_CTI_TOKEN_RE.fullmatch(token) or _HASH_TOKEN_RE.fullmatch(token))


def extract_search_terms(question: str, *, max_terms: int = 12) -> List[str]:
    """Extract likely entity-centric search terms from a natural-language question."""
    normalized = _normalize_space(question)
    if not normalized:
        return []

    candidates: List[str] = []
    lowered = normalized.lower()

    # Favor the phrase after common prompt words: "about X", "regarding X", etc.
    for marker in ("about ", "regarding ", "on ", "for "):
        idx = lowered.find(marker)
        if idx >= 0:
            tail = normalized[idx + len(marker) :].strip(" .?!,:;")
            if tail:
                candidates.append(tail)
            break

    # Preserve quoted phrases exactly.
    for quoted_groups in _QUOTED_RE.findall(normalized):
        quoted = quoted_groups[0] or quoted_groups[1]
        quoted = quoted.strip()
        if quoted:
            candidates.append(quoted)

    # Pull out high-signal CTI tokens and hashes.
    candidates.extend(match.group(0) for match in _CTI_TOKEN_RE.finditer(normalized))
    candidates.extend(match.group(0) for match in _HASH_TOKEN_RE.finditer(normalized))

    # General tokens; keep only useful non-stopword terms.
    for raw in _TOKEN_RE.findall(normalized):
        token = raw.strip(" .?!,:;()[]{}<>\"'")
        token = token.strip("._:-")
        if not token:
            continue
        lower = token.lower()
        if lower in _STOPWORDS:
            continue
        if not _is_structured_token(token):
            if len(lower) < 3:
                continue
            if lower.isdigit() and len(lower) < 4:
                continue
        candidates.append(token)

    # Fallback to whole question as a low-priority backstop.
    candidates.append(normalized)
    return _dedupe_preserve(candidates, limit=max_terms)


def _query_variants(term: str) -> List[str]:
    variants = [term]
    lower = term.lower()
    if lower != term:
        variants.append(lower)

    # Add punctuation-normalized variants to bridge terms like
    # "DYNOWIPER", "DynoWiper", "dyno-wiper", "dyno_wiper".
    de_punct = _NON_ALNUM_RE.sub(" ", term).strip()
    if de_punct and de_punct != term:
        variants.append(de_punct)
        variants.append(de_punct.lower())

    collapsed = _NON_ALNUM_RE.sub("", term).strip()
    if len(collapsed) >= 3 and collapsed.lower() != lower:
        variants.append(collapsed)
        variants.append(collapsed.lower())

    return _dedupe_preserve(variants, limit=6)


def _entity_key(entity: Any) -> Tuple[str, str, str]:
    entity_id = str(getattr(entity, "id", "") or "").strip()
    if entity_id:
        return ("id", entity_id, "")
    name = str(getattr(entity, "name", "") or "").strip().lower()
    entity_type = str(getattr(entity, "type", "") or "").strip().lower()
    return ("name_type", name, entity_type)


def gather_entities(
    question: str,
    search_fn: Callable[[str], Sequence[Any]],
    *,
    limit: int = 20,
    per_term_limit: int = 8,
) -> Tuple[List[Any], List[str]]:
    """Search entities using multiple candidate terms and return deduped results."""
    search_terms = extract_search_terms(question)
    if not search_terms:
        return [], []

    found: List[Any] = []
    seen: set[Tuple[str, str, str]] = set()

    for term in search_terms:
        if len(found) >= limit:
            break
        for query in _query_variants(term):
            try:
                matches = search_fn(query) or []
            except Exception:
                continue
            for entity in list(matches)[:per_term_limit]:
                key = _entity_key(entity)
                if key in seen:
                    continue
                seen.add(key)
                found.append(entity)
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break

    return found, search_terms


# ---------------------------------------------------------------------------
# RAG context gathering — multi-signal retrieval
# ---------------------------------------------------------------------------


def search_text_chunks(
    es_client: Any,
    chunks_index: str,
    terms: List[str],
    *,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Full-text search over the chunks index for RAG passages."""
    if not terms:
        return []
    # Build a combined query: match each term, boost exact phrases
    should_clauses: List[Dict[str, Any]] = []
    for term in terms[:6]:
        should_clauses.append({"match": {"text": {"query": term, "boost": 1.0}}})
        should_clauses.append({"match_phrase": {"text": {"query": term, "boost": 3.0}}})

    try:
        resp = es_client.search(
            index=chunks_index,
            query={"bool": {"should": should_clauses, "minimum_should_match": 1}},
            size=limit,
            _source=["source_uri", "text", "run_id", "start_offset", "end_offset"],
        )
        hits = resp.get("hits", {}).get("hits", [])
        results = []
        seen_uris: set[str] = set()
        for hit in hits:
            src = hit["_source"]
            uri = src.get("source_uri", "")
            # Deduplicate by source_uri to avoid multiple chunks from same doc
            if uri in seen_uris:
                continue
            seen_uris.add(uri)
            text = src.get("text", "")
            # Truncate very long chunks to stay within prompt budget
            if len(text) > 800:
                text = text[:800] + "…"
            results.append(
                {
                    "source_uri": uri,
                    "text": text,
                    "score": hit.get("_score", 0),
                }
            )
        return results
    except Exception:
        _log.debug("Chunk text search failed", exc_info=True)
        return []


def search_provenance_snippets(
    es_client: Any,
    provenance_index: str,
    entity_names: List[str],
    *,
    limit: int = 15,
) -> List[Dict[str, Any]]:
    """Search provenance snippets for mentions of entity names."""
    if not entity_names:
        return []
    should_clauses: List[Dict[str, Any]] = []
    for name in entity_names[:10]:
        should_clauses.append(
            {"match_phrase": {"snippet": {"query": name, "boost": 2.0}}}
        )
        should_clauses.append({"match": {"snippet": {"query": name}}})

    try:
        resp = es_client.search(
            index=provenance_index,
            query={"bool": {"should": should_clauses, "minimum_should_match": 1}},
            size=limit,
            _source=["source_uri", "snippet", "model", "timestamp"],
        )
        hits = resp.get("hits", {}).get("hits", [])
        seen: set[str] = set()
        results = []
        for hit in hits:
            src = hit["_source"]
            snippet = src.get("snippet", "")
            if not snippet or snippet in seen:
                continue
            seen.add(snippet)
            if len(snippet) > 500:
                snippet = snippet[:500] + "…"
            results.append(
                {
                    "source_uri": src.get("source_uri", ""),
                    "snippet": snippet,
                    "model": src.get("model", ""),
                }
            )
        return results
    except Exception:
        _log.debug("Provenance snippet search failed", exc_info=True)
        return []


def search_relations_by_entity_names(
    es_client: Any,
    entities_index: str,
    relations_index: str,
    entity_names: List[str],
    *,
    limit: int = 30,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Find relations for entities by searching entity names, then querying relations.

    Returns (relations_list, entity_id_to_name_map).
    This bridges the gap for entities that have no direct subgraph links
    but *are* connected through name-matched entity IDs.
    """
    if not entity_names:
        return [], {}

    # Step 1: Search for all entity variants by name
    should_clauses: List[Dict[str, Any]] = []
    for name in entity_names[:10]:
        should_clauses.append({"match_phrase": {"name": {"query": name, "boost": 3.0}}})
        should_clauses.append({"match": {"name": {"query": name, "operator": "and"}}})
        # Also check aliases
        should_clauses.append(
            {"match_phrase": {"aliases": {"query": name, "boost": 2.0}}}
        )

    entity_map: Dict[str, str] = {}
    entity_ids: set[str] = set()

    try:
        resp = es_client.search(
            index=entities_index,
            query={"bool": {"should": should_clauses, "minimum_should_match": 1}},
            size=50,
            _source=["name", "type", "aliases"],
        )
        for hit in resp.get("hits", {}).get("hits", []):
            eid = hit["_id"]
            entity_map[eid] = hit["_source"].get("name", eid)
            entity_ids.add(eid)
    except Exception:
        _log.debug("Entity name search for relations failed", exc_info=True)
        return [], {}

    if not entity_ids:
        return [], entity_map

    # Step 2: Find relations where any of these entity IDs are subject or object
    id_list = list(entity_ids)[:30]
    should_rel: List[Dict[str, Any]] = [
        {"terms": {"subject_id": id_list}},
        {"terms": {"object_id": id_list}},
    ]

    relations: List[Dict[str, Any]] = []
    try:
        resp = es_client.search(
            index=relations_index,
            query={"bool": {"should": should_rel, "minimum_should_match": 1}},
            size=limit,
            _source=["subject_id", "object_id", "predicate", "confidence", "attrs"],
        )
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            subj_id = src.get("subject_id", "")
            obj_id = src.get("object_id", "")
            # Resolve names for any entity IDs not yet in the map
            for eid in (subj_id, obj_id):
                if eid and eid not in entity_map:
                    try:
                        edoc = es_client.get(index=entities_index, id=eid)
                        entity_map[eid] = edoc["_source"].get("name", eid)
                    except Exception:
                        entity_map[eid] = eid

            relations.append(
                {
                    "id": hit["_id"],
                    "subject_name": entity_map.get(subj_id, subj_id),
                    "predicate": src.get("predicate", ""),
                    "object_name": entity_map.get(obj_id, obj_id),
                    "confidence": src.get("confidence", 0),
                }
            )
    except Exception:
        _log.debug("Relation search by entity names failed", exc_info=True)

    return relations, entity_map


def gather_full_context(
    question: str,
    graph_store: Any,
    run_store: Optional[Any] = None,
    *,
    entity_limit: int = 20,
    chunk_limit: int = 8,
    relation_limit: int = 40,
    provenance_limit: int = 15,
    subgraph_depth: int = 2,
) -> Tuple[Dict[str, Any], List[str]]:
    """Comprehensive RAG retrieval: entities + subgraph + chunks + provenance.

    Returns (context_dict, search_terms).
    """
    context: Dict[str, Any] = {
        "entities": [],
        "relations": [],
        "provenance": [],
        "chunks": [],
        "stats": None,
    }

    # 1. Extract search terms and find matching entities
    found_entities, search_terms = gather_entities(
        question,
        lambda term: graph_store.search_entities(term),
        limit=entity_limit,
    )

    entity_map: Dict[str, str] = {}
    entity_names: List[str] = []
    for e in found_entities:
        entity_map[e.id] = e.name
        entity_names.append(e.name)
        entry: Dict[str, Any] = {
            "name": e.name,
            "type": getattr(e, "type", "unknown"),
            "aliases": getattr(e, "aliases", []),
        }
        # Include useful attributes
        attrs = getattr(e, "attrs", None) or {}
        filtered_attrs = {
            k: v for k, v in attrs.items() if k not in ("canonical_key",) and v
        }
        if filtered_attrs:
            entry["attrs"] = filtered_attrs
        context["entities"].append(entry)

    # 2. Get subgraphs and provenance for found entities (depth=2 for richer context)
    seen_relations: set[str] = set()
    for e in found_entities[:8]:
        try:
            sub = graph_store.get_subgraph(
                e.id, depth=subgraph_depth, min_confidence=0.0
            )
            for node in sub.nodes:
                if node.id not in entity_map:
                    entity_map[node.id] = node.name

            for edge in sub.edges[:20]:
                if edge.id in seen_relations:
                    continue
                seen_relations.add(edge.id)
                context["relations"].append(
                    {
                        "subject_name": entity_map.get(
                            edge.subject_id, edge.subject_id
                        ),
                        "predicate": edge.predicate,
                        "object_name": entity_map.get(edge.object_id, edge.object_id),
                        "confidence": edge.confidence,
                    }
                )

                # Provenance for each relation
                try:
                    _rel, prov_list, _runs = graph_store.explain_edge(edge.id)
                    for p in prov_list[:3]:
                        snippet = getattr(p, "snippet", None)
                        if snippet:
                            context["provenance"].append(
                                {
                                    "source_uri": getattr(p, "source_uri", None),
                                    "snippet": snippet,
                                }
                            )
                except Exception:
                    pass
        except Exception:
            pass

    # 3. If we found entities but few relations via subgraph, search relations
    #    directly by entity name (covers OpenCTI entities with different IDs)
    if found_entities and len(context["relations"]) < 5:
        es_client = graph_store.client
        indices = graph_store.indices
        extra_rels, extra_map = search_relations_by_entity_names(
            es_client,
            indices.entities,
            indices.relations,
            entity_names + search_terms[:3],
            limit=relation_limit,
        )
        entity_map.update(extra_map)
        for rel in extra_rels:
            if rel["id"] not in seen_relations:
                seen_relations.add(rel["id"])
                context["relations"].append(
                    {
                        "subject_name": rel["subject_name"],
                        "predicate": rel["predicate"],
                        "object_name": rel["object_name"],
                        "confidence": rel["confidence"],
                    }
                )

    # 4. Search text chunks (RAG passages) — always do this for richer context
    es_client = graph_store.client
    indices = graph_store.indices
    # Combine entity names + search terms for chunk queries
    chunk_queries = list(dict.fromkeys(entity_names + search_terms[:4]))
    chunks = search_text_chunks(
        es_client, indices.chunks, chunk_queries, limit=chunk_limit
    )
    context["chunks"] = chunks

    # 5. Search provenance snippets by entity names
    if entity_names:
        prov_snippets = search_provenance_snippets(
            es_client, indices.provenance, entity_names, limit=provenance_limit
        )
        existing_snippets = {p["snippet"] for p in context["provenance"]}
        for ps in prov_snippets:
            if ps["snippet"] not in existing_snippets:
                existing_snippets.add(ps["snippet"])
                context["provenance"].append(
                    {
                        "source_uri": ps["source_uri"],
                        "snippet": ps["snippet"],
                    }
                )

    # 6. Cap collections for prompt budget
    context["relations"] = context["relations"][:relation_limit]
    context["provenance"] = context["provenance"][:provenance_limit]

    # 7. Graph stats
    try:
        stats: Dict[str, Any] = {
            "entities": graph_store.count_entities(),
            "relations": graph_store.count_relations(),
        }
        if run_store:
            stats["runs_completed"] = run_store.count_runs(status="completed")
        context["stats"] = stats
    except Exception:
        pass

    _log.info(
        "Ask RAG context: %d entities, %d relations, %d provenance, %d chunks",
        len(context["entities"]),
        len(context["relations"]),
        len(context["provenance"]),
        len(context["chunks"]),
    )

    return context, search_terms
