"""OpenCTI GraphQL client for Wellspring integration.

All methods are synchronous — designed to run in a background thread
so they never block the FastAPI event loop.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterator, Optional

import httpx

logger = logging.getLogger(__name__)

# ── Inline fragments reused across queries ──────────────────────
_INLINE = """
                        ... on BasicObject {
                          id
                          entity_type
                        }
                        ... on AttackPattern { name }
                        ... on Campaign { name }
                        ... on Malware { name }
                        ... on Tool { name }
                        ... on Vulnerability { name }
                        ... on ThreatActorGroup { name }
                        ... on ThreatActorIndividual { name }
                        ... on IntrusionSet { name }
                        ... on Infrastructure { name }
                        ... on Indicator { name }
                        ... on Identity { name }
                        ... on CourseOfAction { name }
                        ... on Report { name }"""

_QUERY_NAME_MAP = {
    "Malware": "malwares",
    "Threat-Actor": "threatActorsGroup",
    "Attack-Pattern": "attackPatterns",
    "Tool": "tools",
    "Vulnerability": "vulnerabilities",
    "Campaign": "campaigns",
    "Intrusion-Set": "intrusionSets",
    "Indicator": "indicators",
    "Infrastructure": "infrastructures",
    "Report": "reports",
    "Course-Of-Action": "coursesOfAction",
}


class OpenCTIClient:
    """Synchronous GraphQL client for OpenCTI API."""

    def __init__(self, base_url: str, api_token: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "User-Agent": "Wellspring/1.0",
                "Accept": "application/json",
            },
            timeout=timeout,
            verify=True,
        )

    def close(self):
        self._client.close()

    def query(
        self, gql: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a GraphQL query against OpenCTI."""
        payload = {"query": gql}
        if variables:
            payload["variables"] = variables

        resp = self._client.post(f"{self.base_url}/graphql", json=payload)

        if resp.status_code == 403:
            logger.error(
                "OpenCTI 403: headers=%s body=%s", resp.headers, resp.text[:500]
            )

        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            errors = data["errors"]
            logger.error("OpenCTI GraphQL errors: %s", errors)
            raise RuntimeError(
                f"OpenCTI GraphQL error: {errors[0].get('message', 'unknown')}"
            )

        return data.get("data", {})

    # ────────────────────────────────────────────────────────────
    # Streaming page-by-page iterators (constant memory)
    # ────────────────────────────────────────────────────────────

    def iter_entities(
        self,
        entity_type: str,
        page_size: int = 100,
        on_page: Optional[Callable[[int], None]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield entities one at a time, fetching pages transparently.

        *on_page(total_so_far)* is called after each page is fetched,
        useful for progress reporting.
        """
        query_name = _QUERY_NAME_MAP.get(entity_type, entity_type.lower() + "s")
        cursor: Optional[str] = None
        total = 0
        include_rel_timestamps = True

        while True:
            after_clause = f', after: "{cursor}"' if cursor else ""
            created_at_field = (
                "\n                          created_at"
                if include_rel_timestamps
                else ""
            )
            gql = f"""
            {{
              {query_name}(first: {page_size}{after_clause}, orderBy: created_at, orderMode: desc) {{
                pageInfo {{
                  hasNextPage
                  endCursor
                }}
                edges {{
                  node {{
                    id
                    name
                    description
                    stixCoreRelationships(first: 30) {{
                      edges {{
                        node {{
                          id
                          relationship_type
                          confidence{created_at_field}
                          from {{
{_INLINE}
                          }}
                          to {{
{_INLINE}
                          }}
                        }}
                      }}
                    }}
                  }}
                }}
              }}
            }}
            """
            try:
                result = self.query(gql)
            except Exception as exc:
                msg = str(exc)
                if (
                    include_rel_timestamps
                    and "created_at" in msg
                    and ("Cannot query field" in msg or "Unknown field" in msg)
                ):
                    logger.warning(
                        "OpenCTI relation created_at field unavailable; retrying without it"
                    )
                    include_rel_timestamps = False
                    continue
                logger.warning(
                    "Failed to list %s (cursor=%s): %s", entity_type, cursor, exc
                )
                return

            data = result.get(query_name, {})
            edges = data.get("edges", [])
            page_info = data.get("pageInfo", {})

            for edge in edges:
                node = edge.get("node", {})
                relations = []
                for rel_edge in node.get("stixCoreRelationships", {}).get("edges", []):
                    rel = rel_edge.get("node", {})
                    from_obj = rel.get("from") or {}
                    to_obj = rel.get("to") or {}
                    relations.append(
                        {
                            "id": rel.get("id"),
                            "type": rel.get("relationship_type"),
                            "confidence": rel.get("confidence", 50),
                            "timestamp": rel.get("created_at"),
                            "from_id": from_obj.get("id"),
                            "from_name": from_obj.get("name", "unknown"),
                            "from_type": from_obj.get("entity_type", "unknown"),
                            "to_id": to_obj.get("id"),
                            "to_name": to_obj.get("name", "unknown"),
                            "to_type": to_obj.get("entity_type", "unknown"),
                        }
                    )

                total += 1
                yield {
                    "id": node.get("id"),
                    "name": node.get("name", "unknown"),
                    "type": entity_type,
                    "description": (node.get("description") or ""),
                    "relations": relations,
                }

            logger.info(
                "Fetched page of %d %s (total %d so far)",
                len(edges),
                entity_type,
                total,
            )
            if on_page:
                on_page(total)

            if not page_info.get("hasNextPage") or not edges:
                return
            cursor = page_info.get("endCursor")

    def iter_reports(
        self,
        page_size: int = 100,
        on_page: Optional[Callable[[int], None]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield reports one at a time with contained objects."""
        _INLINE_SIMPLE = """
                          ... on BasicObject { id entity_type }
                          ... on AttackPattern { name }
                          ... on Campaign { name }
                          ... on Malware { name }
                          ... on Tool { name }
                          ... on Vulnerability { name }
                          ... on ThreatActorGroup { name }
                          ... on ThreatActorIndividual { name }
                          ... on IntrusionSet { name }
                          ... on Infrastructure { name }
                          ... on Indicator { name }
                          ... on Identity { name }
                          ... on CourseOfAction { name }"""

        cursor: Optional[str] = None
        total = 0
        include_rel_timestamps = True

        while True:
            after_clause = f', after: "{cursor}"' if cursor else ""
            created_at_field = (
                "\n                            created_at"
                if include_rel_timestamps
                else ""
            )
            gql = f"""
            {{
              reports(first: {page_size}{after_clause}, orderBy: created_at, orderMode: desc) {{
                pageInfo {{
                  hasNextPage
                  endCursor
                }}
                edges {{
                  node {{
                    id
                    name
                    description
                    published
                    content
                    objects(first: 200) {{
                      edges {{
                        node {{
                          ... on BasicObject {{
                            id
                            entity_type
                          }}
                          ... on AttackPattern {{ name }}
                          ... on Campaign {{ name }}
                          ... on Malware {{ name }}
                          ... on Tool {{ name }}
                          ... on Vulnerability {{ name }}
                          ... on ThreatActorGroup {{ name }}
                          ... on ThreatActorIndividual {{ name }}
                          ... on IntrusionSet {{ name }}
                          ... on Infrastructure {{ name }}
                          ... on Indicator {{ name }}
                          ... on Identity {{ name }}
                          ... on CourseOfAction {{ name }}
                          ... on StixCoreRelationship {{
                            id
                            relationship_type
                            confidence{created_at_field}
                            from {{
{_INLINE_SIMPLE}
                            }}
                            to {{
{_INLINE_SIMPLE}
                            }}
                          }}
                        }}
                      }}
                    }}
                  }}
                }}
              }}
            }}
            """
            try:
                result = self.query(gql)
            except Exception as exc:
                msg = str(exc)
                if (
                    include_rel_timestamps
                    and "created_at" in msg
                    and ("Cannot query field" in msg or "Unknown field" in msg)
                ):
                    logger.warning(
                        "OpenCTI report relationship created_at field unavailable; retrying without it"
                    )
                    include_rel_timestamps = False
                    continue
                logger.warning("Failed to list reports (cursor=%s): %s", cursor, exc)
                return

            data = result.get("reports", {})
            edges = data.get("edges", [])
            page_info = data.get("pageInfo", {})

            for edge in edges:
                node = edge.get("node", {})
                contained_objects = []
                contained_relations = []

                for obj_edge in node.get("objects", {}).get("edges", []):
                    obj = obj_edge.get("node", {})
                    etype = obj.get("entity_type", "")

                    if obj.get("relationship_type"):
                        from_obj = obj.get("from") or {}
                        to_obj = obj.get("to") or {}
                        contained_relations.append(
                            {
                                "id": obj.get("id"),
                                "type": obj.get("relationship_type"),
                                "confidence": obj.get("confidence", 50),
                                "timestamp": obj.get("created_at"),
                                "from_id": from_obj.get("id"),
                                "from_name": from_obj.get("name", "unknown"),
                                "from_type": from_obj.get("entity_type", "unknown"),
                                "to_id": to_obj.get("id"),
                                "to_name": to_obj.get("name", "unknown"),
                                "to_type": to_obj.get("entity_type", "unknown"),
                            }
                        )
                    elif obj.get("name"):
                        contained_objects.append(
                            {
                                "id": obj.get("id"),
                                "name": obj["name"],
                                "type": etype,
                            }
                        )

                text_parts = []
                if node.get("description"):
                    text_parts.append(node["description"])
                if node.get("content"):
                    text_parts.append(node["content"])

                total += 1
                yield {
                    "id": node.get("id"),
                    "name": node.get("name", "unknown"),
                    "description": (node.get("description") or "")[:1000],
                    "text": "\n\n".join(text_parts),
                    "published": node.get("published"),
                    "objects": contained_objects,
                    "relations": contained_relations,
                }

            logger.info(
                "Fetched page of %d reports (total %d so far)", len(edges), total
            )
            if on_page:
                on_page(total)

            if not page_info.get("hasNextPage") or not edges:
                return
            cursor = page_info.get("endCursor")
