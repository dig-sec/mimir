"""Deterministic provenance-ID generation.

Consolidates the ``_det_prov_id`` helper that was duplicated across
six modules (pipeline/runner, connectors/{__init__, gvm, malware, watcher},
opencti/sync) into a single implementation.

Each caller supplies its own *namespace* UUID so that provenance IDs from
different data sources cannot collide even when key material is the same.
"""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid5

# Default namespace — used by the pipeline runner, Feedly, and OpenCTI
NS_PROVENANCE_DEFAULT = UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")

# Per-connector namespaces (preserved from their original definitions)
NS_PROVENANCE_GVM = UUID("b7a1e3c5-d9f2-4a6b-8e0c-1f3d5b7a9c2e")
NS_PROVENANCE_WATCHER = UUID("e4c8a2b6-f1d3-49e7-8c5a-2d6b0e9f3a71")
NS_PROVENANCE_MALWARE = UUID("d4e5f6a7-b8c9-0123-def0-abcdef012345")
NS_PROVENANCE_AIKG = UUID("f4f6c40f-b5c4-4ab5-9f21-4ca46d8e52eb")


def det_prov_id(
    *,
    namespace: UUID = NS_PROVENANCE_DEFAULT,
    source_uri: str,
    relation_id: str,
    model: str,
    chunk_id: str,
    start_offset: int = 0,
    end_offset: int = 0,
    snippet: str,
) -> str:
    """Return a deterministic provenance UUID keyed by evidence granularity.

    Parameters
    ----------
    namespace:
        UUID5 namespace.  Each data source should use its own namespace
        to avoid cross-source collisions.
    source_uri, relation_id, model, chunk_id:
        Key components that identify the evidence source.
    start_offset, end_offset:
        Character offsets within the chunk.  Pass ``0`` when the connector
        doesn't track offsets (e.g. Watcher).
    snippet:
        The evidence text.  SHA-1-hashed internally for stability.
    """
    snippet_hash = hashlib.sha1(snippet.encode("utf-8")).hexdigest()
    material = (
        f"{source_uri}|{relation_id}|{model}|{chunk_id}|"
        f"{start_offset}|{end_offset}|{snippet_hash}"
    )
    return str(uuid5(namespace, material))
