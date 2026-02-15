"""Data-source connectors for the Mimir platform.

Each connector handles source-specific parsing and graph upsert logic.
Connector workers (``mimir.worker.*_worker``) schedule periodic calls
to these connectors.

Submodules:
- ``feedly``  — Feedly AI entity extraction from Elasticsearch
- ``rss``     — Public RSS/Atom threat feeds
- ``gvm``     — GVM/OpenVAS vulnerability scan results
- ``watcher`` — Watcher threat-intelligence platform
- ``malware`` — Malware sample data (MWDB / dailymalwarefeed)
- ``aikg``    — AI Knowledge Graph triple ingestion
"""

from .feedly import FeedlySyncResult, sync_feedly_index

__all__ = [
    "FeedlySyncResult",
    "sync_feedly_index",
]
