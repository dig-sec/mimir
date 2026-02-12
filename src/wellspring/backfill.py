"""Historical backfill worker for Wellspring.

Ingests ALL data from Feedly and OpenCTI from the very beginning,
using checkpoint-based resumption so restarts don't lose progress.

Checkpoints are stored in Elasticsearch under the index
``{prefix}-backfill-checkpoints`` so they survive container restarts.

Usage (CLI)::

    python -m wellspring.backfill              # backfill everything
    python -m wellspring.backfill --source feedly
    python -m wellspring.backfill --source opencti
    python -m wellspring.backfill --reset      # wipe checkpoints, start over

Usage (API)::

    POST /api/backfill?source=all
    POST /api/backfill?source=feedly
    POST /api/backfill?source=opencti
    POST /api/backfill?reset=true
"""

from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .config import Settings, get_settings
from .storage.base import GraphStore
from .storage.factory import create_graph_store, create_run_store
from .storage.run_store import RunStore

logger = logging.getLogger(__name__)

# How far back to start if no checkpoint exists
_EPOCH = datetime(2020, 1, 1, tzinfo=timezone.utc)

# Process in time-window batches to keep each chunk manageable
# and checkpoint frequently.
_BATCH_WINDOW_HOURS = 24  # 1-day windows


# ── Checkpoint store ─────────────────────────────────────────


class CheckpointStore:
    """Tiny k/v store backed by a single ES index for resumable backfill."""

    def __init__(self, client: Any, index_prefix: str = "wellspring") -> None:
        self._client = client
        self._index = f"{index_prefix}-backfill-checkpoints"
        self._ensure_index()

    def _ensure_index(self) -> None:
        if self._client.indices.exists(index=self._index):
            return
        try:
            self._client.indices.create(
                index=self._index,
                mappings={
                    "properties": {
                        "source": {"type": "keyword"},
                        "checkpoint": {"type": "date"},
                        "updated_at": {"type": "date"},
                        "articles_total": {"type": "long"},
                        "entities_total": {"type": "long"},
                        "relations_total": {"type": "long"},
                    }
                },
            )
        except Exception:
            pass  # race-safe

    def get(self, source: str) -> Optional[datetime]:
        """Return the last checkpoint datetime, or None."""
        try:
            doc = self._client.get(index=self._index, id=source)
            ts = doc["_source"].get("checkpoint")
            if ts:
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            pass
        return None

    def set(
        self,
        source: str,
        checkpoint: datetime,
        articles_total: int = 0,
        entities_total: int = 0,
        relations_total: int = 0,
    ) -> None:
        """Persist a checkpoint."""
        self._client.index(
            index=self._index,
            id=source,
            document={
                "source": source,
                "checkpoint": checkpoint.isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "articles_total": articles_total,
                "entities_total": entities_total,
                "relations_total": relations_total,
            },
            refresh="wait_for",
        )

    def delete(self, source: str) -> None:
        try:
            self._client.delete(index=self._index, id=source, refresh="wait_for")
        except Exception:
            pass

    def get_all(self) -> Dict[str, Any]:
        """Return all checkpoints as a dict."""
        result: Dict[str, Any] = {}
        try:
            resp = self._client.search(
                index=self._index,
                query={"match_all": {}},
                size=100,
            )
            for hit in resp["hits"]["hits"]:
                src = hit["_source"]
                result[src["source"]] = src
        except Exception:
            pass
        return result


# ── Feedly backfill ──────────────────────────────────────────


def backfill_feedly(
    settings: Settings,
    graph_store: GraphStore,
    checkpoints: CheckpointStore,
    *,
    progress_cb: Optional[Any] = None,
) -> Dict[str, Any]:
    """Backfill ALL Feedly data in time-window batches with checkpoints."""
    from .connectors import sync_feedly_index

    indices = settings.elastic_connector_indices_list or ["feedly_news"]
    now = datetime.now(timezone.utc)

    total_articles = 0
    total_entities = 0
    total_relations = 0
    total_iocs = 0
    total_batches = 0
    total_errors: List[str] = []
    per_index: List[Dict[str, Any]] = []

    def _progress(msg: str):
        if progress_cb:
            progress_cb(msg)

    for index_name in indices:
        source_key = f"feedly:{index_name}"
        resume_from = checkpoints.get(source_key) or _EPOCH
        _progress(
            f"Feedly backfill [{index_name}]: resuming from {resume_from.isoformat()}"
        )
        logger.info(
            "Feedly backfill index %s starting from %s",
            index_name,
            resume_from.isoformat(),
        )

        index_articles = 0
        index_entities = 0
        index_relations = 0
        index_iocs = 0
        index_batches = 0
        index_errors: List[str] = []
        window_start = resume_from

        while window_start < now:
            window_end = min(window_start + timedelta(hours=_BATCH_WINDOW_HOURS), now)
            index_batches += 1
            total_batches += 1

            _progress(
                f"Feedly [{index_name}] batch {index_batches}: "
                f"{window_start.strftime('%Y-%m-%d %H:%M')} -> "
                f"{window_end.strftime('%Y-%m-%d %H:%M')}"
            )

            t0 = time.monotonic()
            try:
                result = sync_feedly_index(
                    settings=settings,
                    graph_store=graph_store,
                    run_store=None,
                    index_name=index_name,
                    since=window_start,
                    until=window_end,
                    max_articles=0,
                    queue_for_llm=False,
                )

                index_articles += result.articles_processed
                index_entities += result.entities_created
                index_relations += result.relations_created
                index_iocs += result.iocs_created
                index_errors.extend(result.errors[:5])

                total_articles += result.articles_processed
                total_entities += result.entities_created
                total_relations += result.relations_created
                total_iocs += result.iocs_created

                # Checkpoint only successful windows to avoid skipping data.
                checkpoints.set(
                    source_key,
                    window_end,
                    articles_total=index_articles,
                    entities_total=index_entities,
                    relations_total=index_relations,
                )
                window_start = window_end

                elapsed = time.monotonic() - t0
                logger.info(
                    "Feedly [%s] batch %d done in %.1fs: %d articles, %d entities, %d rels "
                    "(index cumulative: %d/%d/%d)",
                    index_name,
                    index_batches,
                    elapsed,
                    result.articles_processed,
                    result.entities_created,
                    result.relations_created,
                    index_articles,
                    index_entities,
                    index_relations,
                )
            except Exception as exc:
                logger.exception(
                    "Feedly [%s] batch %d failed", index_name, index_batches
                )
                error_msg = f"{index_name} batch {index_batches}: {exc}"
                index_errors.append(error_msg)
                # Stop this index so the same window can be retried on next run.
                break

        per_index.append(
            {
                "index": index_name,
                "articles": index_articles,
                "entities": index_entities,
                "relations": index_relations,
                "iocs": index_iocs,
                "batches": index_batches,
                "errors": index_errors[:50],
            }
        )
        total_errors.extend(index_errors[:10])

    _progress(
        f"Feedly backfill complete: {total_articles} articles, "
        f"{total_entities} entities, {total_relations} relations"
    )

    return {
        "source": "feedly",
        "articles": total_articles,
        "entities": total_entities,
        "relations": total_relations,
        "iocs": total_iocs,
        "batches": total_batches,
        "indices": per_index,
        "errors": total_errors[:50],
    }


# ── OpenCTI backfill ─────────────────────────────────────────


def backfill_opencti(
    settings: Settings,
    graph_store: GraphStore,
    run_store: RunStore,
    checkpoints: CheckpointStore,
    *,
    progress_cb: Optional[Any] = None,
) -> Dict[str, Any]:
    """Pull ALL entities/reports from OpenCTI (full dump)."""
    from .opencti.client import OpenCTIClient
    from .opencti.sync import pull_from_opencti

    source_key = "opencti"

    def _progress(msg: str):
        if progress_cb:
            progress_cb(msg)

    if not settings.opencti_url or not settings.opencti_token:
        _progress("OpenCTI: skipped (not configured)")
        return {"source": "opencti", "skipped": True, "reason": "not configured"}

    _progress("OpenCTI backfill: pulling all entities and reports...")
    logger.info("OpenCTI backfill starting (full pull)")

    client = OpenCTIClient(settings.opencti_url, settings.opencti_token)
    try:
        result = pull_from_opencti(
            client,
            graph_store,
            entity_types=[
                "Malware",
                "Threat-Actor",
                "Attack-Pattern",
                "Tool",
                "Vulnerability",
                "Campaign",
                "Intrusion-Set",
                "Indicator",
                "Infrastructure",
                "Course-Of-Action",
                "Report",
            ],
            max_per_type=0,  # unlimited
            run_store=run_store,
            settings=settings,
            progress_cb=lambda msg: _progress(f"OpenCTI: {msg}"),
        )
    finally:
        client.close()

    checkpoints.set(
        source_key,
        datetime.now(timezone.utc),
        entities_total=result.entities_pulled,
        relations_total=result.relations_pulled,
    )

    summary = {
        "source": "opencti",
        "entities": result.entities_pulled,
        "relations": result.relations_pulled,
        "reports_queued": result.reports_queued,
        "errors": result.errors[:50],
    }
    _progress(
        f"OpenCTI backfill complete: {result.entities_pulled} entities, "
        f"{result.relations_pulled} relations"
    )
    logger.info(
        "OpenCTI backfill done: %d entities, %d relations",
        result.entities_pulled,
        result.relations_pulled,
    )
    return summary


# ── Orchestrator ─────────────────────────────────────────────


def run_backfill(
    settings: Settings,
    graph_store: GraphStore,
    run_store: RunStore,
    checkpoints: CheckpointStore,
    *,
    sources: Optional[List[str]] = None,
    reset: bool = False,
    progress_cb: Optional[Any] = None,
) -> Dict[str, Any]:
    """Run backfill for the requested sources.

    Parameters
    ----------
    sources : list of str, optional
        Which sources to backfill.  ``["feedly", "opencti"]`` or
        ``["all"]`` (default).
    reset : bool
        If True, wipe checkpoints before starting.
    """
    if not sources or "all" in sources:
        sources = ["feedly", "opencti"]

    if reset:
        for s in sources:
            if s == "feedly":
                for index_name in settings.elastic_connector_indices_list or [
                    "feedly_news"
                ]:
                    source_key = f"feedly:{index_name}"
                    checkpoints.delete(source_key)
                    logger.info("Reset checkpoint for %s", source_key)
            else:
                checkpoints.delete(s)
                logger.info("Reset checkpoint for %s", s)

    results: Dict[str, Any] = {}

    for source in sources:
        if source == "feedly":
            results["feedly"] = backfill_feedly(
                settings,
                graph_store,
                checkpoints,
                progress_cb=progress_cb,
            )
        elif source == "opencti":
            results["opencti"] = backfill_opencti(
                settings,
                graph_store,
                run_store,
                checkpoints,
                progress_cb=progress_cb,
            )
        else:
            logger.warning("Unknown backfill source: %s", source)
            results[source] = {"error": f"unknown source: {source}"}

    return results


def get_backfill_status(checkpoints: CheckpointStore) -> Dict[str, Any]:
    """Return current checkpoint state for all sources."""
    return checkpoints.get_all()


# ── CLI entry point ──────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Wellspring historical backfill")
    parser.add_argument(
        "--source",
        "-s",
        choices=["all", "feedly", "opencti"],
        default="all",
        help="Which source to backfill (default: all)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe checkpoints and start from the beginning",
    )
    args = parser.parse_args()

    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    graph_store = create_graph_store(settings)
    run_store = create_run_store(settings)

    # Build a checkpoint store using the same ES client as the graph store
    es_client = getattr(graph_store, "client", None)
    if es_client is None:
        logger.error("Backfill requires Elasticsearch graph store")
        raise SystemExit(1)

    checkpoints = CheckpointStore(es_client, settings.elastic_index_prefix)

    sources = [args.source] if args.source != "all" else ["all"]

    def _progress(msg: str):
        logger.info("PROGRESS: %s", msg)

    t0 = time.monotonic()
    results = run_backfill(
        settings,
        graph_store,
        run_store,
        checkpoints,
        sources=sources,
        reset=args.reset,
        progress_cb=_progress,
    )
    elapsed = time.monotonic() - t0
    logger.info("Backfill finished in %.1fs: %s", elapsed, results)


if __name__ == "__main__":
    main()
