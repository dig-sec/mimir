from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from elasticsearch import ConflictError, NotFoundError

from ...lake import build_lake_metadata
from ...schemas import Chunk, ExtractionRun
from ..run_store import RunStore
from ._helpers import (
    _ElasticBase,
    _parse_datetime,
)


class ElasticRunStore(_ElasticBase, RunStore):
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "mimir",
        verify_certs: bool = True,
    ) -> None:
        super().__init__(hosts, username, password, index_prefix, verify_certs)
        self._ensure_indices()

    def _ensure_indices(self) -> None:
        self._ensure_index(
            self.indices.runs,
            {
                "started_at": {"type": "date"},
                "document_length": {"type": "integer"},
                "model": {"type": "keyword"},
                "prompt_version": {"type": "keyword"},
                "params": {"type": "object"},
                "status": {"type": "keyword"},
                "error": {"type": "text"},
            },
        )
        self._ensure_index(
            self.indices.documents,
            {
                "source_uri": {"type": "keyword"},
                "text": {"type": "text"},
                "metadata": {"type": "object"},
            },
        )
        self._ensure_index(
            self.indices.chunks,
            {
                "run_id": {"type": "keyword"},
                "source_uri": {"type": "keyword"},
                "start_offset": {"type": "integer"},
                "end_offset": {"type": "integer"},
                "text": {"type": "text"},
            },
        )

    def _to_run(self, run_id: str, source: Dict[str, Any]) -> ExtractionRun:
        return ExtractionRun(
            run_id=run_id,
            started_at=_parse_datetime(source["started_at"]),
            model=source["model"],
            prompt_version=source["prompt_version"],
            params=source.get("params") or {},
            status=source["status"],
            error=source.get("error"),
        )

    def create_run(
        self,
        run: ExtractionRun,
        source_uri: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        normalized_metadata = build_lake_metadata(
            source_uri,
            metadata,
            ingested_at=run.started_at,
        )
        self.client.index(
            index=self.indices.runs,
            id=run.run_id,
            document={
                "started_at": run.started_at.isoformat(),
                "document_length": len(text),
                "model": run.model,
                "prompt_version": run.prompt_version,
                "params": run.params,
                "status": run.status,
                "error": run.error,
            },
            refresh="wait_for",
        )
        self.client.index(
            index=self.indices.documents,
            id=run.run_id,
            document={
                "source_uri": source_uri,
                "text": text,
                "metadata": normalized_metadata,
            },
            refresh="wait_for",
        )

    def update_run_status(
        self, run_id: str, status: str, error: Optional[str] = None
    ) -> None:
        self.client.update(
            index=self.indices.runs,
            id=run_id,
            doc={"status": status, "error": error},
            refresh="wait_for",
        )

    def get_run(self, run_id: str) -> Optional[ExtractionRun]:
        try:
            doc = self.client.get(index=self.indices.runs, id=run_id)
        except NotFoundError:
            return None
        return self._to_run(doc["_id"], doc["_source"])

    def recover_stale_runs(self) -> int:
        response = self.client.update_by_query(
            index=self.indices.runs,
            query={"term": {"status": "running"}},
            script={
                "source": "ctx._source.status = params.status; ctx._source.error = null",
                "params": {"status": "pending"},
            },
            refresh=True,
            conflicts="proceed",
        )
        return int(response.get("updated", 0))

    def claim_next_run(self) -> Optional[ExtractionRun]:
        response = self.client.search(
            index=self.indices.runs,
            query={"term": {"status": "pending"}},
            sort=[
                {"document_length": {"order": "asc", "missing": "_last"}},
                {"started_at": "asc"},
            ],
            size=25,
            seq_no_primary_term=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        for hit in hits:
            run_id = hit["_id"]
            try:
                self.client.update(
                    index=self.indices.runs,
                    id=run_id,
                    if_seq_no=hit["_seq_no"],
                    if_primary_term=hit["_primary_term"],
                    doc={"status": "running", "error": None},
                    refresh="wait_for",
                )
                return self._to_run(run_id, hit["_source"])
            except ConflictError:
                continue
        return None

    def get_document(self, run_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.client.get(index=self.indices.documents, id=run_id)
        except NotFoundError:
            return None
        source = doc["_source"]
        return {
            "source_uri": source["source_uri"],
            "text": source["text"],
            "metadata": source.get("metadata") or {},
        }

    def store_chunks(self, run_id: str, chunks: List[Chunk]) -> None:
        for chunk in chunks:
            try:
                self.client.create(
                    index=self.indices.chunks,
                    id=chunk.chunk_id,
                    document={
                        "run_id": run_id,
                        "source_uri": chunk.source_uri,
                        "start_offset": chunk.start_offset,
                        "end_offset": chunk.end_offset,
                        "text": chunk.text,
                    },
                    refresh="wait_for",
                )
            except ConflictError:
                continue

    def get_chunks(self, run_id: str) -> List[Chunk]:
        hits = list(
            self._iter_search_hits(
                self.indices.chunks,
                query={"term": {"run_id": run_id}},
                sort=[{"start_offset": "asc"}, {"_id": "asc"}],
            )
        )
        return [
            Chunk(
                chunk_id=hit["_id"],
                source_uri=hit["_source"]["source_uri"],
                start_offset=int(hit["_source"]["start_offset"]),
                end_offset=int(hit["_source"]["end_offset"]),
                text=hit["_source"]["text"],
            )
            for hit in hits
        ]

    def list_recent_runs(self, limit: int = 50) -> List[ExtractionRun]:
        response = self.client.search(
            index=self.indices.runs,
            query={"match_all": {}},
            sort=[{"started_at": "desc"}],
            size=limit,
        )
        hits = response.get("hits", {}).get("hits", [])
        return [self._to_run(hit["_id"], hit["_source"]) for hit in hits]

    def delete_all_runs(self) -> int:
        count = self.count_runs()
        self.client.delete_by_query(
            index=self.indices.chunks,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        self.client.delete_by_query(
            index=self.indices.documents,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        self.client.delete_by_query(
            index=self.indices.runs,
            query={"match_all": {}},
            refresh=True,
            conflicts="proceed",
        )
        return count

    def purge_document_text(self, run_id: str) -> bool:
        """Delete the full document text for a finished run."""
        try:
            self.client.delete(
                index=self.indices.documents,
                id=run_id,
                refresh="wait_for",
            )
            return True
        except NotFoundError:
            return False

    def purge_stale_pending_runs(self, max_age_days: int = 14) -> int:
        """Delete pending runs (and their documents) older than *max_age_days*."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        # Find the stale run IDs so we can also clean up their documents
        stale_query: Dict[str, Any] = {
            "bool": {
                "filter": [
                    {"term": {"status": "pending"}},
                    {"range": {"started_at": {"lt": cutoff}}},
                ]
            }
        }
        # Delete matching documents first
        stale_run_ids: List[str] = []
        for hit in self._iter_search_hits(
            self.indices.runs,
            query=stale_query,
            sort=[{"started_at": "asc"}],
        ):
            stale_run_ids.append(hit["_id"])

        if not stale_run_ids:
            return 0

        # Purge documents and chunks for those runs
        for rid in stale_run_ids:
            try:
                self.client.delete(index=self.indices.documents, id=rid)
            except NotFoundError:
                pass
        self.client.delete_by_query(
            index=self.indices.chunks,
            query={"terms": {"run_id": stale_run_ids}},
            refresh=True,
            conflicts="proceed",
        )

        # Delete the runs themselves
        response = self.client.delete_by_query(
            index=self.indices.runs,
            query=stale_query,
            refresh=True,
            conflicts="proceed",
        )
        return int(response.get("deleted", 0))

    def count_runs(
        self,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        filters: List[Dict[str, Any]] = []
        if status:
            filters.append({"term": {"status": status}})
        if since:
            filters.append({"range": {"started_at": {"gt": since.isoformat()}}})
        if filters:
            query: Dict[str, Any] = {"bool": {"filter": filters}}
        else:
            query = {"match_all": {}}
        response = self.client.count(index=self.indices.runs, query=query)
        return int(response["count"])
