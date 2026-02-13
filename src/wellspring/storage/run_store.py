from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..schemas import Chunk, ExtractionRun


class RunStore(ABC):
    @abstractmethod
    def create_run(
        self,
        run: ExtractionRun,
        source_uri: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_run_status(
        self, run_id: str, status: str, error: Optional[str] = None
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_run(self, run_id: str) -> Optional[ExtractionRun]:
        raise NotImplementedError

    @abstractmethod
    def recover_stale_runs(self) -> int:
        """Reset any 'running' runs back to 'pending' (e.g. after a crash)."""
        ...

    def claim_next_run(self) -> Optional[ExtractionRun]:
        raise NotImplementedError

    @abstractmethod
    def get_document(self, run_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def store_chunks(self, run_id: str, chunks: List[Chunk]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_chunks(self, run_id: str) -> List[Chunk]:
        raise NotImplementedError

    @abstractmethod
    def list_recent_runs(self, limit: int = 50) -> List[ExtractionRun]:
        raise NotImplementedError

    @abstractmethod
    def delete_all_runs(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def purge_document_text(self, run_id: str) -> bool:
        """Delete the full document text for a finished run to reclaim storage."""
        ...

    @abstractmethod
    def purge_stale_pending_runs(self, max_age_days: int = 14) -> int:
        """Delete pending runs older than *max_age_days*.

        Returns the number of runs purged.
        """
        ...

    @abstractmethod
    def count_runs(
        self,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        raise NotImplementedError
