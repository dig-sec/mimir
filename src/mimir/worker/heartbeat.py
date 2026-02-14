from __future__ import annotations

import json
import logging
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import Settings

logger = logging.getLogger(__name__)
_SAFE_SEGMENT_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkerHeartbeat:
    """Write per-worker heartbeat files for API status reporting."""

    def __init__(self, settings: Settings, worker_id: str) -> None:
        self.worker_id = worker_id
        self.base_dir = Path(settings.worker_heartbeat_dir).expanduser()
        self.hostname = socket.gethostname()
        self.pid = os.getpid()
        configured_instance = os.getenv("WORKER_HEARTBEAT_INSTANCE", "").strip()
        raw_instance = configured_instance or f"{self.hostname}-{self.pid}"
        self.instance_id = _SAFE_SEGMENT_RE.sub("_", raw_instance).strip("._-") or str(
            self.pid
        )
        self.path = self.base_dir / f"{worker_id}--{self.instance_id}.json"

    def update(
        self,
        state: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "worker_id": self.worker_id,
            "instance_id": self.instance_id,
            "state": str(state or "unknown"),
            "updated_at": _utc_now_iso(),
            "pid": self.pid,
            "hostname": self.hostname,
            "details": details or {},
        }
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            tmp_path = self.path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=True, sort_keys=True)
            tmp_path.replace(self.path)
        except Exception:
            logger.debug("Failed to write heartbeat for %s", self.worker_id, exc_info=True)
