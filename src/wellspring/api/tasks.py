"""Background task manager for long-running operations."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BackgroundTask:
    id: str
    kind: str  # "opencti_pull", "filesystem_scan", etc.
    status: TaskStatus = TaskStatus.PENDING
    progress: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None


class TaskManager:
    """Simple in-memory task tracker for background jobs."""

    def __init__(self):
        self._tasks: Dict[str, BackgroundTask] = {}
        self._running: Dict[str, asyncio.Task] = {}

    def create(self, kind: str, detail: Optional[Dict] = None) -> BackgroundTask:
        task = BackgroundTask(
            id=str(uuid4())[:8],
            kind=kind,
            status=TaskStatus.PENDING,
            detail=detail or {},
            started_at=datetime.utcnow().isoformat(),
        )
        self._tasks[task.id] = task
        return task

    def get(self, task_id: str) -> Optional[BackgroundTask]:
        return self._tasks.get(task_id)

    def list_all(self) -> List[BackgroundTask]:
        return list(self._tasks.values())

    def update(self, task_id: str, **kwargs):
        t = self._tasks.get(task_id)
        if t:
            for k, v in kwargs.items():
                setattr(t, k, v)

    def start_async(self, task_id: str, coro):
        """Kick off a coroutine and track it."""
        async_task = asyncio.create_task(coro)
        self._running[task_id] = async_task

        async def _wrapper():
            try:
                await async_task
            except Exception as exc:
                logger.exception("Background task %s failed", task_id)
                self.update(
                    task_id,
                    status=TaskStatus.FAILED,
                    error=str(exc),
                    finished_at=datetime.utcnow().isoformat(),
                )

        asyncio.create_task(_wrapper())


# Singleton
task_manager = TaskManager()
