from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from mimir.worker.heartbeat import WorkerHeartbeat


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_heartbeat_uses_replica_specific_filename(tmp_path, monkeypatch):
    settings = SimpleNamespace(worker_heartbeat_dir=str(tmp_path))
    monkeypatch.setenv("WORKER_HEARTBEAT_INSTANCE", "llm/replica#1")

    heartbeat = WorkerHeartbeat(settings, "llm-worker")
    heartbeat.update("running", {"active_tasks": 2})

    assert heartbeat.path.exists()
    assert heartbeat.path.name.startswith("llm-worker--llm_replica_1")

    payload = _read_json(heartbeat.path)
    assert payload["worker_id"] == "llm-worker"
    assert payload["instance_id"] == "llm_replica_1"
    assert payload["state"] == "running"
    assert payload["details"]["active_tasks"] == 2


def test_heartbeat_rewrites_single_file_for_same_instance(tmp_path, monkeypatch):
    settings = SimpleNamespace(worker_heartbeat_dir=str(tmp_path))
    monkeypatch.setenv("WORKER_HEARTBEAT_INSTANCE", "elastic-primary")

    heartbeat = WorkerHeartbeat(settings, "elastic-worker")
    heartbeat.update("running", {"runs_queued": 10})
    heartbeat.update("sleeping", {"next_run_in_seconds": 1800})

    files = list(tmp_path.glob("elastic-worker--*.json"))
    assert len(files) == 1

    payload = _read_json(files[0])
    assert payload["state"] == "sleeping"
    assert payload["details"]["next_run_in_seconds"] == 1800
