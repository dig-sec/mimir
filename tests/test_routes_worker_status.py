from __future__ import annotations

import asyncio
import importlib
import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict


class _DummyGraphStore:
    client = None
    indices = None

    def count_entities(self) -> int:
        return 7

    def count_relations(self) -> int:
        return 11


class _DummyRunStore:
    def count_runs(self, status: str | None = None, since: Any = None) -> int:
        if status == "completed":
            return 2
        return 0

    def list_recent_runs(self, limit: int = 50):  # pragma: no cover - helper only
        return []


class _DummyMetricsStore:
    def get_rollup_overview(self, days: int = 30, source_uri: str | None = None):
        return {"active_actors": 0}

    def get_cti_overview(self, days: int = 30, source_uri: str | None = None):
        return {"docs_total": 0, "assessments_total": 0}

    def get_pir_trending_summary(self, days: int = 30, source_uri: str | None = None):
        return None


def _load_routes(monkeypatch, tmp_path: Path, **settings_overrides: Any):
    settings_values: Dict[str, Any] = {
        "worker_heartbeat_dir": str(tmp_path),
        "elastic_connector_enabled": True,
        "elastic_connector_hosts": "http://connector.local:9200",
        "elastic_connector_indices": "feedly_news,mwdb-openrelik",
        "elastic_worker_exclude_indices": "feedly_news",
        "elastic_worker_interval_minutes": 30,
        "feedly_worker_interval_minutes": 30,
        "opencti_url": "http://opencti.local",
        "opencti_token": "token",
        "opencti_worker_interval_minutes": 30,
        "rss_worker_enabled": True,
        "rss_worker_interval_minutes": 30,
        "rss_worker_feeds": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "malware_worker_enabled": True,
        "malware_worker_interval_minutes": 30,
        "malware_worker_indices": "mwdb-openrelik",
        "gvm_worker_enabled": True,
        "gvm_worker_interval_minutes": 30,
        "gvm_connection_type": "unix",
        "gvm_socket_path": "/run/gvmd/gvmd.sock",
        "watcher_worker_enabled": True,
        "watcher_worker_interval_minutes": 30,
        "watcher_base_url": "http://watcher.local:9002",
        "watcher_pull_trendy_words": True,
        "llm_worker_poll_seconds": 2,
    }
    settings_values.update(settings_overrides)

    import mimir.storage.factory as factory

    monkeypatch.setattr(
        factory, "create_graph_store", lambda settings: _DummyGraphStore()
    )
    monkeypatch.setattr(factory, "create_run_store", lambda settings: _DummyRunStore())
    monkeypatch.setattr(
        factory, "create_metrics_store", lambda settings: _DummyMetricsStore()
    )

    for key in list(sys.modules):
        if key.startswith("mimir.api.routes"):
            sys.modules.pop(key, None)
    routes = importlib.import_module("mimir.api.routes")
    new_settings = replace(routes.settings, **settings_values)
    routes.settings = new_settings
    # Propagate to sub-modules that bind settings at import time
    import mimir.api.routes._helpers as _h

    _h.settings = new_settings
    for submod_name in list(sys.modules):
        if (
            submod_name.startswith("mimir.api.routes.")
            and submod_name != "mimir.api.routes._helpers"
        ):
            submod = sys.modules.get(submod_name)
            if submod and hasattr(submod, "settings"):
                submod.settings = new_settings
    return routes


def _write_heartbeat(
    base_dir: Path,
    worker_id: str,
    instance_id: str,
    *,
    state: str,
    updated_at: datetime,
    details: Dict[str, Any] | None = None,
) -> None:
    payload = {
        "worker_id": worker_id,
        "instance_id": instance_id,
        "state": state,
        "updated_at": updated_at.astimezone(timezone.utc).isoformat(),
        "pid": 4321,
        "hostname": "unit-test-host",
        "details": details or {},
    }
    target = base_dir / f"{worker_id}--{instance_id}.json"
    target.write_text(json.dumps(payload), encoding="utf-8")


def test_worker_specs_include_connector_workers_when_configured(
    monkeypatch, tmp_path: Path
):
    routes = _load_routes(monkeypatch, tmp_path)

    specs = {spec["id"]: spec for spec in routes._worker_specs()}
    assert specs["llm-worker"]["enabled"] is True
    assert specs["feedly-worker"]["enabled"] is True
    assert specs["opencti-worker"]["enabled"] is True
    assert specs["elastic-worker"]["enabled"] is True
    assert specs["malware-worker"]["enabled"] is True
    assert specs["rss-worker"]["enabled"] is True
    assert specs["gvm-worker"]["enabled"] is True
    assert specs["watcher-worker"]["enabled"] is True


def test_build_worker_status_marks_stale_and_counts_replicas(
    monkeypatch, tmp_path: Path
):
    routes = _load_routes(
        monkeypatch,
        tmp_path,
        opencti_worker_interval_minutes=1,
        malware_worker_interval_minutes=1,
    )
    now = datetime.now(timezone.utc)

    _write_heartbeat(
        tmp_path,
        "opencti-worker",
        "opencti-1",
        state="running",
        updated_at=now - timedelta(minutes=10),
    )
    _write_heartbeat(
        tmp_path,
        "malware-worker",
        "mal-1",
        state="running",
        updated_at=now - timedelta(seconds=90),
        details={"samples_processed": 5},
    )
    _write_heartbeat(
        tmp_path,
        "malware-worker",
        "mal-2",
        state="sleeping",
        updated_at=now - timedelta(seconds=15),
        details={"samples_processed": 9},
    )

    statuses = {status["id"]: status for status in routes._build_worker_statuses()}
    assert statuses["opencti-worker"]["state"] == "stale"
    assert statuses["opencti-worker"]["health"] == "warn"

    malware = statuses["malware-worker"]
    assert malware["state"] == "sleeping"
    assert malware["health"] == "ok"
    assert malware["details"]["replicas"] == 2
    assert malware["details"]["samples_processed"] == 9


def test_disabled_worker_stays_disabled_even_with_recent_heartbeat(
    monkeypatch,
    tmp_path: Path,
):
    routes = _load_routes(
        monkeypatch,
        tmp_path,
        elastic_connector_indices="feedly_news",
        elastic_worker_exclude_indices="feedly_news",
    )
    now = datetime.now(timezone.utc)
    _write_heartbeat(
        tmp_path,
        "elastic-worker",
        "elastic-1",
        state="running",
        updated_at=now - timedelta(seconds=5),
    )

    statuses = {status["id"]: status for status in routes._build_worker_statuses()}
    elastic = statuses["elastic-worker"]
    assert elastic["enabled"] is False
    assert elastic["state"] == "disabled"
    assert "excluded" in elastic["disabled_reason"]
    assert elastic["details"]["last_reported_state"] == "running"


def test_stats_payload_includes_worker_statuses(monkeypatch, tmp_path: Path):
    routes = _load_routes(monkeypatch, tmp_path)
    _write_heartbeat(
        tmp_path,
        "llm-worker",
        "llm-1",
        state="running",
        updated_at=datetime.now(timezone.utc),
        details={"active_tasks": 1},
    )

    payload = asyncio.run(routes.get_stats(source_uri=None))
    workers = payload["workers"]
    assert payload["entities"] == 7
    assert payload["relations"] == 11
    assert any(worker["id"] == "llm-worker" for worker in workers)


def test_api_search_delegates_to_graph_store_and_caps_results(
    monkeypatch, tmp_path: Path
):
    routes = _load_routes(monkeypatch, tmp_path)

    calls: list[tuple[str, str | None]] = []

    class _SearchGraphStore:
        def search_entities(self, query: str, entity_type: str | None = None):
            calls.append((query, entity_type))
            return [
                SimpleNamespace(
                    id=f"e-{i}", name=f"Name {i}", type=entity_type or "unknown"
                )
                for i in range(60)
            ]

    # Patch at the sub-module level so the function sees the new store
    import mimir.api.routes.search as _search_mod

    _search_mod.graph_store = _SearchGraphStore()
    result = routes.search_entities(q="dyno", entity_type="malware")

    assert calls == [("dyno", "malware")]
    assert len(result) == 50
    assert result[0]["type"] == "malware"
