from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

import pytest

_VIEWPORTS = [
    {"name": "mobile-small", "width": 320, "height": 568},
    {"name": "mobile", "width": 375, "height": 812},
    {"name": "tablet", "width": 768, "height": 1024},
    {"name": "desktop", "width": 1280, "height": 800},
]


def _is_reachable(url: str) -> bool:
    try:
        with urlopen(url, timeout=3):
            return True
    except HTTPError:
        # Reaching the app with non-2xx is still "up" for smoke tests.
        return True
    except (URLError, TimeoutError, OSError):
        return False


def _mock_status_endpoints(page: Any) -> None:
    stats_payload = {
        "entities": 42,
        "relations": 128,
        "metrics": {"active_actors": 7},
        "runs_total": 24,
        "runs_completed": 20,
        "runs_failed": 1,
        "runs_pending": 2,
        "runs_running": 1,
        "rate_per_hour": 8,
        "entity_type_counts": {"malware": 10, "threat_actor": 8, "vulnerability": 5},
        "workers": [
            {
                "id": "llm-worker",
                "label": "LLM Extraction",
                "enabled": True,
                "health": "ok",
                "state": "running",
                "age_seconds": 4,
                "interval_seconds": 2,
                "details": {"entities_created": 12, "relations_created": 34},
            },
            {
                "id": "feedly-worker",
                "label": "Feedly Sync",
                "enabled": True,
                "health": "ok",
                "state": "sleeping",
                "age_seconds": 30,
                "interval_seconds": 1800,
                "details": {"entities_created": 5, "relations_created": 9},
            },
        ],
        "metrics_status": {
            "last_rollup_at": "2026-02-15T12:00:00Z",
            "rollup_age_seconds": 45,
            "is_stale": False,
            "has_data": True,
            "error": "",
        },
        "pir_metrics_status": {
            "last_rollup_at": "2026-02-15T12:00:00Z",
            "rollup_age_seconds": 45,
            "is_stale": False,
            "has_data": True,
            "error": "",
        },
        "cti_metrics_status": {
            "last_rollup_at": "2026-02-15T12:00:00Z",
            "rollup_age_seconds": 45,
            "is_stale": False,
            "has_data": True,
            "error": "",
        },
    }

    tasks_payload = []
    runs_payload = []

    def handler(route: Any) -> None:
        path = urlparse(route.request.url).path
        if path.endswith("/api/stats"):
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(stats_payload),
            )
            return
        if path.endswith("/api/tasks"):
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(tasks_payload),
            )
            return
        if path.endswith("/api/runs"):
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(runs_payload),
            )
            return
        route.continue_()

    page.route("**/api/**", handler)


def _mock_search_endpoint(page: Any) -> None:
    def handler(route: Any) -> None:
        parsed = urlparse(route.request.url)
        if not parsed.path.endswith("/api/search"):
            route.continue_()
            return

        query = parse_qs(parsed.query)
        q = (query.get("q", [""])[0] or "").lower()
        if not q:
            payload = []
        else:
            payload = [
                {"id": "entity-apt28", "name": "APT28", "type": "threat_actor"},
                {
                    "id": "entity-lazarus",
                    "name": "Lazarus Group",
                    "type": "threat_actor",
                },
            ]
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    page.route("**/api/search*", handler)


@pytest.fixture(scope="session")
def ui_base_url() -> str:
    return os.getenv("MIMIR_UI_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


@pytest.fixture(scope="session")
def sync_api() -> Any:
    try:
        import playwright.sync_api as playwright_sync_api
    except ModuleNotFoundError:
        pytest.skip(
            "Playwright is not installed. Install with: pip install -r requirements-dev.txt"
        )
    return playwright_sync_api


@pytest.fixture(scope="session", autouse=True)
def _ui_opt_in() -> None:
    if os.getenv("MIMIR_RUN_UI_TESTS", "0") != "1":
        pytest.skip("UI tests are opt-in. Set MIMIR_RUN_UI_TESTS=1 to run.")


@pytest.fixture(scope="session", autouse=True)
def _ui_reachable(ui_base_url: str) -> None:
    if not _is_reachable(ui_base_url):
        pytest.skip(
            f"UI base URL {ui_base_url!r} is not reachable. "
            "Start the stack first (for example: docker compose up -d)."
        )


@pytest.fixture()
def page(sync_api: Any) -> Any:
    headless = os.getenv("MIMIR_UI_HEADLESS", "1") != "0"
    with sync_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=headless)
        except sync_api.Error as exc:
            if "Executable doesn't exist" in str(exc):
                pytest.skip(
                    "Playwright browser binary not installed. "
                    "Run: python -m playwright install chromium"
                )
            raise
        context = browser.new_context()
        new_page = context.new_page()
        try:
            yield new_page
        finally:
            context.close()
            browser.close()


@pytest.mark.ui
@pytest.mark.parametrize("viewport", _VIEWPORTS, ids=[v["name"] for v in _VIEWPORTS])
def test_tabs_are_usable_across_viewports(
    page: Any,
    ui_base_url: str,
    viewport: dict[str, int],
    sync_api: Any,
) -> None:
    expect = sync_api.expect
    page.set_viewport_size({"width": viewport["width"], "height": viewport["height"]})
    _mock_status_endpoints(page)

    page.goto(ui_base_url, wait_until="domcontentloaded")

    expect(page.locator("header h1")).to_have_text("Mimir")
    expect(page.locator("#askDashboard")).to_be_visible()

    page.get_by_role("button", name="Explore").click()
    expect(page.locator(".sidebar")).to_be_visible()
    expect(page.locator("#panelExplore")).to_be_visible()
    expect(page.locator("#searchInput")).to_be_visible()

    page.get_by_role("button", name="Status").click()
    expect(page.locator("#statusDashboard")).to_be_visible()
    expect(page.locator("#statusGrid")).to_be_visible()

    page.get_by_role("button", name="PIR").click()
    expect(page.locator("#pirDashboard")).to_be_visible()

    page.get_by_role("button", name="Ask").click()
    expect(page.locator("#askDashboard")).to_be_visible()


@pytest.mark.ui
def test_explore_search_selects_entity(
    page: Any, ui_base_url: str, sync_api: Any
) -> None:
    expect = sync_api.expect
    page.set_viewport_size({"width": 1280, "height": 800})
    _mock_search_endpoint(page)

    page.goto(ui_base_url, wait_until="domcontentloaded")
    page.get_by_role("button", name="Explore").click()

    page.locator("#searchInput").fill("apt")
    expect(page.locator(".entity-card")).to_have_count(2)

    first = page.locator(".entity-card").first
    first.click()
    expect(page.locator("#entityIdInput")).to_have_value("entity-apt28")
    expect(page.locator("#searchInput")).to_have_value("APT28")


@pytest.mark.ui
def test_status_dashboard_renders_worker_rows(
    page: Any, ui_base_url: str, sync_api: Any
) -> None:
    expect = sync_api.expect
    page.set_viewport_size({"width": 1280, "height": 800})
    _mock_status_endpoints(page)

    page.goto(ui_base_url, wait_until="domcontentloaded")
    page.get_by_role("button", name="Status").click()

    expect(page.locator("#statusGrid")).to_contain_text("Workers")
    expect(page.locator("#statusGrid")).to_contain_text("LLM Extraction")
    expect(page.locator("#statusGrid")).to_contain_text("RUNNING")
