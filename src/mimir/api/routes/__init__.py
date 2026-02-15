"""Routes package — assembles domain sub-routers into a single ``router``.

Backward-compatible re-exports of ``graph_store``, ``run_store``,
``metrics_store`` so that ``app.py`` can continue to do::

    from .routes import router, metrics_store
"""

from __future__ import annotations

from fastapi import APIRouter

from ._helpers import build_worker_statuses as _build_worker_statuses  # noqa: F401
from ._helpers import graph_store, metrics_store, run_store, settings  # noqa: F401
from ._helpers import worker_specs as _worker_specs  # noqa: F401
from .admin import get_stats  # noqa: F401
from .admin import router as admin_router  # noqa: F401
from .connectors import router as connectors_router
from .export import router as export_router
from .ingest import router as ingest_router
from .intelligence import lake_overview  # noqa: F401
from .intelligence import router as intelligence_router  # noqa: F401
from .search import router as search_router
from .search import search_entities  # noqa: F401
from .ui_routes import router as ui_router

router = APIRouter()

router.include_router(ui_router)
router.include_router(search_router)
router.include_router(ingest_router)
router.include_router(export_router)
router.include_router(connectors_router)
router.include_router(intelligence_router)
router.include_router(admin_router)
