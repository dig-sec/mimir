from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from ..config import get_settings
from .access import authorize_request
from .routes import router

settings = get_settings()
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


async def _metrics_rollup_loop() -> None:
    """Periodically trigger metrics rollups in the background."""
    from .routes import metrics_store

    interval = settings.metrics_rollup_interval_seconds
    if not settings.metrics_rollup_enabled or interval <= 0:
        logger.info("Metrics auto-rollup disabled.")
        return

    logger.info("Metrics auto-rollup started (every %ds)", interval)
    # Short initial delay so the API is fully ready, then run immediately
    await asyncio.sleep(10)
    while True:
        try:
            await asyncio.to_thread(
                metrics_store.rollup_daily_threat_actor_stats,
                lookback_days=settings.metrics_rollup_lookback_days,
                min_confidence=settings.metrics_rollup_min_confidence,
            )
            await asyncio.to_thread(
                metrics_store.rollup_daily_pir_stats,
                lookback_days=settings.metrics_rollup_lookback_days,
                min_confidence=settings.metrics_rollup_min_confidence,
            )
            cti_fn = getattr(metrics_store, "rollup_daily_cti_assessments", None)
            if cti_fn:
                await asyncio.to_thread(
                    cti_fn,
                    lookback_days=settings.metrics_rollup_lookback_days,
                    min_confidence=settings.metrics_rollup_min_confidence,
                )
            logger.info("Metrics auto-rollup completed.")
        except Exception:
            logger.exception("Metrics auto-rollup failed")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connector sync and LLM extraction are now handled by dedicated
    # worker processes (feedly_worker, opencti_worker, elastic_worker,
    # malware_worker, llm_worker).  The API process no longer runs an
    # inline scheduler.
    #
    # Manual sync endpoints in routes.py still work — they just trigger
    # one-shot syncs on demand.
    logger.info("API started.  Data ingestion handled by separate worker processes.")
    rollup_task = asyncio.create_task(_metrics_rollup_loop())
    try:
        yield
    finally:
        rollup_task.cancel()
        try:
            await rollup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Mimir API", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def enforce_access_controls(request: Request, call_next):
    allowed, status_code, detail = authorize_request(
        request,
        api_token=settings.api_token,
        allow_localhost_without_token=settings.allow_localhost_without_token,
        auth_disabled=settings.auth_disabled,
    )
    if allowed:
        return await call_next(request)

    if status_code == 403:
        logger.warning(
            "Blocked unauthenticated request from host=%s path=%s",
            request.client.host if request.client else "",
            request.url.path,
        )
    return JSONResponse(status_code=status_code, content={"detail": detail})


# Serve static assets (CSS, JS)
_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

app.include_router(router)
