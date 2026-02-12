from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ..config import get_settings
from .routes import graph_store, router, run_store
from .scheduler import run_sync_loop

settings = get_settings()
logging.basicConfig(level=settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start the periodic sync scheduler
    sync_task = asyncio.create_task(run_sync_loop(settings, graph_store, run_store))
    yield
    # Shutdown: cancel the scheduler
    sync_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Wellspring API", version="0.1.0", lifespan=lifespan)

# Serve static assets (CSS, JS)
_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

app.include_router(router)
