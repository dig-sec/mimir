from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ..config import get_settings
from .routes import graph_store, router, run_store

settings = get_settings()
logging.basicConfig(level=settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connector sync and LLM extraction are now handled by dedicated
    # worker processes (feedly_worker, opencti_worker, elastic_worker,
    # llm_worker).  The API process no longer runs an inline scheduler.
    #
    # Manual sync endpoints in routes.py still work — they just trigger
    # one-shot syncs on demand.
    logging.getLogger(__name__).info(
        "API started.  Data ingestion handled by separate worker processes."
    )
    yield


app = FastAPI(title="Wellspring API", version="0.1.0", lifespan=lifespan)

# Serve static assets (CSS, JS)
_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

app.include_router(router)
