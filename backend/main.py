"""FastAPI application.

Mounts the JSON API plus the simple Web UI (static files).
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api import (
    approvals,
    evaluation,
    incidents,
    knowledge,
    logs,
    mcp,
    metrics,
    security,
    workflow,
)
from backend.services.config import get_settings

logging.basicConfig(level=logging.INFO)

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")

for router in (
    incidents.router,
    approvals.router,
    workflow.router,
    mcp.router,
    knowledge.router,
    logs.router,
    security.router,
    metrics.router,
    evaluation.router,
):
    app.include_router(router)

_static_dir = settings.frontend_dir
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(os.path.join(_static_dir, "index.html"))