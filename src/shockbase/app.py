"""HTTP application: legacy app routes, owner routes, and the admin page."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.responses import FileResponse, PlainTextResponse, Response

if TYPE_CHECKING:
    from shockbase.hub import Hub
    from shockbase.store import Store

INDEX = Path(__file__).resolve().parent / "static" / "index.html"


def create_app(store: Store, hub: Hub) -> FastAPI:
    """Wire store and hub into the process the apps and the owner page share."""
    from shockbase.admin import router as admin_router
    from shockbase.legacy import router as legacy_router

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.hub.start()
            yield
        finally:
            try:
                app.state.hub.stop()
            finally:
                app.state.store.close()

    app = FastAPI(title="Shockbase", lifespan=lifespan)
    app.state.store = store
    app.state.hub = hub
    app.include_router(legacy_router)
    app.include_router(admin_router)

    @app.get("/")
    def index() -> Response:
        if not INDEX.is_file():
            return PlainTextResponse("index.html is missing", status_code=404)
        response = FileResponse(INDEX)
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
