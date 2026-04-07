from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .auth import admin_tailscale_block_response, is_admin_request_allowed
from .database import init_db
from .routers import admin_router, client_router, public_router
from .settings import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_title, version=settings.app_version, lifespan=lifespan)

    @app.middleware("http")
    async def admin_network_guard(request, call_next):
        if request.url.path.startswith("/admin") and not is_admin_request_allowed(request):
            return admin_tailscale_block_response()
        return await call_next(request)

    app.mount("/static", StaticFiles(directory=settings.base_dir / "static"), name="static")
    app.include_router(public_router)
    app.include_router(admin_router)
    app.include_router(client_router)
    return app


app = create_app()
