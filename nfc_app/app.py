from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .auth import admin_tailscale_block_response, is_admin_request_allowed
from .database import assert_database_ready, connection_scope
from .routers import admin_router, client_router, public_router
from .settings import settings, validate_runtime_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_settings()
    assert_database_ready()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_title, version=settings.app_version, lifespan=lifespan)

    @app.middleware("http")
    async def database_unit_of_work(request, call_next):
        with connection_scope():
            return await call_next(request)

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
