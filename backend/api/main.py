"""FastAPI main application entrypoint, lifecycle events, and exception handlers."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import logging
import os
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.dependencies import get_service_container
from backend.api.routes.alerts import router as alerts_router
from backend.api.routes.firewall import router as firewall_router
from backend.api.routes.flows import router as flows_router
from backend.api.routes.health import router as health_router
from backend.api.routes.ml import router as ml_router
from backend.api.routes.notifications import router as notifications_router
from backend.api.routes.packets import router as packets_router
from backend.api.routes.stats import router as stats_router
from backend.api.routes.websocket import router as websocket_router
from backend.api.websocket.manager import ws_manager

logger = logging.getLogger("dpi_ids_ips.backend")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application startup and graceful shutdown."""
    logger.info("Initializing FastAPI Backend Services...")
    loop = asyncio.get_running_loop()
    ws_manager.set_event_loop(loop)

    container = get_service_container()
    container.initialize()
    logger.info("FastAPI Backend Services Initialized.")

    yield

    logger.info("Shutting down FastAPI Backend Services...")
    await ws_manager.shutdown()
    container.shutdown()
    logger.info("FastAPI Backend Services Gracefully Stopped.")


def create_app() -> FastAPI:
    """Builds and configures the FastAPI application."""
    app = FastAPI(
        title="DPI/IDS/IPS Central Security Backend",
        version="1.0.0",
        description="FastAPI Backend for Real-Time Deep Packet Inspection, Threat Detection, Alert Notifications, and WebSocket Monitoring",
        lifespan=lifespan,
    )

    # CORS configuration via environment variable
    # Security Hardening: Reject wildcard origins when credentials are enabled.
    # Default to explicit development localhost origins rather than universal wildcard.
    default_dev_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    cors_raw = os.getenv("CORS_ORIGINS", "").strip()
    if cors_raw:
        origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
        # If user explicitly specifies wildcard '*', credentials cannot be safely permitted
        has_wildcard = any(o == "*" for o in origins)
        allow_creds = not has_wildcard
        effective_origins = origins
    else:
        effective_origins = default_dev_origins
        allow_creds = True

    app.add_middleware(
        CORSMiddleware,
        allow_origins=effective_origins,
        allow_credentials=allow_creds,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Centralized Exception Handlers

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "ClientError" if exc.status_code < 500 else "ServerError",
                "message": exc.detail,
                "path": request.url.path,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "ValidationError",
                "message": "Invalid request parameter or payload validation failed.",
                "path": request.url.path,
                "details": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled error processing {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "message": "An unexpected error occurred while processing the request.",
                "path": request.url.path,
            },
        )

    # Register Routers under /api/v1
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(alerts_router, prefix="/api/v1")
    app.include_router(flows_router, prefix="/api/v1")
    app.include_router(packets_router, prefix="/api/v1")
    app.include_router(stats_router, prefix="/api/v1")
    app.include_router(ml_router, prefix="/api/v1")
    app.include_router(firewall_router, prefix="/api/v1")
    app.include_router(notifications_router, prefix="/api/v1")

    # Register WebSocket Router at root (/ws/monitor)
    app.include_router(websocket_router)

    return app


# Application singleton for ASGI servers (e.g. uvicorn backend.api.main:app)
app = create_app()
