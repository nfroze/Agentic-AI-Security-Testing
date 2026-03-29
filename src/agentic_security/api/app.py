"""Main FastAPI application."""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..attacks.registry import AttackRegistry
from ..core.exceptions import AgenticSecurityError
from .database import Database
from .dependencies import set_database
from .routers import attacks, reports, targets, tests
from .schemas import ErrorResponse, HealthResponse

logger = logging.getLogger(__name__)

# Get version
try:
    from importlib.metadata import version
    __version__ = version("agentic-security")
except Exception:
    __version__ = "0.1.0"

# Global database instance
db: Optional[Database] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager.

    Handles startup and shutdown events.
    """
    global db

    # Startup
    logger.info("Starting up Agentic AI Security Testing API")

    # Initialize database
    db = Database()
    await db.initialize()
    set_database(db)

    # Discover attack modules
    logger.info("Discovering attack modules...")
    AttackRegistry.discover()
    attacks_found = len(AttackRegistry.list_attacks())
    logger.info(f"Discovered {attacks_found} attack modules")

    yield

    # Shutdown
    logger.info("Shutting down")
    if db:
        await db.close()


# Create FastAPI app
app = FastAPI(
    title="Agentic AI Security Testing API",
    description="End-to-end platform for testing AI agents against OWASP Top 10 categories",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure from environment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handlers
@app.exception_handler(AgenticSecurityError)
async def agentic_security_error_handler(request, exc):
    """Handle custom agentic security exceptions.

    Args:
        request: Request object.
        exc: Exception instance.

    Returns:
        JSON error response.
    """
    logger.error(f"Agentic security error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": str(exc),
            "error_code": exc.__class__.__name__,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    """Handle validation errors.

    Args:
        request: Request object.
        exc: Exception instance.

    Returns:
        JSON error response.
    """
    logger.warning(f"Validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": [
                {
                    "field": ".".join(str(x) for x in err["loc"][1:]),
                    "message": err["msg"],
                }
                for err in exc.errors()
            ],
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle uncaught exceptions.

    Args:
        request: Request object.
        exc: Exception instance.

    Returns:
        JSON error response.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error_code": "INTERNAL_SERVER_ERROR",
        },
    )


# Health check endpoint
@app.get("/", tags=["health"])
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns:
        Health status and version.
    """
    return HealthResponse(
        status="healthy",
        version=__version__,
    )


# Include routers
app.include_router(targets.router)
app.include_router(tests.router)
app.include_router(attacks.router)
app.include_router(reports.router)


# Root documentation
@app.get("/api/v1", tags=["info"])
async def api_info() -> dict:
    """API information and endpoints.

    Returns:
        Information about available endpoints.
    """
    return {
        "name": "Agentic AI Security Testing API",
        "version": __version__,
        "description": "End-to-end platform for testing AI agents and LLMs against OWASP Top 10 categories",
        "endpoints": {
            "targets": "/api/v1/targets",
            "tests": "/api/v1/tests",
            "attacks": "/api/v1/attacks",
            "reports": "/api/v1/reports",
        },
        "documentation": "/docs",
    }
