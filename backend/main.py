"""FastAPI entry point for NeMo-Shield.

Run:  uvicorn backend.main:app --reload
"""

from __future__ import annotations

from dotenv import load_dotenv

# Load .env before importing anything that reads env vars (DB, rails, admin key).
load_dotenv()

import os  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from backend.database import audit_store  # noqa: E402
from backend.routes import behind_trusted_proxy, get_rails, router  # noqa: E402
from backend.security import configured_admin_key  # noqa: E402

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if origin.strip()
]

HSTS_VALUE = "max-age=63072000; includeSubDomains"
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
# Admin responses carry audit data; never let a browser or proxy cache them.
NO_STORE_PREFIXES = ("/api/v1/audit", "/api/v1/telemetry")


def is_production() -> bool:
    return os.getenv("ENVIRONMENT", "").strip().lower() == "production"


def served_over_https(request: Request) -> bool:
    """True if the client connection is HTTPS.

    Behind our own proxy, TLS ends at the proxy, so the app sees plain HTTP and
    the proxy reports the original scheme in X-Forwarded-Proto. That header is
    only trusted under BEHIND_TRUSTED_PROXY=1, like X-Forwarded-For.
    """
    if request.url.scheme == "https":
        return True
    if not behind_trusted_proxy():
        return False
    # Each proxy appends; the last value was written by the proxy nearest to us.
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[-1].strip().lower()
    return forwarded == "https"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm: parse the Colang config and build LLMRails once at startup.
    app.state.rails = get_rails()
    if configured_admin_key() is None:
        print(
            "[NeMo-Shield] WARNING: ADMIN_API_KEY is unset or uses the legacy default; "
            "/telemetry and /audit/logs will return 503.",
            flush=True,
        )
    await audit_store.connect()
    yield
    await audit_store.close()


def create_app() -> FastAPI:
    """Build the app. Reads ENVIRONMENT at call time, so tests can build a production instance."""
    production = is_production()
    app = FastAPI(
        title="NeMo-Shield",
        description="Enterprise AI safety and guardrails gateway built on NVIDIA NeMo Guardrails.",
        version="0.2.0",
        lifespan=lifespan,
        # The schema maps every route and model; don't publish it in production.
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Added after CORS, so it wraps it: preflight and error responses get the headers too.
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if served_over_https(request):
            response.headers.setdefault("Strict-Transport-Security", HSTS_VALUE)
        if request.url.path.startswith(NO_STORE_PREFIXES):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(router)
    return app


app = create_app()
